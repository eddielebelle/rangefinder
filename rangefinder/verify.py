"""Fidelity verification: does a generated facade faithfully reproduce the real service
from the consumer's (tooling) perspective?

The method is black-box differential equivalence. We capture a live target, serve the
generated facade in-process on a loopback port, then probe *both* with the same client and
diff protocol-aware equivalence classes:

- HTTP: for each captured route, GET the real server AND the replica live, and compare
  status + body + the security-relevant headers. (Comparing the replica against the
  capture's own stored bytes would be a tautology — the replica just replays them — so we
  always re-fetch the real server.)
- LDAP: enumerate the real directory and the replica at the same access level, and compare
  the entry-DN set and each entry's attribute value-sets. The replica read goes through the
  facade's own rendering, so a lossy replay shows up as a divergence.

The result is a score (faithful / total) plus an explicit divergence list and a
fidelity-boundary note — the map of where to stop trusting the replica. Fidelity is only
claimed for the perspective the capture exercised (e.g. an anonymous bind).
"""

from __future__ import annotations

import asyncio
import socket
import threading
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse

from rangefinder.config.model import RangeConfig
from rangefinder.facades.base import FacadeContext
from rangefinder.facades.registry import build_facade
from rangefinder.telemetry.emitter import Emitter


@dataclass
class Divergence:
    key: str  # the route path or entry DN that diverged
    kind: str  # status | headers | body | missing | extra | attrs
    detail: str


@dataclass
class VerifyReport:
    protocol: str
    target: str
    total: int = 0
    matched: int = 0
    divergences: list[Divergence] = field(default_factory=list)
    boundary: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def score(self) -> float:
        return 1.0 if self.total == 0 else self.matched / self.total


# --------------------------------------------------------------- in-process facade server


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class _ServedFacade:
    """Serve one captured service dict as a live facade on 127.0.0.1:<ephemeral>.

    Runs the facade's event loop in a daemon thread so the (synchronous) probe clients can
    hit it over a real socket, exactly as an external tool would. The port is pre-picked
    before start (rather than read back after) so this works for both the asyncio facades
    and the impacket-threaded SMB facade, which binds its own listener.
    """

    def __init__(self, service: dict):
        self.port = _free_port()
        cfg = RangeConfig.model_validate({
            "name": "verify",
            "network": {"subnet": "10.99.0.0/24"},
            "hosts": [{"id": "t", "hostname": "target", "ip": "10.99.0.10",
                       "os": "generic_linux", "services": [service]}],
        })
        self._cfg = cfg
        self._host = cfg.hosts[0]
        self._loop: asyncio.AbstractEventLoop | None = None
        self._facade = None
        self._thread: threading.Thread | None = None
        self._ready = threading.Event()
        self._error: BaseException | None = None

    def __enter__(self) -> "_ServedFacade":
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        if not self._ready.wait(10):
            raise RuntimeError("facade did not start within 10s")
        if self._error is not None:
            raise self._error
        return self

    def _run(self) -> None:
        loop = asyncio.new_event_loop()
        self._loop = loop
        asyncio.set_event_loop(loop)
        try:
            ctx = FacadeContext(
                host_id=self._host.id, host_name=self._host.hostname,
                host_ip=str(self._host.ip), emitter=Emitter([]), config_dir=".",
                identities=self._cfg.identities, hosts=tuple(self._cfg.hosts),
            )
            self._facade = build_facade(self._host.services[0], ctx)
            self._facade.bind_host = "127.0.0.1"
            self._facade.port = self.port  # pre-picked free port
            loop.run_until_complete(self._facade.start())
        except BaseException as exc:  # surface startup failure to __enter__
            self._error = exc
            self._ready.set()
            loop.close()
            return
        self._ready.set()
        loop.run_forever()
        try:
            loop.run_until_complete(self._facade.stop())
        finally:
            loop.close()

    def __exit__(self, *exc) -> None:
        if self._loop is not None:
            self._loop.call_soon_threadsafe(self._loop.stop)
        if self._thread is not None:
            self._thread.join(timeout=5)


# ------------------------------------------------------------------------------- HTTP


def verify_http(url: str, *, max_paths: int = 200, timeout: float = 5.0) -> VerifyReport:
    from rangefinder.capture.http import _KEEP_HEADERS, _build_opener, _fetch, capture_http

    service, warnings = capture_http(url, max_paths=max_paths, scrub=False, timeout=timeout)
    report = VerifyReport("http", url, warnings=list(warnings))

    parsed = urlparse(url if "://" in url else "http://" + url)
    real_base = f"{parsed.scheme or 'http'}://{parsed.netloc}"
    paths = sorted((service.get("paths") or {}).keys())
    if not paths:
        report.warnings.append("no routes captured; nothing to verify")
        return report

    compare_headers = _KEEP_HEADERS | {"server"}
    opener = _build_opener(True)
    with _ServedFacade(service) as srv:
        repl_base = f"http://127.0.0.1:{srv.port}"
        for path in paths:
            report.total += 1
            real = _fetch(opener, real_base + path, timeout)
            repl = _fetch(opener, repl_base + path, timeout)
            divs = _diff_http(path, real, repl, compare_headers)
            if divs:
                report.divergences.extend(divs)
            else:
                report.matched += 1

        # Fidelity boundary: an uncaptured path falls back to the facade default, which is
        # where the replica stops matching. Probe one and report it (not counted).
        absent = "/rf-verify-absent-" + "z" * 8
        real_a = _fetch(opener, real_base + absent, timeout)
        repl_a = _fetch(opener, repl_base + absent, timeout)
        if real_a and repl_a and _diff_http(absent, real_a, repl_a, compare_headers):
            report.boundary.append(
                f"uncaptured paths diverge: real {real_a.status} vs replica {repl_a.status} "
                "response for a path that was never probed (facade serves its default)")
    return report


def _diff_http(path, real, repl, compare_headers) -> list[Divergence]:
    if real is None and repl is None:
        return []
    if real is None or repl is None:
        return [Divergence(path, "missing",
                           f"reachable on real={real is not None}, replica={repl is not None}")]
    divs: list[Divergence] = []
    if real.status != repl.status:
        divs.append(Divergence(path, "status", f"real {real.status} vs replica {repl.status}"))
    rh = {k: real.headers.get(k) for k in compare_headers if k in real.headers}
    eh = {k: repl.headers.get(k) for k in compare_headers if k in repl.headers}
    if rh != eh:
        keys = sorted(set(rh) | set(eh))
        diff = [k for k in keys if rh.get(k) != eh.get(k)]
        divs.append(Divergence(path, "headers", "differing: " + ", ".join(diff)))
    if real.body != repl.body:
        divs.append(Divergence(path, "body", f"{len(real.body)}B real vs {len(repl.body)}B replica"))
    return divs


# ------------------------------------------------------------------------------- LDAP


def verify_ldap(host: str, port: int = 389, *, tls: bool = False, bind_dn: str = "",
                password: str = "", timeout: float = 5.0) -> VerifyReport:
    from rangefinder.capture.ldap import capture_ldap

    service, warnings = capture_ldap(host, port, tls=tls, bind_dn=bind_dn,
                                     password=password, timeout=timeout, scrub=False)
    report = VerifyReport("ldap", f"{host}:{port}", warnings=list(warnings))
    real = {e["dn"]: e["attributes"] for e in service["entries"]}

    with _ServedFacade(service) as srv:
        # Enumerate the replica through the facade's own rendering, same access level.
        repl_service, _ = capture_ldap("127.0.0.1", srv.port, tls=False, bind_dn=bind_dn,
                                       password=password, timeout=timeout, scrub=False)
    repl = {e["dn"]: e["attributes"] for e in repl_service["entries"]}

    for dn, attrs in real.items():
        report.total += 1
        if dn not in repl:
            report.divergences.append(Divergence(dn or "(RootDSE)", "missing", "entry absent on replica"))
            continue
        detail = _diff_attrs(attrs, repl[dn])
        if detail:
            report.divergences.append(Divergence(dn or "(RootDSE)", "attrs", detail))
        else:
            report.matched += 1
    for dn in repl:
        if dn not in real:
            report.divergences.append(Divergence(dn or "(RootDSE)", "extra", "entry only on replica"))

    report.boundary.append(
        "fidelity claimed only for the "
        + ("anonymous" if not bind_dn else f"'{bind_dn}'")
        + " bind perspective the capture exercised; deeper/credentialed reads not verified")
    return report


def _diff_attrs(real: dict, repl: dict) -> str:
    # Operational attributes the facade synthesises for a valid RootDSE/entry are allowed to
    # appear on the replica; we only flag captured attributes that fail to reproduce.
    problems: list[str] = []
    for name, vals in real.items():
        if name not in repl:
            problems.append(f"-{name}")
        elif set(vals) != set(repl[name]):
            problems.append(f"~{name}")
    if problems:
        return "attrs " + ", ".join(sorted(problems))
    return ""


# ------------------------------------------------------------------------------- SMB


def verify_smb(host: str, port: int = 445, *, username: str = "", password: str = "",
               domain: str = "", timeout: float = 5.0) -> VerifyReport:
    from rangefinder.capture.smb import capture_smb

    service, warnings = capture_smb(host, port, username=username, password=password,
                                    domain=domain, timeout=timeout, scrub=False)
    report = VerifyReport("smb", f"{host}:{port}", warnings=list(warnings))
    real_raw = {s["name"]: s.get("files", {}) for s in service.get("shares", [])}

    with _ServedFacade(service) as srv:
        repl_service = _recapture_smb("127.0.0.1", srv.port, username, password, domain, timeout)
    repl_raw = {s["name"]: s.get("files", {}) for s in repl_service.get("shares", [])}

    # SMB share and path names are case-insensitive per protocol — a client reaches the same
    # share/file regardless of case — so equivalence is case-folded (file *content* is exact).
    real = {k.casefold(): v for k, v in real_raw.items()}
    repl = {k.casefold(): v for k, v in repl_raw.items()}
    label = {k.casefold(): k for k in real_raw}
    for key, files in real.items():
        report.total += 1
        if key not in repl:
            report.divergences.append(Divergence(label[key], "missing", "share absent on replica"))
            continue
        detail = _diff_files(files, repl[key])
        if detail:
            report.divergences.append(Divergence(label[key], "files", detail))
        else:
            report.matched += 1
    for key in repl:
        if key not in real:
            report.divergences.append(Divergence(key, "extra", "share only on replica"))

    if set(real_raw) != set(repl_raw) and set(real) == set(repl):
        report.boundary.append(
            "share/path names compared case-insensitively (SMB is case-insensitive); the "
            "impacket-backed replica normalises case, which tooling treats as identical")
    report.boundary.append(
        "fidelity claimed only for the "
        + (f"'{username}'" if username else "null-session")
        + " access level the capture exercised; deeper/authenticated reads not verified")
    return report


def _recapture_smb(host, port, username, password, domain, timeout, attempts: int = 6) -> dict:
    """Enumerate the replica, retrying while the impacket server finishes coming up."""
    from rangefinder.capture.smb import capture_smb

    last: Exception | None = None
    for _ in range(attempts):
        try:
            service, _ = capture_smb(host, port, username=username, password=password,
                                     domain=domain, timeout=timeout, scrub=False)
            return service
        except Exception as exc:  # impacket raises many types on a not-yet-ready listener
            last = exc
            time.sleep(0.4)
    raise RuntimeError(f"could not enumerate replica SMB after {attempts} tries: {last}")


def _diff_files(real: dict, repl: dict) -> str:
    # Paths are case-insensitive (SMB); content comparison stays byte-exact.
    repl_cf = {p.casefold(): c for p, c in repl.items()}
    real_cf = {p.casefold() for p in real}
    problems: list[str] = []
    for path, content in real.items():
        cf = path.casefold()
        if cf not in repl_cf:
            problems.append(f"-{path}")
        elif content != repl_cf[cf]:
            problems.append(f"~{path}")
    for path in repl:
        if path.casefold() not in real_cf:
            problems.append(f"+{path}")
    if problems:
        return "files " + ", ".join(sorted(problems))
    return ""
