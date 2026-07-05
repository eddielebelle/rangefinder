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
from rangefinder.telemetry.emitter import Emitter, ListSink


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
    # Detection perspective: telemetry the replica emitted while it was probed.
    telemetry_events: int = 0
    alerts: int = 0
    blind_spots: list[str] = field(default_factory=list)

    @property
    def score(self) -> float:
        return 1.0 if self.total == 0 else self.matched / self.total

    @property
    def ok(self) -> bool:
        """Faithful AND observable: no divergence of any kind and no detection blind spot."""
        return not self.divergences and not self.blind_spots


def _detection(report: VerifyReport, events: list[dict], expected_paths=None) -> None:
    """Record the SOC/defender perspective: did the probed actions produce telemetry?"""
    report.telemetry_events = len(events)
    report.alerts = sum(1 for e in events if e.get("event", {}).get("kind") == "alert")
    if expected_paths is not None:
        seen = {e.get("url", {}).get("path") for e in events}
        report.blind_spots = [p for p in expected_paths if p not in seen]
    elif report.total > 0 and not events:
        report.blind_spots = ["no telemetry emitted while the replica served data"]


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
        self._sink = ListSink()  # capture the telemetry the facade emits while probed
        self._loop: asyncio.AbstractEventLoop | None = None
        self._facade = None
        self._thread: threading.Thread | None = None
        self._ready = threading.Event()
        self._error: BaseException | None = None

    @property
    def events(self) -> list[dict]:
        return list(self._sink.events)

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
                host_ip=str(self._host.ip), emitter=Emitter([self._sink]), config_dir=".",
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


def verify_http(url: str, *, max_paths: int = 200, timeout: float = 5.0,
                nmap: bool = False) -> VerifyReport:
    from rangefinder.capture.http import _KEEP_HEADERS, _build_opener, _fetch, capture_http

    service, warnings, _ = capture_http(url, max_paths=max_paths, scrub=False, timeout=timeout)
    report = VerifyReport("http", url, warnings=list(warnings))

    parsed = urlparse(url if "://" in url else "http://" + url)
    real_base = f"{parsed.scheme or 'http'}://{parsed.netloc}"
    real_host = parsed.hostname or "127.0.0.1"
    real_port = parsed.port or (443 if parsed.scheme == "https" else 80)
    paths = sorted((service.get("paths") or {}).keys())
    if not paths:
        report.warnings.append("no routes captured; verifying method posture only")

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

        # Method posture diff: the twin must reproduce TRACE/XST and the OPTIONS method-advertising
        # behaviour, not just the route content. Probe live on both sides. real_trace is None only
        # when the real server was unreachable, so it gates whether we score at all — otherwise an
        # unobserved posture would be silently rubber-stamped as a match.
        real_trace, real_methods = _http_method_posture(opener, real_base, timeout)
        repl_trace, repl_methods = _http_method_posture(opener, repl_base, timeout)
        if real_trace is not None:
            report.total += 1
            if real_trace == repl_trace:
                report.matched += 1
            else:
                report.divergences.append(Divergence(
                    "posture:trace_enabled", "posture",
                    f"real TRACE enabled={real_trace} vs replica {repl_trace}"))
            # None==None (neither advertises OPTIONS) is a match; a real 405/404 vs a fabricated
            # replica 200+Allow is a divergence — the status matters, not just the method set.
            report.total += 1
            if real_methods == repl_methods:
                report.matched += 1
            else:
                report.divergences.append(Divergence(
                    "posture:allowed_methods", "posture",
                    f"real {sorted(real_methods) if real_methods else None} vs "
                    f"replica {sorted(repl_methods) if repl_methods else None}"))

        # Fidelity boundary: an uncaptured path falls back to the facade default, which is
        # where the replica stops matching. Probe one and report it (not counted).
        absent = "/rf-verify-absent-" + "z" * 8
        real_a = _fetch(opener, real_base + absent, timeout)
        repl_a = _fetch(opener, repl_base + absent, timeout)
        if real_a and repl_a and _diff_http(absent, real_a, repl_a, compare_headers):
            report.boundary.append(
                f"uncaptured paths diverge: real {real_a.status} vs replica {repl_a.status} "
                "response for a path that was never probed (facade serves its default)")

        time.sleep(0.15)  # let the last handler flush its event
        _detection(report, srv.events, expected_paths=paths)

        if nmap and paths:  # recon-tool perspective: does nmap -sV fingerprint them the same?
            _add_nmap(report, real_host, real_port, srv.port, timeout=90.0)
    return report


def _add_nmap(report: VerifyReport, real_host: str, real_port: int, repl_port: int,
              timeout: float) -> None:
    real_fp, err = _nmap_fingerprint(real_host, real_port, timeout)
    if err:
        report.boundary.append(f"nmap -sV fingerprint not checked ({err})")
        return
    repl_fp, _ = _nmap_fingerprint("127.0.0.1", repl_port, timeout)
    if real_fp is None:
        report.boundary.append("nmap -sV detected no service to compare")
    elif real_fp != repl_fp:
        report.divergences.append(Divergence(
            f"port {real_port}", "fingerprint", f"nmap -sV '{real_fp}' vs replica '{repl_fp}'"))
    else:
        report.boundary.append(f"nmap -sV fingerprint matches: {real_fp}")


def _nmap_fingerprint(host: str, port: int, timeout: float):
    """Return (fingerprint_string_or_None, error_or_None) from an nmap -sV scan of one port."""
    import shutil
    import subprocess

    if shutil.which("nmap") is None:
        return None, "nmap not installed"
    try:
        proc = subprocess.run(
            ["nmap", "-sV", "-Pn", "-p", str(port), "--version-intensity", "5", "-oX", "-", host],
            capture_output=True, timeout=timeout, check=False,
        )
    except (subprocess.SubprocessError, OSError) as exc:
        return None, f"nmap failed: {exc}"
    return _parse_nmap_service(proc.stdout), None


def _parse_nmap_service(xml: bytes):
    """Extract a normalized 'name product version' fingerprint from nmap -oX output."""
    import xml.etree.ElementTree as ET

    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return None
    svc = root.find(".//port/service")
    if svc is None:
        return None
    parts = [svc.get(k) for k in ("name", "product", "version") if svc.get(k)]
    return " ".join(parts) or None


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


def _http_method_posture(opener, base: str, timeout: float):
    """(trace_enabled, allowed_methods) from live OPTIONS/TRACE probes — reusing the capture probes
    so verify and capture classify identically (no drift). trace is None if unreachable;
    allowed_methods is None when the server doesn't answer OPTIONS with an Allow header."""
    from rangefinder.capture.http import _probe_allowed_methods, _probe_trace

    trace = _probe_trace(opener, base, timeout)
    methods = _probe_allowed_methods(opener, base, timeout)
    return trace, (frozenset(methods) if methods else None)


# ------------------------------------------------------------------------------- LDAP


def verify_ldap(host: str, port: int = 389, *, tls: bool = False, bind_dn: str = "",
                password: str = "", timeout: float = 5.0) -> VerifyReport:
    from rangefinder.capture.ldap import _probe_anonymous_bind, capture_ldap

    service, warnings, _ = capture_ldap(host, port, tls=tls, bind_dn=bind_dn,
                                     password=password, timeout=timeout, scrub=False)
    report = VerifyReport("ldap", f"{host}:{port}", warnings=list(warnings))
    real = {e["dn"]: e["attributes"] for e in service["entries"]}

    with _ServedFacade(service) as srv:
        # Enumerate the replica through the facade's own rendering, same access level.
        repl_service, _, _ = capture_ldap("127.0.0.1", srv.port, tls=False, bind_dn=bind_dn,
                                          password=password, timeout=timeout, scrub=False)
        # Probe anonymous-bind acceptance directly on the twin (behavioural, not the fail-closed
        # config value), so a facade regression that served anon would surface as a divergence.
        repl_anon = _probe_anonymous_bind("127.0.0.1", srv.port, timeout=timeout)
        time.sleep(0.1)
        det_events = srv.events
    real_anon = _probe_anonymous_bind(host, port, tls=tls, timeout=timeout)
    repl = {e["dn"]: e["attributes"] for e in repl_service["entries"]}
    _detection(report, det_events)

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

    # Posture diff: the twin must reproduce the anon-bind posture, not just the entries. We compare
    # the *behaviour* observed on each side (a live anonymous bind), so anon enforcement can't
    # silently regress into a false "anonymous bind allowed" finding. (Inconclusive probes on either
    # side -> skip; there's nothing to assert.)
    if real_anon is not None and repl_anon is not None:
        report.total += 1
        if real_anon == repl_anon:
            report.matched += 1
        else:
            report.divergences.append(Divergence(
                "posture:allow_anonymous_bind", "posture",
                f"real anon-bind accepted={real_anon} vs replica {repl_anon}"))

    report.boundary.append(
        "fidelity claimed only for the "
        + ("anonymous" if not bind_dn else f"'{bind_dn}'")
        + " bind perspective the capture exercised; deeper/credentialed reads not verified")
    return report


# Live operational attributes a real directory recomputes on every request — the facade
# regenerates them per query by design (e.g. RootDSE currentTime, injected fresh in the ldap
# facade), so their value is *expected* to differ between the capture read and the replica read.
# Comparing them is a guaranteed intermittent false divergence; exclude by name (case-insensitive).
_EPHEMERAL_LDAP_ATTRS = frozenset({"currenttime"})


def _diff_attrs(real: dict, repl: dict) -> str:
    # Operational attributes the facade synthesises for a valid RootDSE/entry are allowed to
    # appear on the replica; we only flag captured attributes that fail to reproduce. Live
    # operational attributes (see _EPHEMERAL_LDAP_ATTRS) are skipped — a differing value there
    # is faithful behaviour, not a fidelity gap.
    problems: list[str] = []
    for name, vals in real.items():
        if name.lower() in _EPHEMERAL_LDAP_ATTRS:
            continue
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

    service, warnings, _ = capture_smb(host, port, username=username, password=password,
                                       domain=domain, timeout=timeout, scrub=False)
    report = VerifyReport("smb", f"{host}:{port}", warnings=list(warnings))
    real_raw = {s["name"]: s.get("files", {}) for s in service.get("shares", [])}

    with _ServedFacade(service) as srv:
        repl_service = _recapture_smb("127.0.0.1", srv.port, username, password, domain, timeout)
        time.sleep(0.1)
        det_events = srv.events
    repl_raw = {s["name"]: s.get("files", {}) for s in repl_service.get("shares", [])}
    _detection(report, det_events)

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

    # Posture diff: the twin must reproduce the measured security posture, not just the files.
    # Each field the capture measured on the real host is re-measured on the replica (both go
    # through the same capture_smb probes) and asserted equal — so guest-fallback, SMB1, signing
    # and dialect stay locked and can't silently regress into a false finding.
    for f in ("server_os", "signing_required", "smb1_enabled", "reject_unknown_users", "max_dialect"):
        if f not in service:
            continue
        # Known facade limitation: the impacket backend can't do AES-CMAC signing, so at SMB 3.1.1
        # it advertises signing enabled-but-not-required regardless of cfg.signing_required. That's
        # a documented boundary, not a per-host fidelity gap — diffing it would flag every faithful
        # modern (3.1.1, signing-required) twin, so record it as a boundary and skip the diff.
        if f == "signing_required" and service.get("max_dialect") == "3.1.1":
            report.boundary.append(
                "SMB 3.1.1 signing_required not reproduced: the impacket backend can't AES-CMAC "
                "sign, so the twin advertises signing enabled-not-required at 3.1.1 (known limit)")
            continue
        report.total += 1
        rv, pv = service.get(f), repl_service.get(f)
        if rv == pv:
            report.matched += 1
        else:
            report.divergences.append(
                Divergence(f"posture:{f}", "posture", f"real {rv!r} vs replica {pv!r}"))

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
            service, _, _ = capture_smb(host, port, username=username, password=password,
                                        domain=domain, timeout=timeout, scrub=False)
            return service
        except Exception as exc:  # impacket raises many types on a not-yet-ready listener
            last = exc
            time.sleep(0.4)
    raise RuntimeError(f"could not enumerate replica SMB after {attempts} tries: {last}")


# ------------------------------------------------------------------------------- DNS


def verify_dns(host: str, port: int = 53, *, zone: str, timeout: float = 5.0) -> VerifyReport:
    from rangefinder.capture.dns import _server_ip, capture_dns

    service, warnings, _ = capture_dns(host, port, zone=zone, timeout=timeout, scrub=False)
    report = VerifyReport("dns", f"{host}:{port} ({zone})", warnings=list(warnings))
    # Exclude SOA from the per-record answer diff: its serial is volatile on a live (dynamic-update)
    # zone and would ticker between capture and this re-query, flagging a faithful twin as divergent
    # (the same live-operational-attribute trap as LDAP currentTime). The zone-transfer posture is
    # still exercised below, and the SOA still brackets a served AXFR.
    queries = sorted({(r["name"], r["type"]) for r in service["records"] if r["type"] != "SOA"})
    if not queries:
        report.warnings.append("no records captured; verifying zone-transfer posture only")

    server = _server_ip(host)
    with _ServedFacade(service) as srv:
        for name, rtype in queries:
            report.total += 1
            real_ans = _dns_answers(server, port, name, rtype, timeout)
            repl_ans = _dns_answers("127.0.0.1", srv.port, name, rtype, timeout)
            if real_ans != repl_ans:
                report.divergences.append(Divergence(
                    f"{name} {rtype}", "answers",
                    f"{sorted(real_ans)} vs replica {sorted(repl_ans)}"))
            else:
                report.matched += 1
        # Posture diff: the twin must reproduce the zone-transfer decision, not just the records.
        # Attempt a live AXFR on both sides and compare — so a permitted transfer (a real exposure)
        # can't silently regress, and a refused one can't be fabricated on the twin.
        repl_axfr = _axfr_allowed("127.0.0.1", srv.port, zone, timeout)
        time.sleep(0.1)
        det_events = srv.events
    real_axfr = _axfr_allowed(server, port, zone, timeout)
    # Only score the posture when both sides were actually observed (an unreachable real server
    # returns None); comparing None==None would fake a match on a posture we never measured.
    if real_axfr is None or repl_axfr is None:
        report.warnings.append("AXFR posture not verified (a live transfer probe was inconclusive)")
    else:
        report.total += 1
        if real_axfr == repl_axfr:
            report.matched += 1
        else:
            report.divergences.append(Divergence(
                "posture:axfr_allowed", "posture",
                f"real AXFR allowed={real_axfr} vs replica {repl_axfr}"))
    _detection(report, det_events)
    report.boundary.append(
        "verified the records the capture found (AXFR or the probe set); names never queried "
        "are not covered — DNS has no reliable enumeration without a zone transfer")
    return report


def _dns_answers(server: str, port: int, name: str, rtype: str, timeout: float) -> frozenset:
    import dns.exception
    import dns.flags
    import dns.message
    import dns.query
    import dns.rdatatype

    try:
        q = dns.message.make_query(name, rtype)
        resp = dns.query.udp(q, server, port=port, timeout=timeout)
        if resp.flags & dns.flags.TC:
            resp = dns.query.tcp(q, server, port=port, timeout=timeout)
    except dns.exception.DNSException:
        return frozenset()
    out = set()
    for rrset in resp.answer:
        label = dns.rdatatype.to_text(rrset.rdtype)
        for rdata in rrset:
            out.add(f"{label}:{rdata.to_text()}")
    return frozenset(out)


def _axfr_allowed(server: str, port: int, zone: str, timeout: float) -> bool | None:
    """Whether a zone transfer (AXFR) of ``zone`` is permitted: True if it succeeds, False if the
    server (reachably) refuses it, or None if the server couldn't be observed (unreachable /
    filtered) — so the caller doesn't score an unmeasured posture as a match.

    Mirrors ``capture_dns``'s transfer parameters (relativize=False on the xfr) so the two agree on
    what 'succeeded' means; check_origin=False because we only care about success, not zone
    well-formedness.
    """
    import dns.exception
    import dns.query
    import dns.zone

    try:
        z = dns.zone.from_xfr(
            dns.query.xfr(server, zone, port=port, timeout=timeout, relativize=False),
            relativize=False, check_origin=False)
        return z is not None
    except (ConnectionError, TimeoutError, OSError, dns.exception.Timeout):
        return None  # couldn't reach / observe the server — not a measured refusal
    except Exception:
        return False  # server responded but refused / failed the transfer


# ------------------------------------------------------------------------------- SSH


def verify_ssh(host: str, port: int = 22, *, timeout: float = 5.0) -> VerifyReport:
    from rangefinder.capture.ssh import (
        _probe_auth_methods, _read_kexinit, _weak_offered, capture_ssh)

    service, warnings, _ = capture_ssh(host, port, timeout=timeout)
    report = VerifyReport("ssh", f"{host}:{port}", warnings=list(warnings))

    # Reuse what capture already measured on the real host (its KEXINIT name-lists + auth methods
    # are in `service`) instead of re-probing production a second time. real_kex is None when the
    # capture couldn't read the KEXINIT.
    real_kex = None
    if "kex_algs" in service:
        real_kex = {"kex": service["kex_algs"], "host_key": service["host_key_algs"],
                    "enc_s2c": service["encryption_algs"], "mac_s2c": service["mac_algs"]}
    real_auth = service.get("auth_methods")

    with _ServedFacade(service) as srv:
        try:
            repl_kex = _read_kexinit("127.0.0.1", srv.port, timeout)[1]
        except Exception:
            repl_kex = None
        repl_auth = _probe_auth_methods("127.0.0.1", srv.port, timeout)
        time.sleep(0.1)
        det_events = srv.events
    _detection(report, det_events)

    # Compare at the finding level: asyncssh can't byte-match OpenSSH's algorithm lists, but the
    # transferable exposures — which weak algorithms are offered, the host-key type, and whether
    # password auth is enabled — must round-trip. A dimension we couldn't observe on one side is
    # recorded as a boundary, never silently scored as a match.
    if real_kex is not None and repl_kex is not None:
        report.total += 1
        rw, pw = _weak_offered(real_kex), _weak_offered(repl_kex)
        if rw == pw:
            report.matched += 1
        else:
            report.divergences.append(Divergence(
                "posture:weak_algorithms", "posture", f"real {sorted(rw)} vs replica {sorted(pw)}"))
        report.total += 1
        rt, pt = _ssh_key_types(real_kex["host_key"]), _ssh_key_types(repl_kex["host_key"])
        if rt == pt:
            report.matched += 1
        else:
            report.divergences.append(Divergence(
                "posture:host_key_type", "posture", f"real {sorted(rt)} vs replica {sorted(pt)}"))
    else:
        report.boundary.append("SSH crypto posture not verified — a KEXINIT read was inconclusive")

    if real_auth is not None and repl_auth is not None:
        report.total += 1
        rp, pp = _ssh_password_auth(real_auth), _ssh_password_auth(repl_auth)
        if rp == pp:
            report.matched += 1
        else:
            report.divergences.append(Divergence(
                "posture:password_auth", "posture", f"real password-auth={rp} vs replica {pp}"))
    else:
        report.boundary.append(
            "SSH password-auth posture not verified — an auth probe was inconclusive")

    report.boundary.append(
        "SSH posture compared at the finding level — the weak-algorithm set, host-key type and "
        "password-auth policy round-trip; exact algorithm ordering / extension lists are not "
        "byte-matched (asyncssh backend, not OpenSSH)")
    return report


def _ssh_key_type(alg: str) -> str:
    # Keep the FIDO (sk-) and certificate distinctions so a real host on a cert/FIDO host key
    # isn't scored as matching a twin that fell back to a plain key of the same family.
    a = alg.lower()
    prefix = ""
    if a.startswith("sk-"):
        prefix += "sk-"
    if "-cert-" in a or "cert-v01" in a:
        prefix += "cert-"
    for family in ("ed25519", "ecdsa", "rsa"):
        if family in a:
            return prefix + family
    if "dss" in a or "dsa" in a:
        return prefix + "dsa"
    return a


def _ssh_key_types(algs: list[str]) -> set[str]:
    return {_ssh_key_type(a) for a in algs}


def _ssh_password_auth(methods: list[str]) -> bool:
    # keyboard-interactive is a password path too (PAM / asyncssh), so it counts as password auth.
    return "password" in methods or "keyboard-interactive" in methods


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


# --------------------------------------------------------------- estate-level edge verification

@dataclass
class EdgeResult:
    kind: str
    host_id: str
    username: str
    origin: str
    target: str                    # live addr:port tested, or "-"
    verdict: str                   # measured-live | refuted | untested
    leaked_at: list[str] = field(default_factory=list)
    note: str = ""

    @property
    def exploitable(self) -> bool:
        """A credential that authenticates live AND sits in leaked text — the transferable finding."""
        return self.verdict == "measured-live" and bool(self.leaked_at)


@dataclass
class EstateReport:
    target: str
    results: list[EdgeResult] = field(default_factory=list)
    boundary: list[str] = field(default_factory=list)

    @property
    def confirmed(self) -> list[EdgeResult]:
        return [r for r in self.results if r.verdict == "measured-live"]

    @property
    def exploitable(self) -> list[EdgeResult]:
        return [r for r in self.results if r.exploitable]

    @property
    def refuted(self) -> list[EdgeResult]:
        return [r for r in self.results if r.verdict == "refuted"]

    @property
    def untested(self) -> list[EdgeResult]:
        return [r for r in self.results if r.verdict == "untested"]

    @property
    def ok(self) -> bool:
        """No credential was confirmed to both authenticate live and sit in a readable leak."""
        return not self.exploitable


def verify_estate(cfg: RangeConfig, targets: dict, *, timeout: float = 5.0) -> EstateReport:
    """Validate a range's coherence edges against the live estate, tiering each credential claim
    measured-live / refuted / untested (fail-closed on anything not proven).

    ``targets`` maps a config host id -> (live_address, port_or_None); a credential whose host has
    no target, or whose live probe is inconclusive, is recorded untested (never scored as real).
    """
    from rangefinder.coherence import iter_credentials, iter_leaks, leak_contains
    from rangefinder.credtest import validate_credential

    leaks = list(iter_leaks(cfg))
    shown = ", ".join(f"{hid}={addr}" for hid, (addr, _p) in sorted(targets.items())) or "(none)"
    report = EstateReport(target=shown)

    claims = list(iter_credentials(cfg))
    # A --target port override is only unambiguous when the host exposes one service port; on a
    # multi-service host (LDAP 389 + SMB 445) a single port would misroute the others, so fall back
    # to each claim's own port and say so once.
    host_ports: dict = {}
    for c in claims:
        host_ports.setdefault(c["host_id"], set()).add(c["port"])
    warned_ambiguous: set = set()

    for claim in claims:
        hid = claim["host_id"]
        leaked_at = sorted({loc for text, loc in leaks if leak_contains(claim["secret"], text)})
        if hid not in targets:
            report.results.append(EdgeResult(
                claim["kind"], hid, claim["username"], claim["origin"], "-", "untested",
                leaked_at, "no --target for this host"))
            continue
        addr, tport = targets[hid]
        if tport is not None and len(host_ports[hid]) == 1:
            port = tport
        else:
            port = claim["port"]
            if tport is not None and hid not in warned_ambiguous:
                warned_ambiguous.add(hid)
                report.boundary.append(
                    f"--target port for {hid!r} ignored: host has multiple service ports "
                    f"({sorted(host_ports[hid])}); used each service's own port")
        verdict = validate_credential(
            claim["kind"], addr, port, claim["username"], claim["secret"],
            domain=claim.get("domain", ""), path=claim.get("path", "/"),
            tls=claim.get("tls", False), timeout=timeout)
        tier = {True: "measured-live", False: "refuted", None: "untested"}[verdict]
        note = ("authenticates on the live estate" if verdict is True
                else "rejected by the live service" if verdict is False
                else "probe inconclusive (unreachable / unsupported)")
        report.results.append(EdgeResult(
            claim["kind"], hid, claim["username"], claim["origin"], f"{addr}:{port}", tier,
            leaked_at, note))

    if report.untested:
        report.boundary.append(
            f"{len(report.untested)} credential(s) not validated live (no target / unreachable) — "
            f"their edges stay unproven, not disproven")
    return report
