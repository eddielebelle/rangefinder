"""Capture a live web server's response surface into a faithful ``http`` facade.

This is record-replay, not misconfig-detection: it probes real paths, records the actual
``(status, headers, body)`` the server returned, and emits an http facade that replays
them. Any weakness present in the real responses — an exposed ``/.git``, a directory
listing, a verbose error, a leaked config — carries through automatically, because it was
captured, not because any code here knows what it is.

Verbatim by default (faithful twin, holds real content); ``scrub=True`` runs captured
bodies/headers through a best-effort redactor so the config can leave the owning org.
"""

from __future__ import annotations

import re
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

from rangefinder.capture.scrub import Scrubber, apply

# Common interesting/sensitive paths worth probing beyond what crawling finds. This is a
# discovery aid (where to look), NOT a misconfig catalog — whatever they return is captured
# faithfully and only kept if it actually exists.
_PROBE_PATHS = [
    "/", "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
    "/.git/HEAD", "/.git/config", "/.svn/entries", "/.env", "/.DS_Store", "/.htaccess",
    "/backup", "/backup.zip", "/backup.sql", "/db.sql", "/dump.sql",
    "/admin", "/administrator", "/login", "/wp-login.php", "/wp-admin/", "/phpmyadmin/",
    "/server-status", "/server-info", "/actuator", "/actuator/health", "/metrics",
    "/config.php", "/config.json", "/web.config", "/settings.py", "/.aws/credentials",
    "/api", "/api/v1", "/graphql", "/debug", "/test", "/old", "/dev", "/tmp",
    "/readme.txt", "/README.md", "/LICENSE", "/info.php", "/phpinfo.php", "/crossdomain.xml",
]

# Notable response headers worth preserving per-route (Server is captured separately).
_KEEP_HEADERS = {
    "content-type", "www-authenticate", "location", "x-powered-by", "set-cookie",
    "x-frame-options", "content-security-policy", "strict-transport-security",
}
_MAX_BODY = 100_000
_LINK_RE = re.compile(rb'(?:href|src|action)\s*=\s*["\']([^"\'#?]+)', re.IGNORECASE)


@dataclass
class _Resp:
    status: int
    headers: dict[str, str]
    body: bytes


def capture_http(
    base_url: str,
    *,
    max_paths: int = 200,
    scrub: bool = False,
    timeout: float = 5.0,
    insecure: bool = True,
) -> tuple[dict, list[str], "CaptureReport"]:
    """Probe *base_url* and return (http_service_config, warnings, capture_report)."""
    from rangefinder.capture.posture import CaptureReport
    parsed = urlparse(base_url if "://" in base_url else "http://" + base_url)
    scheme = parsed.scheme or "http"
    netloc = parsed.netloc
    base = f"{scheme}://{netloc}"
    tls = scheme == "https"
    port = parsed.port or (443 if tls else 80)

    opener = _build_opener(insecure)
    warnings: list[str] = []
    scrubber = Scrubber() if scrub else None

    # Seed probe set with the built-in list, then expand via the home page + robots.txt.
    to_probe: set[str] = set(_PROBE_PATHS)
    home = _fetch(opener, base + "/", timeout)
    if home is not None:
        to_probe |= _links(home.body, base)
    robots = _fetch(opener, base + "/robots.txt", timeout)
    if robots is not None and robots.status == 200:
        to_probe |= _robots_paths(robots.body)

    # Baseline 404 so we only keep paths that actually exist / differ.
    baseline = _fetch(opener, base + "/rf-does-not-exist-" + "x" * 8, timeout)
    default_status = baseline.status if baseline else 404
    default_body = _text(baseline.body) if baseline else None

    server_header: str | None = None
    routes: dict[str, dict] = {}
    probed = 0
    # Reachability: only emit a facade if the target actually answered. A dead port answers nothing,
    # and fabricating an http service the real estate doesn't run is the fail-open the contract
    # forbids (worse via `capture --append`, which would inject a phantom host into an estate). Any
    # of the home page, robots.txt, or the 404 baseline answering proves the service is live.
    got_response = home is not None or robots is not None or baseline is not None
    for path in sorted(to_probe):
        if probed >= max_paths:
            warnings.append(f"probe cap {max_paths} reached; some paths not captured")
            break
        probed += 1
        resp = _fetch(opener, base + path, timeout)
        if resp is None:
            continue
        got_response = True
        if server_header is None:
            server_header = resp.headers.get("server")
        # Keep it only if it's a real endpoint (not the generic 404) — the existence and
        # content of that endpoint is exactly what we want to reproduce.
        if resp.status == default_status and _text(resp.body) == default_body:
            continue
        routes[path] = _route(resp, scrubber)

    # Method posture: OPTIONS advertises the allowed methods; TRACE echoing the request is the
    # Cross-Site Tracing (XST) exposure. Both are safe to probe (no state change).
    allowed_methods = _probe_allowed_methods(opener, base, timeout)
    trace_enabled = _probe_trace(opener, base, timeout)
    trace_measured = trace_enabled is not None
    trace_enabled = bool(trace_enabled)

    # A definitive answer to any probe (a route, the OPTIONS Allow, or the TRACE result) also proves
    # the service is live; without any of it, fail closed rather than emit a phantom facade.
    if not (got_response or trace_measured or allowed_methods):
        raise ValueError(
            f"no HTTP service reachable at {base} — nothing answered ({probed} paths probed); "
            f"not emitting a facade (fail-closed)")

    service: dict = {"type": "http", "port": port}
    if tls:
        service["tls"] = True
    if server_header:
        service["server_header"] = apply(scrubber, server_header)
    if default_status != 404:
        service["default_status"] = default_status
    if default_body:
        service["default_body"] = apply(scrubber, default_body)[:_MAX_BODY]
    if routes:
        service["paths"] = routes
    service["trace_enabled"] = trace_enabled
    if allowed_methods:
        service["allowed_methods"] = allowed_methods

    warnings.append(f"captured {len(routes)} live route(s) from {base} ({probed} probed)")

    report = CaptureReport(target=netloc or base, perspective="unauthenticated HTTP client",
                           protocol="http")
    report.measured("tls", tls, "https" if tls else "plaintext")
    if server_header:
        report.measured("server_header", apply(scrubber, server_header), "Server response header")
    report.measured("routes", f"{len(routes)} live", f"{probed} paths probed")
    report.measured("default_status", default_status, "response to an unknown path")
    if trace_measured:
        report.measured("trace_enabled", trace_enabled,
                        "TRACE " + ("echoed the request — Cross-Site Tracing" if trace_enabled
                                    else "refused"))
    else:
        report.assumed("trace_enabled", False, "TRACE not probeable; assumed disabled (fail-closed)")
    if allowed_methods:
        report.measured("allowed_methods", ", ".join(allowed_methods), "OPTIONS Allow header")
    else:
        report.assumed("allowed_methods", "(not advertised)",
                       "OPTIONS not answered with an Allow header; the twin won't advertise "
                       "methods either (fail-closed — no fabricated OPTIONS surface)")
    # Auth-gated routes prove a boundary exists; what sits *behind* it is another perspective.
    gated = sorted(p for p, r in routes.items() if r.get("status") in (401, 403))
    if gated:
        report.unmeasurable("authenticated_content", f"{len(gated)} gated route(s)",
                            "captured unauthenticated; content behind "
                            + ", ".join(gated[:3]) + (" …" if len(gated) > 3 else "")
                            + " not measured. Re-capture with credentials to reach it.")
    return service, warnings, report


# The capture User-Agent (see _fetch) doubles as the marker that confirms a TRACE echo: a real
# TRACE-enabled server reflects the whole request — including this UA — back in the body, whereas
# a benign 200 page that merely mentions "TRACE" does not contain it.
_TRACE_MARKER = b"rangefinder-capture"


def _probe_allowed_methods(opener, base: str, timeout: float) -> list[str] | None:
    """The methods the server advertises via ``OPTIONS /`` — but only when it actually *answers*
    OPTIONS (2xx with an Allow header). A 4xx/5xx (OPTIONS not supported) returns None, so the twin
    doesn't fabricate OPTIONS support the real server lacks."""
    resp = _fetch(opener, base + "/", timeout, method="OPTIONS")
    if resp is None or resp.status not in (200, 204):
        return None
    allow = resp.headers.get("allow")
    if not allow:
        return None
    methods = [m.strip().upper() for m in allow.split(",") if m.strip()]
    return methods or None


def _probe_trace(opener, base: str, timeout: float) -> bool | None:
    """Whether TRACE is enabled (Cross-Site Tracing): True if the server echoes our request back,
    False if it refuses, None if unreachable. Confirms the echo by looking for the request marker
    (our User-Agent) in the body, not a loose 'TRACE' substring that a benign page could contain."""
    resp = _fetch(opener, base + "/", timeout, method="TRACE")
    if resp is None:
        return None
    return bool(resp.status == 200 and _TRACE_MARKER in (resp.body or b""))


def _route(resp: _Resp, scrubber: Scrubber | None) -> dict:
    entry: dict = {}
    if resp.status != 200:
        entry["status"] = resp.status
    headers = {}
    for name, value in resp.headers.items():
        low = name.lower()
        if low in _KEEP_HEADERS and low != "content-type":
            headers[name] = apply(scrubber, value)
    ctype = resp.headers.get("content-type")
    if ctype:
        entry["content_type"] = ctype
    text = _text(resp.body)
    if text is not None:
        entry["body"] = apply(scrubber, text)[:_MAX_BODY]
    if headers:
        entry["headers"] = headers
    return entry


# ------------------------------------------------------------------- fetch helpers


def _build_opener(insecure: bool):
    handlers: list = [_NoRedirect()]
    if insecure:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
    return urllib.request.build_opener(*handlers)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    # Capture 3xx responses as-is instead of following them.
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _fetch(opener, url: str, timeout: float, method: str = "GET") -> _Resp | None:
    req = urllib.request.Request(url, headers={"User-Agent": "rangefinder-capture/1.0"},
                                 method=method)
    try:
        resp = opener.open(req, timeout=timeout)
        return _Resp(resp.status, _headers(resp), resp.read(_MAX_BODY + 1))
    except urllib.error.HTTPError as exc:  # 3xx (no-redirect) / 4xx / 5xx still carry data
        return _Resp(exc.code, _headers(exc), exc.read(_MAX_BODY + 1) if exc.fp else b"")
    except (urllib.error.URLError, ssl.SSLError, OSError, ValueError):
        return None


def _headers(resp) -> dict[str, str]:
    # HTTP header names are case-insensitive; normalize to lowercase keys.
    return {k.lower(): v for k, v in resp.headers.items()}


def _links(body: bytes, base: str) -> set[str]:
    out: set[str] = set()
    host = urlparse(base).netloc
    for m in _LINK_RE.finditer(body or b""):
        raw = m.group(1).decode("latin-1", "ignore")
        target = urljoin(base + "/", raw)
        p = urlparse(target)
        if p.netloc == host and p.path:
            out.add(p.path)
    return out


def _robots_paths(body: bytes) -> set[str]:
    out: set[str] = set()
    for line in (body or b"").decode("latin-1", "ignore").splitlines():
        m = re.match(r"\s*(?:dis)?allow\s*:\s*(\S+)", line, re.IGNORECASE)
        if m and m.group(1).startswith("/"):
            out.add(m.group(1))
    return out


def _text(body: bytes | None) -> str | None:
    if body is None:
        return None
    try:
        return body.decode("utf-8")
    except UnicodeDecodeError:
        return None  # binary body: route is kept (status/content-type), body omitted
