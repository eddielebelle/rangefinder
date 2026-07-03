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
) -> tuple[dict, list[str]]:
    """Probe *base_url* and return (http_service_config, warnings)."""
    parsed = urlparse(base_url if "://" in base_url else "http://" + base_url)
    scheme = parsed.scheme or "http"
    netloc = parsed.netloc
    base = f"{scheme}://{netloc}"
    tls = scheme == "https"
    port = parsed.port or (443 if tls else 80)

    opener = _build_opener(insecure)
    warnings: list[str] = []

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
    for path in sorted(to_probe):
        if probed >= max_paths:
            warnings.append(f"probe cap {max_paths} reached; some paths not captured")
            break
        probed += 1
        resp = _fetch(opener, base + path, timeout)
        if resp is None:
            continue
        if server_header is None:
            server_header = resp.headers.get("server")
        # Keep it only if it's a real endpoint (not the generic 404) — the existence and
        # content of that endpoint is exactly what we want to reproduce.
        if resp.status == default_status and _text(resp.body) == default_body:
            continue
        routes[path] = _route(resp, scrub)

    service: dict = {"type": "http", "port": port}
    if tls:
        service["tls"] = True
    if server_header:
        service["server_header"] = _maybe_scrub(server_header, scrub)
    if default_status != 404:
        service["default_status"] = default_status
    if default_body:
        service["default_body"] = _maybe_scrub(default_body, scrub)[:_MAX_BODY]
    if routes:
        service["paths"] = routes

    warnings.append(f"captured {len(routes)} live route(s) from {base} ({probed} probed)")
    return service, warnings


def _route(resp: _Resp, scrub: bool) -> dict:
    entry: dict = {}
    if resp.status != 200:
        entry["status"] = resp.status
    headers = {}
    for name, value in resp.headers.items():
        low = name.lower()
        if low in _KEEP_HEADERS and low != "content-type":
            headers[name] = _maybe_scrub(value, scrub)
    ctype = resp.headers.get("content-type")
    if ctype:
        entry["content_type"] = ctype
    text = _text(resp.body)
    if text is not None:
        entry["body"] = _maybe_scrub(text, scrub)[:_MAX_BODY]
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


def _fetch(opener, url: str, timeout: float) -> _Resp | None:
    req = urllib.request.Request(url, headers={"User-Agent": "rangefinder-capture/1.0"})
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


# ------------------------------------------------------------------------ scrubbing

_EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
_SECRETY = re.compile(
    r"(?i)(password|passwd|pwd|secret|api[_-]?key|token|authorization)"
    r"(\s*[:=]\s*|\s*[\"']\s*:\s*[\"']?)([^\s\"'<>&,;]+)"
)
_LONGTOKEN = re.compile(r"\b(?=[A-Za-z0-9+/]*[0-9])[A-Za-z0-9+/]{32,}={0,2}\b")


def _maybe_scrub(text: str, scrub: bool) -> str:
    if not scrub:
        return text
    text = _EMAIL.sub("user@example.invalid", text)
    text = _SECRETY.sub(lambda m: m.group(1) + m.group(2) + "REDACTED", text)
    text = _LONGTOKEN.sub("REDACTED", text)
    return text
