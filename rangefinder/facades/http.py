"""HTTP/1.1 facade.

Enumeration/version-detection grade: it answers curl, dirb/gobuster and scanner HTTP
probes with a configurable server header and a table of canned routes, and logs every
request. It is not a real application server — planted-vuln routes are canned
request/response decoys, not exploitable code paths.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import format_datetime
from pathlib import Path
from urllib.parse import unquote

from rangefinder.config.services import HttpConfig, HttpPath
from rangefinder.facades.base import ConnScope, Facade, FacadeContext
from rangefinder.facades.registry import register
from rangefinder.telemetry import event as ev

_READ_TIMEOUT_S = 15.0
_MAX_BODY_DRAIN = 8 * 1024 * 1024  # cap body draining to avoid unbounded reads

_REASONS = {
    200: "OK",
    301: "Moved Permanently",
    302: "Found",
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    411: "Length Required",
    500: "Internal Server Error",
}


@dataclass
class _Route:
    methods: frozenset[str]
    status: int
    body: bytes
    content_type: str
    headers: dict[str, str]
    vuln_id: str | None
    auth_realm: str | None = None
    auth_users: dict[str, str] = field(default_factory=dict)
    auth_ntlm: bool = False


@dataclass
class _Request:
    method: str
    target: str
    path: str
    query: str | None
    version: str  # "1.0" / "1.1"
    headers: dict[str, str]  # lowercased keys
    nbytes: int  # bytes consumed (line + headers + drained body)
    wants_close: bool
    head: bytes  # verbatim request-line + header bytes (for a faithful TRACE echo)


@register("http")
class HttpFacade(Facade):
    def __init__(self, *, cfg: HttpConfig, ctx: FacadeContext, service_id: str):
        super().__init__(
            bind_host=cfg.bind,
            port=cfg.port,
            ctx=ctx,
            service_id=service_id,
            protocol="http",
        )
        self.cfg = cfg
        self.routes: dict[str, _Route] = {}
        ids = ctx.identities
        self._passwords = {u.sam.lower(): u.password for u in (ids.users if ids else []) if u.password}
        self._netbios = (
            (ids.netbios or ids.domain.split(".")[0].upper()) if ids else "WORKGROUP"
        )

    @classmethod
    def from_config(cls, cfg: HttpConfig, ctx: FacadeContext) -> "HttpFacade":
        prefix = "https" if cfg.tls else "http"
        self = cls(cfg=cfg, ctx=ctx, service_id=f"{prefix}-{cfg.port}")
        if cfg.tls:
            from rangefinder.tls import server_context

            self.protocol = "https"
            self.ssl_context = server_context(ctx.host_name, self.tls_sans())
        for path, spec in cfg.paths.items():
            self.routes[path] = _build_route(spec, ctx.config_dir)
        return self

    async def handle(self, scope, reader, writer):
        ntlm_state: dict = {}  # per-connection NTLM auth state (keep-alive)
        while True:
            req = await self._read_request(reader)
            if req is None:
                return  # EOF or unrecoverable parse error (already responded if 400)

            # TRACE is a server-wide method (it echoes the request — the XST exposure), so it is
            # handled before route dispatch. OPTIONS, by contrast, is resource-scoped and goes
            # through the normal route + auth path below, so it can't fabricate surface on a gated
            # or nonexistent path.
            if req.method == "TRACE":
                await self._handle_trace(scope, req, writer)
                if not self.cfg.keepalive or req.wants_close:
                    return
                continue

            route = self.routes.get(req.path)

            if route is not None and route.auth_ntlm:
                gate = self._ntlm_gate(scope, req, ntlm_state)
                if gate is not None:  # not yet authorized -> challenge / reject
                    g_status, g_headers = gate
                    close = not self.cfg.keepalive or req.wants_close
                    resp_bytes = await self._send(
                        writer, req, g_status, b"", "text/plain; charset=utf-8", g_headers, close
                    )
                    scope.emit(ev.http_request(
                        scope, method=req.method, path=req.path, query=req.query,
                        original=req.target, version=req.version,
                        user_agent=req.headers.get("user-agent"),
                        referrer=req.headers.get("referer"), status_code=g_status,
                        request_bytes=req.nbytes, response_bytes=resp_bytes,
                        matched_route=req.path, vuln_id=None,
                    ))
                    if close:
                        return
                    continue

            status, body, content_type, headers, vuln_id, matched = self._resolve(
                req, route
            )
            creds = _basic_creds(req)
            if creds is not None:
                scope.emit(
                    ev.http_auth(
                        scope,
                        scheme="basic",
                        username=creds[0],
                        password=creds[1],
                        path=req.path,
                        outcome="success" if status != 401 else "failure",
                    )
                )
            close = not self.cfg.keepalive or req.wants_close
            resp_bytes = await self._send(
                writer, req, status, body, content_type, headers, close
            )
            scope.emit(
                ev.http_request(
                    scope,
                    method=req.method,
                    path=req.path,
                    query=req.query,
                    original=req.target,
                    version=req.version,
                    user_agent=req.headers.get("user-agent"),
                    referrer=req.headers.get("referer"),
                    status_code=status,
                    request_bytes=req.nbytes,
                    response_bytes=resp_bytes,
                    matched_route=matched,
                    vuln_id=vuln_id,
                )
            )
            if close:
                return

    async def _handle_trace(self, scope, req: _Request, writer) -> None:
        """Reproduce the captured TRACE posture. When ``trace_enabled`` was measured, echo the
        request verbatim (message/http) — the Cross-Site Tracing exposure; otherwise refuse it
        (405) like a hardened server. Fail-closed default refuses TRACE."""
        if self.cfg.trace_enabled:
            status, body, ctype, headers = 200, req.head, "message/http", {}
        else:
            headers = {"Allow": ", ".join(self.cfg.allowed_methods)} if self.cfg.allowed_methods else {}
            status, body, ctype = 405, b"", "text/plain; charset=utf-8"

        close = not self.cfg.keepalive or req.wants_close
        resp_bytes = await self._send(writer, req, status, body, ctype, headers, close)
        scope.emit(ev.http_request(
            scope, method=req.method, path=req.path, query=req.query, original=req.target,
            version=req.version, user_agent=req.headers.get("user-agent"),
            referrer=req.headers.get("referer"), status_code=status,
            request_bytes=req.nbytes, response_bytes=resp_bytes,
            matched_route=req.path if self.routes.get(req.path) else None, vuln_id=None))

    # ---- request parsing ---------------------------------------------------------
    async def _read_request(self, reader: asyncio.StreamReader) -> _Request | None:
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=_READ_TIMEOUT_S)
        except (asyncio.TimeoutError, ValueError):
            return None
        if not line:
            return None  # peer closed

        nbytes = len(line)
        raw_head = bytearray(line)
        try:
            parts = line.decode("latin-1").rstrip("\r\n").split(" ")
            method, target, proto = parts[0], parts[1], parts[2]
        except (IndexError, ValueError):
            return None
        version = "1.1" if proto.endswith("1.1") else "1.0"

        headers: dict[str, str] = {}
        while True:
            try:
                hline = await asyncio.wait_for(
                    reader.readline(), timeout=_READ_TIMEOUT_S
                )
            except (asyncio.TimeoutError, ValueError):
                return None
            if not hline:
                break
            nbytes += len(hline)
            raw_head += hline
            if hline in (b"\r\n", b"\n"):
                break
            try:
                name, _, value = hline.decode("latin-1").partition(":")
            except ValueError:
                continue
            if name:
                headers[name.strip().lower()] = value.strip()

        # Drain any request body so keep-alive does not desync.
        drained = await self._drain_body(reader, headers)
        nbytes += drained

        conn = headers.get("connection", "").lower()
        if version == "1.1":
            wants_close = conn == "close"
        else:
            wants_close = conn != "keep-alive"

        raw_path, sep, query = target.partition("?")
        path = unquote(raw_path)
        return _Request(
            method=method.upper(),
            target=target,
            path=path,
            query=query if sep else None,
            version=version,
            headers=headers,
            nbytes=nbytes,
            wants_close=wants_close,
            head=bytes(raw_head),
        )

    async def _drain_body(
        self, reader: asyncio.StreamReader, headers: dict[str, str]
    ) -> int:
        if headers.get("transfer-encoding", "").lower() == "chunked":
            # v1 does not parse chunked bodies; the connection will be closed after
            # the response, so precise draining is unnecessary.
            return 0
        cl = headers.get("content-length")
        if not cl:
            return 0
        try:
            n = int(cl)
        except ValueError:
            return 0
        n = max(0, min(n, _MAX_BODY_DRAIN))
        try:
            data = await asyncio.wait_for(
                reader.readexactly(n), timeout=_READ_TIMEOUT_S
            )
            return len(data)
        except (asyncio.TimeoutError, asyncio.IncompleteReadError):
            return 0

    # ---- response resolution -----------------------------------------------------
    def _resolve(self, req: _Request, route: _Route | None):
        if route is None:
            return (
                self.cfg.default_status,
                (self.cfg.default_body or "").encode("utf-8"),
                self.cfg.default_content_type,
                {},
                None,
                None,
            )
        # Auth gate first — a protected resource challenges before revealing anything (incl. its
        # methods via OPTIONS), so OPTIONS on a gated path can't bypass auth or leak its existence.
        if route.auth_realm is not None:
            creds = _basic_creds(req)
            authorized = creds is not None and route.auth_users.get(creds[0]) == creds[1]
            if not authorized:
                headers = {"WWW-Authenticate": f'Basic realm="{route.auth_realm}"'}
                return (401, b"", "text/plain; charset=utf-8", headers, None, req.path)
        # OPTIONS on an existing (and authorized) resource advertises the measured server methods —
        # but only when they were measured. Unmeasured -> fall through to the normal method check
        # (405), so the twin never fabricates OPTIONS support the real server didn't expose.
        if req.method == "OPTIONS" and self.cfg.allowed_methods is not None:
            headers = {"Allow": ", ".join(self.cfg.allowed_methods)}
            return (200, b"", "text/plain; charset=utf-8", headers, None, req.path)
        if req.method not in route.methods and req.method != "HEAD":
            headers = {"Allow": ", ".join(sorted(route.methods))}
            return (405, b"", "text/plain; charset=utf-8", headers, None, req.path)
        return (
            route.status,
            route.body,
            route.content_type,
            dict(route.headers),
            route.vuln_id,
            req.path,
        )

    def _ntlm_gate(self, scope, req: _Request, state: dict):
        """NTLM over HTTP. Returns None when authorized, else (status, headers) to send."""
        if state.get("authenticated"):
            return None
        auth = req.headers.get("authorization", "")
        if auth[:5].lower() != "ntlm ":
            return (401, {"WWW-Authenticate": "NTLM"})
        try:
            token = base64.b64decode(auth[5:].strip())
        except (binascii.Error, ValueError):
            return (401, {"WWW-Authenticate": "NTLM"})
        if len(token) < 12 or token[:7] != b"NTLMSSP":
            return (401, {"WWW-Authenticate": "NTLM"})

        msg_type = struct.unpack("<I", token[8:12])[0]
        if msg_type == 1:  # Type1 -> Type2 challenge
            from rangefinder.ntlm import build_challenge

            type2, ch8, neg, chal = build_challenge(token, self.ctx.host_name.upper(), self._netbios)
            state.update(ch8=ch8, neg=neg, chal=chal)
            return (401, {"WWW-Authenticate": "NTLM " + base64.b64encode(type2).decode()})
        if msg_type == 3:  # Type3 -> validate
            from rangefinder.ntlm import nt_hash, validate

            neg, chal, ch8 = state.get("neg"), state.get("chal"), state.get("ch8")
            if neg is None:
                return (401, {"WWW-Authenticate": "NTLM"})
            domain, user, _ws, _ = validate(token, None, ch8, neg, chal)
            pw = self._passwords.get(user.lower())
            _, _, _, ok = validate(token, nt_hash(pw) if pw else None, ch8, neg, chal)
            scope.emit(ev.http_auth(
                scope, scheme="ntlm", username=f"{domain}\\{user}" if domain else user,
                password=None, path=req.path, outcome="success" if ok else "failure",
            ))
            if ok:
                state["authenticated"] = True
                return None
            return (401, {"WWW-Authenticate": "NTLM"})
        return (401, {"WWW-Authenticate": "NTLM"})

    # ---- response writing --------------------------------------------------------
    async def _send(
        self,
        writer: asyncio.StreamWriter,
        req: _Request,
        status: int,
        body: bytes,
        content_type: str,
        route_headers: dict[str, str],
        close: bool,
    ) -> int:
        reason = _REASONS.get(status, "")
        head_only = req.method == "HEAD"

        headers: dict[str, str] = {
            "Server": self.cfg.server_header,
            "Date": format_datetime(datetime.now(timezone.utc), usegmt=True),
            "Content-Type": content_type,
            "Content-Length": str(len(body)),
            "Connection": "close" if close else "keep-alive",
        }
        headers.update(self.cfg.extra_headers)
        headers.update(route_headers)

        lines = [f"HTTP/1.1 {status} {reason}".rstrip()]
        lines.extend(f"{k}: {v}" for k, v in headers.items())
        raw = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")
        if not head_only:
            raw += body

        writer.write(raw)
        await writer.drain()
        return len(raw)


def _basic_creds(req: _Request) -> tuple[str, str] | None:
    auth = req.headers.get("authorization", "")
    if not auth.lower().startswith("basic "):
        return None
    try:
        raw = base64.b64decode(auth[6:].strip()).decode("latin-1")
    except (binascii.Error, ValueError):
        return None
    user, sep, pw = raw.partition(":")
    return (user, pw) if sep else None


def _build_route(spec: HttpPath, config_dir: str) -> _Route:
    if spec.body_file is not None:
        body = (Path(config_dir) / spec.body_file).read_bytes()
    elif spec.body is not None:
        body = spec.body.encode("utf-8")
    else:
        body = b""
    return _Route(
        methods=frozenset(m.upper() for m in spec.methods),
        status=spec.status,
        body=body,
        content_type=spec.content_type,
        headers=dict(spec.headers),
        vuln_id=spec.vuln_id,
        auth_realm=spec.auth_realm,
        auth_users=dict(spec.auth_users),
        auth_ntlm=spec.auth_ntlm,
    )
