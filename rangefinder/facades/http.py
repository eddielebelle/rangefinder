"""HTTP/1.1 facade.

Enumeration/version-detection grade: it answers curl, dirb/gobuster and scanner HTTP
probes with a configurable server header and a table of canned routes, and logs every
request. It is not a real application server — planted-vuln routes are canned
request/response decoys, not exploitable code paths.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
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
        while True:
            req = await self._read_request(reader)
            if req is None:
                return  # EOF or unrecoverable parse error (already responded if 400)
            route = self.routes.get(req.path)
            status, body, content_type, headers, vuln_id, matched = self._resolve(
                req, route
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

    # ---- request parsing ---------------------------------------------------------
    async def _read_request(self, reader: asyncio.StreamReader) -> _Request | None:
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=_READ_TIMEOUT_S)
        except (asyncio.TimeoutError, ValueError):
            return None
        if not line:
            return None  # peer closed

        nbytes = len(line)
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
    )
