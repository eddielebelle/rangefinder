"""Facade base class, per-connection scope, and the shared connection wrapper.

Concurrency rule: a single Facade instance serves every connection on its port, so its
attributes are effectively read-only after construction. All per-connection state lives
on a ConnScope (or in handler locals) — never on ``self``.
"""

from __future__ import annotations

import abc
import asyncio
import time
import uuid
from dataclasses import dataclass, field

from rangefinder.telemetry import event as ev
from rangefinder.telemetry.emitter import Emitter

# Benign connection outcomes produced constantly by scanners; not worth logging as errors.
_BENIGN = (
    ConnectionResetError,
    BrokenPipeError,
    asyncio.IncompleteReadError,
    asyncio.CancelledError,
)


@dataclass(frozen=True)
class FacadeContext:
    """Immutable per-host context injected into every facade on the host."""

    host_id: str
    host_name: str
    host_ip: str | None
    emitter: Emitter
    config_dir: str  # directory of the config file, for resolving body_file paths


@dataclass
class ConnScope:
    """All mutable state for one TCP connection."""

    facade: "Facade"
    src_ip: str | None
    src_port: int | None
    conn_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    start: float = field(default_factory=time.monotonic)

    def emit(self, event: dict) -> None:
        self.facade.ctx.emitter.emit(event)


class Facade(abc.ABC):
    type_name: str = "base"  # set by the @register decorator

    def __init__(
        self,
        *,
        bind_host: str,
        port: int,
        ctx: FacadeContext,
        service_id: str,
        protocol: str,
    ) -> None:
        self.bind_host = bind_host
        self.port = port
        self.ctx = ctx
        self.service_id = service_id
        self.protocol = protocol
        self._server: asyncio.AbstractServer | None = None

    # ---- identity fields read by the telemetry envelope --------------------------
    @property
    def host_id(self) -> str:
        return self.ctx.host_id

    @property
    def host_name(self) -> str:
        return self.ctx.host_name

    @property
    def host_ip(self) -> str | None:
        return self.ctx.host_ip

    @property
    def dataset(self) -> str:
        return f"rangefinder.{self.type_name}"

    # ---- construction ------------------------------------------------------------
    @classmethod
    @abc.abstractmethod
    def from_config(cls, cfg, ctx: FacadeContext) -> "Facade":
        """Build a facade from its typed config model and host context.

        Must fully validate config and resolve any files *before* binding a socket, so
        a bad config fails fast instead of half-starting the host.
        """

    # ---- per-connection logic ----------------------------------------------------
    @abc.abstractmethod
    async def handle(
        self,
        scope: ConnScope,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Serve one connection. Must not raise on client misbehavior."""

    # ---- lifecycle ---------------------------------------------------------------
    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._wrapped_handle, self.bind_host, self.port, reuse_address=True
        )
        self.ctx.emitter.emit(ev.service_listen(self))

    @property
    def bound_port(self) -> int:
        """Actual bound port (useful when configured port is 0, e.g. in tests)."""
        assert self._server is not None and self._server.sockets
        return self._server.sockets[0].getsockname()[1]

    async def serve_forever(self) -> None:
        assert self._server is not None
        async with self._server:
            await self._server.serve_forever()

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            try:
                await self._server.wait_closed()
            except Exception:
                pass

    async def _wrapped_handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peer = writer.get_extra_info("peername")
        src_ip, src_port = (peer[0], peer[1]) if peer else (None, None)
        scope = ConnScope(self, src_ip, src_port)
        scope.emit(ev.connection_open(scope))
        try:
            await self.handle(scope, reader, writer)
        except _BENIGN:
            pass
        except Exception as exc:  # never let one connection kill the listener
            scope.emit(ev.connection_error(scope, exc))
        finally:
            duration_ns = int((time.monotonic() - scope.start) * 1e9)
            scope.emit(ev.connection_close(scope, duration_ns))
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
