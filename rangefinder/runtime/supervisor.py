"""Per-host supervisor: serve all of a host's facades in one event loop.

Docker sends SIGTERM then SIGKILL after a grace period (default 10s). The supervisor
catches SIGTERM/SIGINT, stops accepting, cancels serve tasks, and exits cleanly within
that window. Telemetry sinks flush per event, so nothing buffered is lost.
"""

from __future__ import annotations

import asyncio
import signal

from rangefinder.facades.base import Facade, FacadeContext
from rangefinder.telemetry import event as ev
from rangefinder.telemetry.emitter import Emitter

# Leave headroom before Docker's SIGKILL.
_DRAIN_GRACE_S = 8.0


class HostSupervisor:
    def __init__(
        self, facades: list[Facade], emitter: Emitter, ctx: FacadeContext
    ) -> None:
        self.facades = facades
        self.emitter = emitter
        self.ctx = ctx
        self._stop = asyncio.Event()

    async def run(self) -> None:
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                loop.add_signal_handler(sig, self._stop.set)
            except NotImplementedError:  # e.g. non-main thread; not expected in prod
                pass

        # Phase 1: bind every listener. If any fails, roll all back and abort.
        started: list[Facade] = []
        try:
            for facade in self.facades:
                await facade.start()
                started.append(facade)
        except OSError as exc:
            for facade in started:
                await facade.stop()
            raise RuntimeError(
                f"failed to bind {facade.type_name} on port {facade.port}: {exc}"
            ) from exc

        # Phase 2: serve until stop signalled.
        serve_tasks = [
            asyncio.create_task(f.serve_forever(), name=f.service_id) for f in started
        ]
        self.emitter.emit(
            ev.host_event(
                self.ctx,
                "host_ready",
                {"services": [f.service_id for f in started]},
            )
        )
        await self._stop.wait()

        # Phase 3: graceful shutdown, bounded so we always beat SIGKILL.
        self.emitter.emit(ev.host_event(self.ctx, "host_stopping"))
        for facade in started:
            await facade.stop()
        for task in serve_tasks:
            task.cancel()
        try:
            await asyncio.wait_for(
                asyncio.gather(*serve_tasks, return_exceptions=True),
                timeout=_DRAIN_GRACE_S,
            )
        except asyncio.TimeoutError:
            pass
        self.emitter.close()


def serve_host(
    facades: list[Facade], emitter: Emitter, ctx: FacadeContext
) -> None:
    """Run a host's facades to completion (blocks until SIGTERM/SIGINT)."""
    ports = [f.port for f in facades]
    dupes = sorted({p for p in ports if ports.count(p) > 1})
    if dupes:
        raise RuntimeError(f"host {ctx.host_id!r}: duplicate bind ports {dupes}")
    asyncio.run(HostSupervisor(facades, emitter, ctx).run())
