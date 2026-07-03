"""Generic server-speaks-first TCP banner facade.

Answers nmap ``-sV`` and manual probes for line-oriented protocols (SSH/FTP/SMTP/POP3).
It sends a configurable banner immediately on connect with the exact terminator, then
optionally replies to lines matching configured regex rules. It intentionally does NOT
implement any real handshake (SSH KEX, FTP auth, etc.) — it is a version-detection decoy
only, and everything it sees is logged.
"""

from __future__ import annotations

import asyncio
import re

from rangefinder.config.services import BannerConfig
from rangefinder.facades.base import Facade, FacadeContext
from rangefinder.facades.registry import register
from rangefinder.telemetry import event as ev

_PREVIEW_BYTES = 200


@register("banner")
class BannerFacade(Facade):
    def __init__(self, *, cfg: BannerConfig, ctx: FacadeContext, service_id: str):
        super().__init__(
            bind_host=cfg.bind,
            port=cfg.port,
            ctx=ctx,
            service_id=service_id,
            protocol=cfg.protocol,
        )
        self.cfg = cfg
        # Compile once; instance is shared across connections (read-only after init).
        self._rules = [
            (re.compile(rule.match.encode("latin-1")), rule) for rule in cfg.rules
        ]
        self._banner_bytes = (cfg.banner + cfg.terminator).encode("latin-1")

    @classmethod
    def from_config(cls, cfg: BannerConfig, ctx: FacadeContext) -> "BannerFacade":
        return cls(cfg=cfg, ctx=ctx, service_id=f"{cfg.protocol}-{cfg.port}")

    async def handle(self, scope, reader, writer):
        if self.cfg.banner_delay_ms:
            await asyncio.sleep(self.cfg.banner_delay_ms / 1000)

        writer.write(self._banner_bytes)
        await writer.drain()
        scope.emit(ev.banner_sent(scope, self.cfg.banner))

        if self.cfg.close_after_banner:
            return

        while True:
            try:
                line = await asyncio.wait_for(
                    reader.readline(), timeout=self.cfg.idle_timeout_s
                )
            except (asyncio.TimeoutError, ValueError):
                return
            if not line:
                return

            matched_rule = None
            response: bytes | None = None
            close_after = False
            for pattern, rule in self._rules:
                if pattern.search(line):
                    matched_rule = rule.match
                    out = rule.respond.encode("latin-1")
                    response = out if rule.raw else out + self.cfg.terminator.encode(
                        "latin-1"
                    )
                    close_after = rule.close_after
                    break

            scope.emit(ev.line_received(scope, _preview(line), matched_rule))

            if response is not None:
                writer.write(response)
                await writer.drain()
            if close_after:
                return


def _preview(line: bytes) -> str:
    return line[:_PREVIEW_BYTES].decode("latin-1", "replace").rstrip("\r\n")
