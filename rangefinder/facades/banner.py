"""Generic server-speaks-first TCP banner facade.

Answers nmap ``-sV`` and manual probes for line-oriented protocols (SSH/FTP/SMTP/POP3)
via a text banner + regex rules, and for binary protocols (MySQL greeting, RDP X.224
negotiation) via a raw banner + hex rules. It intentionally does NOT implement any real
handshake past the greeting/probe response — it is a version-detection decoy only, and
everything it sees is logged.
"""

from __future__ import annotations

import asyncio
import os
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
        self._text_rules = [
            (re.compile(rule.match.encode("latin-1")), rule)
            for rule in cfg.rules
            if not cfg.binary and rule.match
        ]
        self._hex_rules = [
            (bytes.fromhex(rule.match_hex), rule)
            for rule in cfg.rules
            if cfg.binary and rule.match_hex
        ]
        self._banner_bytes = _greeting_bytes(cfg)

    @classmethod
    def from_config(cls, cfg: BannerConfig, ctx: FacadeContext) -> "BannerFacade":
        return cls(cfg=cfg, ctx=ctx, service_id=f"{cfg.protocol}-{cfg.port}")

    async def handle(self, scope, reader, writer):
        if self.cfg.banner_delay_ms:
            await asyncio.sleep(self.cfg.banner_delay_ms / 1000)

        greeting = self._banner_bytes
        if greeting and self.cfg.protocol == "mysql":
            # Real mysqld emits a fresh random salt + connection id every connect; a static
            # handshake (identical across connections) is an obvious decoy tell.
            greeting = _randomize_mysql_greeting(greeting)
        if greeting:
            writer.write(greeting)
            await writer.drain()
            scope.emit(ev.banner_sent(scope, self.cfg.banner or self.cfg.banner_hex or ""))

        if self.cfg.close_after_banner:
            return

        if self.cfg.binary:
            await self._serve_binary(scope, reader, writer)
        else:
            await self._serve_text(scope, reader, writer)

    async def _serve_text(self, scope, reader, writer):
        term = self.cfg.terminator.encode("latin-1")
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
            for pattern, rule in self._text_rules:
                if pattern.search(line):
                    matched_rule = rule.match
                    out = rule.respond.encode("latin-1")
                    response = out if rule.raw else out + term
                    close_after = rule.close_after
                    break

            scope.emit(ev.line_received(scope, _text_preview(line), matched_rule))
            if response is not None:
                writer.write(response)
                await writer.drain()
            if close_after:
                return

    async def _serve_binary(self, scope, reader, writer):
        while True:
            try:
                data = await asyncio.wait_for(
                    reader.read(4096), timeout=self.cfg.idle_timeout_s
                )
            except (asyncio.TimeoutError, ValueError):
                return
            if not data:
                return

            matched_rule = None
            response: bytes | None = None
            close_after = False
            for needle, rule in self._hex_rules:
                if needle in data:
                    matched_rule = rule.match_hex
                    response = bytes.fromhex(rule.respond_hex) if rule.respond_hex else None
                    close_after = rule.close_after
                    break

            scope.emit(ev.line_received(scope, _hex_preview(data), matched_rule))
            if response:
                writer.write(response)
                await writer.drain()
            # Close promptly unless a matched rule explicitly keeps the connection open;
            # holding unmatched probes open stalls scanners like nmap --version-all.
            if close_after or matched_rule is None:
                return


def _randomize_mysql_greeting(data: bytes) -> bytes:
    """Freshen the random fields of a MySQL HandshakeV10 packet per connection.

    Layout after the 4-byte packet header: [1 protocol=0x0a][server-version \\0]
    [4 connection-id][8 auth-plugin-data-1][1 filler][2 cap-low][1 charset][2 status]
    [2 cap-high][1 auth-len][10 reserved][12 auth-plugin-data-2]... We only touch the
    connection id and the two salt halves — the fields real mysqld randomizes — leaving the
    configured version/capabilities intact. Returns the input unchanged if it is not a v10
    handshake.
    """
    try:
        if len(data) < 40 or data[4] != 0x0A:
            return data
        nul = data.index(0, 5)  # terminator of the server-version string
        b = bytearray(data)
        p = nul + 1
        b[p:p + 4] = os.urandom(4)          # connection / thread id
        b[p + 4:p + 12] = os.urandom(8)     # auth-plugin-data part 1
        salt2 = p + 12 + 1 + 2 + 1 + 2 + 2 + 1 + 10  # skip filler + caps + charset + status + reserved
        b[salt2:salt2 + 12] = os.urandom(12)  # auth-plugin-data part 2
        return bytes(b)
    except (ValueError, IndexError):
        return data


def _greeting_bytes(cfg: BannerConfig) -> bytes:
    if cfg.banner_hex:
        return bytes.fromhex(cfg.banner_hex)
    # Text mode: an empty banner still sends the terminator so probe-first scanners see a
    # response (avoids nmap "tcpwrapped"); binary mode sends nothing unless banner_hex set.
    if cfg.binary:
        return b""
    return (cfg.banner + cfg.terminator).encode("latin-1")


def _text_preview(line: bytes) -> str:
    return line[:_PREVIEW_BYTES].decode("latin-1", "replace").rstrip("\r\n")


def _hex_preview(data: bytes) -> str:
    return data[:32].hex()
