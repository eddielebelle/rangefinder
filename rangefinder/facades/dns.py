"""DNS facade (UDP + TCP).

Answers A/AAAA/CNAME/NS/PTR/MX/TXT/SRV queries from the configured records, plus
autofilled A records for every host in the range. High-signal for AD ranges: the
``_ldap._tcp`` / ``_kerberos._tcp`` SRV records that domain-joined tooling uses to locate
a DC. The DNS wire format is simple enough to implement directly on the stdlib (no extra
dependency). Every query is logged.

Deliberate limits: authoritative flat-file answers only — no recursion, no zone transfer
(AXFR), no DNSSEC, no wildcards. Names are encoded uncompressed (valid, marginally larger).
"""

from __future__ import annotations

import asyncio
import socket
import struct

from rangefinder.config.services import DnsConfig, DnsRecord
from rangefinder.facades.base import Facade, FacadeContext
from rangefinder.facades.registry import register
from rangefinder.telemetry import event as ev

# type name <-> numeric code
_TYPE_CODE = {"A": 1, "NS": 2, "CNAME": 5, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28, "SRV": 33}
_CODE_TYPE = {v: k for k, v in _TYPE_CODE.items()}
_QTYPE_ANY = 255
_CLASS_IN = 1


@register("dns")
class DnsFacade(Facade):
    def __init__(self, *, cfg: DnsConfig, ctx: FacadeContext, service_id: str, zone: str):
        super().__init__(
            bind_host=cfg.bind, port=cfg.port, ctx=ctx, service_id=service_id, protocol="dns"
        )
        self.cfg = cfg
        self.zone = zone
        # name(lower) -> list[(type_code, value, ttl)]
        self.records = _build_records(cfg, zone, ctx)
        self._udp_transport: asyncio.BaseTransport | None = None
        self._tcp_server: asyncio.AbstractServer | None = None
        self._stopped: asyncio.Future | None = None

    @classmethod
    def from_config(cls, cfg: DnsConfig, ctx: FacadeContext) -> "DnsFacade":
        zone = (cfg.zone or (ctx.identities.domain if ctx.identities else "") or "").lower().rstrip(".")
        return cls(cfg=cfg, ctx=ctx, service_id=f"dns-{cfg.port}", zone=zone)

    # ---- lifecycle (UDP datagram endpoint + TCP server) --------------------------
    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        self._udp_transport, _ = await loop.create_datagram_endpoint(
            lambda: _DnsUdpProtocol(self), local_addr=(self.bind_host, self.port)
        )
        self._tcp_server = await asyncio.start_server(
            self._handle_tcp, self.bind_host, self.port, reuse_address=True
        )
        self.ctx.emitter.emit(ev.service_listen(self))

    async def serve_forever(self) -> None:
        self._stopped = asyncio.get_running_loop().create_future()
        try:
            await self._stopped
        except asyncio.CancelledError:
            pass

    async def stop(self) -> None:
        if self._udp_transport is not None:
            self._udp_transport.close()
        if self._tcp_server is not None:
            self._tcp_server.close()
            try:
                await self._tcp_server.wait_closed()
            except Exception:
                pass
        if self._stopped is not None and not self._stopped.done():
            self._stopped.set_result(None)

    async def handle(self, scope, reader, writer) -> None:
        raise NotImplementedError  # DNS overrides the transport; base path unused

    async def _handle_tcp(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        src_ip, src_port = (peer[0], peer[1]) if peer else (None, None)
        try:
            while True:
                header = await reader.readexactly(2)
                (length,) = struct.unpack("!H", header)
                query = await reader.readexactly(length)
                response = self.build_response(query, src_ip, src_port, "tcp")
                if response is not None:
                    writer.write(struct.pack("!H", len(response)) + response)
                    await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    # ---- query handling ----------------------------------------------------------
    def build_response(self, data: bytes, src_ip, src_port, transport: str) -> bytes | None:
        try:
            txn_id = data[0:2]
            req_flags = struct.unpack("!H", data[2:4])[0]
            qname, offset = _decode_name(data, 12)
            qtype, qclass = struct.unpack("!HH", data[offset : offset + 4])
            question = data[12 : offset + 4]
        except (IndexError, struct.error):
            return None

        answers, rcode = self._resolve(qname, qtype)
        flags = 0x8000 | (req_flags & 0x7800) | 0x0400 | (req_flags & 0x0100) | rcode
        header = txn_id + struct.pack("!HHHHH", flags, 1, len(answers), 0, 0)
        body = question + b"".join(answers)

        self.ctx.emitter.emit(
            ev.dns_query(
                self,
                src_ip=src_ip,
                src_port=src_port,
                transport=transport,
                qname=qname.lower(),
                qtype=_CODE_TYPE.get(qtype, str(qtype)),
                rcode="NOERROR" if rcode == 0 else "NXDOMAIN",
                answers=len(answers),
            )
        )
        return header + body

    def _resolve(self, qname: str, qtype: int) -> tuple[list[bytes], int]:
        key = qname.lower().rstrip(".")
        rrs = self.records.get(key)
        if not rrs:
            return [], 3  # NXDOMAIN
        answers = [
            _encode_rr(key, code, value, ttl)
            for (code, value, ttl) in rrs
            if qtype == _QTYPE_ANY or code == qtype
        ]
        return answers, 0  # NOERROR (possibly empty if name exists with other types)


class _DnsUdpProtocol(asyncio.DatagramProtocol):
    def __init__(self, facade: DnsFacade):
        self.facade = facade
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr):
        src_ip, src_port = addr[0], addr[1]
        response = self.facade.build_response(data, src_ip, src_port, "udp")
        if response is not None and self.transport is not None:
            self.transport.sendto(response, addr)


# ------------------------------------------------------------------- record building


def _build_records(cfg: DnsConfig, zone: str, ctx: FacadeContext) -> dict[str, list[tuple[int, str, int]]]:
    records: dict[str, list[tuple[int, str, int]]] = {}

    def add(name: str, code: int, value: str, ttl: int):
        records.setdefault(name.lower().rstrip("."), []).append((code, value, ttl))

    for rec in cfg.records:
        code = _TYPE_CODE.get(rec.type)
        if code is None:
            continue
        add(_qualify(rec.name, zone), code, rec.value, rec.ttl)

    if cfg.autofill_hosts and zone:
        for hostname, ip in ctx.hosts:
            fqdn = _qualify(hostname, zone)
            # Don't clobber an explicit A record for the same name.
            if not any(c == 1 for c, _, _ in records.get(fqdn.lower(), [])):
                family = socket.AF_INET6 if ":" in ip else socket.AF_INET
                add(fqdn, 28 if family == socket.AF_INET6 else 1, ip, 300)

    return records


def _qualify(name: str, zone: str) -> str:
    n = name.rstrip(".")
    if not zone:
        return n
    if n.lower() == zone or n.lower().endswith("." + zone):
        return n
    return f"{n}.{zone}" if n else zone


# ---------------------------------------------------------------------- wire codec


def _decode_name(data: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    jumped = False
    end = offset
    while True:
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:  # compression pointer
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                end = offset + 2
            offset = pointer
            jumped = True
            continue
        offset += 1
        labels.append(data[offset : offset + length].decode("latin-1"))
        offset += length
    return ".".join(labels), (end if jumped else offset)


def _encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        if label:
            out += bytes([len(label)]) + label.encode("latin-1")
    return out + b"\x00"


def _encode_rr(name: str, code: int, value: str, ttl: int) -> bytes:
    rdata = _encode_rdata(code, value)
    return _encode_name(name) + struct.pack("!HHIH", code, _CLASS_IN, ttl, len(rdata)) + rdata


def _encode_rdata(code: int, value: str) -> bytes:
    if code == 1:  # A
        return socket.inet_aton(value)
    if code == 28:  # AAAA
        return socket.inet_pton(socket.AF_INET6, value)
    if code in (2, 5, 12):  # NS, CNAME, PTR
        return _encode_name(value)
    if code == 16:  # TXT (chunk into <=255-byte segments)
        raw = value.encode("utf-8")
        out = b""
        for i in range(0, len(raw), 255):
            chunk = raw[i : i + 255]
            out += bytes([len(chunk)]) + chunk
        return out or b"\x00"
    if code == 15:  # MX: "<pref> <exchange>"
        pref, _, exchange = value.partition(" ")
        return struct.pack("!H", int(pref)) + _encode_name(exchange.strip())
    if code == 33:  # SRV: "<prio> <weight> <port> <target>"
        prio, weight, port, target = value.split()
        return struct.pack("!HHH", int(prio), int(weight), int(port)) + _encode_name(target)
    return value.encode("utf-8")
