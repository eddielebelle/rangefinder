import asyncio
import socket
import struct

from dataclasses import replace

from helpers import make_ctx

from rangefinder.config.model import Host
from rangefinder.config.services import DnsConfig, DnsRecord
from rangefinder.facades.dns import DnsFacade, _decode_name, _encode_name


def _host(hid, ip):
    return Host(id=hid, hostname=hid, ip=ip, services=[{"type": "banner", "port": 9, "banner": "x"}])


def _cfg():
    return DnsConfig(
        port=53,
        zone="corp.local",
        autofill_hosts=True,
        records=[
            DnsRecord(name="_ldap._tcp.dc._msdcs", type="SRV", value="0 100 389 dc01.corp.local"),
            DnsRecord(name="corp.local", type="MX", value="10 mail.corp.local"),
        ],
    )


def _ctx():
    ctx, sink = make_ctx()
    return replace(ctx, hosts=(_host("dc01", "10.13.37.10"), _host("web01", "10.13.37.20"))), sink


def _facade():
    ctx, sink = _ctx()
    return DnsFacade.from_config(_cfg(), ctx), sink


def _query(qname: str, qtype: int) -> bytes:
    header = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)  # RD set
    return header + _encode_name(qname) + struct.pack("!HH", qtype, 1)


def _parse_answers(resp: bytes):
    txn, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", resp[:12])
    _, offset = _decode_name(resp, 12)
    offset += 4  # qtype+qclass
    out = []
    for _ in range(an):
        _, offset = _decode_name(resp, offset)
        rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", resp[offset : offset + 10])
        offset += 10
        rdata = resp[offset : offset + rdlen]
        offset += rdlen
        out.append((rtype, rdata))
    return flags, an, out


def test_autofill_a_record():
    facade, sink = _facade()
    resp = facade.build_response(_query("web01.corp.local", 1), "10.0.0.9", 5300, "udp")
    flags, an, answers = _parse_answers(resp)
    assert an == 1
    rtype, rdata = answers[0]
    assert rtype == 1
    assert socket.inet_ntoa(rdata) == "10.13.37.20"
    assert any(e["event"]["action"] == "dns_query" for e in sink.events)


def test_autofill_ptr_record():
    """A resolver pointed at us must get real reverse names, not fall through to the host's
    docker naming — so range host IPs autofill PTRs back to their FQDNs."""
    facade, _ = _facade()
    resp = facade.build_response(_query("20.37.13.10.in-addr.arpa", 12), "10.0.0.9", 5300, "udp")
    _, off = _decode_name(resp, 12)
    off += 4  # qtype + qclass
    _, off = _decode_name(resp, off)  # answer owner name
    rtype, _rclass, _ttl, _rdlen = struct.unpack("!HHIH", resp[off : off + 10])
    off += 10
    ptr_target, _ = _decode_name(resp, off)
    assert rtype == 12
    assert ptr_target == "web01.corp.local"


def test_srv_record():
    facade, _ = _facade()
    resp = facade.build_response(_query("_ldap._tcp.dc._msdcs.corp.local", 33), "10.0.0.9", 5300, "udp")
    _, an, answers = _parse_answers(resp)
    assert an == 1
    rtype, rdata = answers[0]
    assert rtype == 33
    prio, weight, port = struct.unpack("!HHH", rdata[:6])
    assert (prio, weight, port) == (0, 100, 389)
    target, _ = _decode_name(rdata, 6)
    assert target == "dc01.corp.local"


def test_mx_record():
    facade, _ = _facade()
    resp = facade.build_response(_query("corp.local", 15), "10.0.0.9", 5300, "udp")
    _, an, answers = _parse_answers(resp)
    assert an == 1
    rtype, rdata = answers[0]
    assert rtype == 15
    assert struct.unpack("!H", rdata[:2])[0] == 10


def test_nxdomain():
    facade, sink = _facade()
    resp = facade.build_response(_query("nope.corp.local", 1), "10.0.0.9", 5300, "udp")
    flags, an, _ = _parse_answers(resp)
    assert an == 0
    assert (flags & 0x000F) == 3  # NXDOMAIN rcode
    q = next(e for e in sink.events if e["event"]["action"] == "dns_query")
    assert q["dns"]["response_code"] == "NXDOMAIN"


def test_udp_end_to_end():
    async def run():
        facade, sink = _facade()
        facade.bind_host = "127.0.0.1"
        facade.port = 0
        # bind an explicit ephemeral UDP port
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))
        facade.port = s.getsockname()[1]
        s.close()
        await facade.start()
        try:
            loop = asyncio.get_running_loop()
            client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client.setblocking(False)
            # UDP connect() is immediate (no handshake) and fixes the default peer, so we
            # can use sock_sendall/sock_recv — which exist on 3.10, unlike sock_sendto.
            client.connect(("127.0.0.1", facade.port))
            await loop.sock_sendall(client, _query("dc01.corp.local", 1))
            data = await asyncio.wait_for(loop.sock_recv(client, 512), timeout=2)
            client.close()
        finally:
            await facade.stop()
        return data

    resp = asyncio.run(run())
    _, an, answers = _parse_answers(resp)
    assert an == 1 and socket.inet_ntoa(answers[0][1]) == "10.13.37.10"


def _axfr_query(zone: str) -> bytes:
    header = struct.pack("!HHHHHH", 0x1234, 0x0000, 1, 0, 0, 0)
    return header + _encode_name(zone) + struct.pack("!HH", 252, 1)  # qtype 252 = AXFR


def _parse_axfr(resp):
    """A served AXFR is a list of messages (chunked); flatten their answer RRs into one list."""
    assert isinstance(resp, list)
    flags0, rrs = None, []
    for msg in resp:
        flags, _, part = _parse_answers(msg)
        flags0 = flags if flags0 is None else flags0
        rrs.extend(part)
    return flags0, rrs


def test_axfr_served_over_tcp_when_allowed():
    ctx, sink = _ctx()
    cfg = _cfg().model_copy(update={"axfr_allowed": True})
    facade = DnsFacade.from_config(cfg, ctx)
    resp = facade.build_response(_axfr_query("corp.local"), "10.0.0.9", 5300, "tcp")
    flags, rrs = _parse_axfr(resp)
    assert (flags & 0x000F) == 0            # NOERROR
    assert len(rrs) >= 3                    # SOA + >=1 record + SOA
    assert rrs[0][0] == 6 and rrs[-1][0] == 6   # bracketed by the zone SOA (type 6)
    # the whole zone leaks — the autofilled dc01 A record rides along in the transfer
    assert any(rtype == 1 and socket.inet_ntoa(rd) == "10.13.37.10" for rtype, rd in rrs)
    q = next(e for e in sink.events if e["event"]["action"] == "dns_query")
    assert q["dns"]["response_code"] == "NOERROR"


def test_axfr_refused_for_foreign_zone_even_when_allowed():
    """AXFR is served only for the zone the twin is authoritative for; a transfer of some other
    zone name is REFUSED, like a real server — not answered with this zone's records."""
    ctx, _ = _ctx()
    cfg = _cfg().model_copy(update={"axfr_allowed": True})
    facade = DnsFacade.from_config(cfg, ctx)
    resp = facade.build_response(_axfr_query("evil.example"), "10.0.0.9", 5300, "tcp")
    flags, an, _ = _parse_answers(resp)   # single REFUSED message, not a list
    assert an == 0
    assert (flags & 0x000F) == 5           # REFUSED


def test_axfr_chunked_across_messages_for_large_zone():
    """A zone too big for one 64 KB TCP message is split across several, each SOA/record framed —
    so a real (large AD) zone transfer doesn't overflow the length prefix."""
    ctx, _ = _ctx()
    big = [DnsRecord(name=f"h{i}", type="TXT", value="x" * 250) for i in range(400)]
    cfg = _cfg().model_copy(update={"axfr_allowed": True, "records": _cfg().records + big})
    facade = DnsFacade.from_config(cfg, ctx)
    resp = facade.build_response(_axfr_query("corp.local"), "10.0.0.9", 5300, "tcp")
    assert isinstance(resp, list) and len(resp) >= 2      # actually chunked
    assert all(len(msg) <= 65535 for msg in resp)         # every message fits the length prefix
    flags, rrs = _parse_axfr(resp)
    assert (flags & 0x000F) == 0 and rrs[0][0] == 6 and rrs[-1][0] == 6


def test_axfr_refused_when_not_allowed():
    facade, sink = _facade()  # axfr_allowed defaults False (fail-closed)
    resp = facade.build_response(_axfr_query("corp.local"), "10.0.0.9", 5300, "tcp")
    flags, an, _ = _parse_answers(resp)
    assert an == 0
    assert (flags & 0x000F) == 5            # REFUSED, like a hardened server
    q = next(e for e in sink.events if e["event"]["action"] == "dns_query")
    assert q["dns"]["response_code"] == "REFUSED"


def test_axfr_refused_over_udp_even_when_allowed():
    ctx, _ = _ctx()
    cfg = _cfg().model_copy(update={"axfr_allowed": True})
    facade = DnsFacade.from_config(cfg, ctx)
    resp = facade.build_response(_axfr_query("corp.local"), "10.0.0.9", 5300, "udp")
    flags, an, _ = _parse_answers(resp)
    assert an == 0
    assert (flags & 0x000F) == 5            # AXFR is TCP-only; refuse over UDP


def test_capture_measures_axfr_posture():
    """Capturing a server that permits AXFR records axfr_allowed=True as measured provenance and
    pulls the whole zone (the transfer being allowed is itself the exposure)."""
    from rangefinder.capture.dns import capture_dns

    async def run():
        ctx, _ = _ctx()
        cfg = _cfg().model_copy(update={"axfr_allowed": True})
        facade = DnsFacade.from_config(cfg, ctx)
        facade.bind_host = "127.0.0.1"
        facade.port = 0
        await facade.start()
        tcp_port = facade._tcp_server.sockets[0].getsockname()[1]
        try:
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(
                None, lambda: capture_dns("127.0.0.1", tcp_port, zone="corp.local", timeout=3.0))
        finally:
            await facade.stop()

    service, warnings, report = asyncio.run(run())
    assert service["axfr_allowed"] is True
    status = {i.field: i.status for i in report.items}
    assert status.get("axfr_allowed") == "measured"
    # the zone leaked via the transfer — the autofilled dc01 A record came through
    assert any(r["type"] == "A" and r["value"] == "10.13.37.10" for r in service["records"])
