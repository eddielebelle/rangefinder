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
            await loop.sock_sendto(client, _query("dc01.corp.local", 1), ("127.0.0.1", facade.port))
            data = await asyncio.wait_for(loop.sock_recv(client, 512), timeout=2)
            client.close()
        finally:
            await facade.stop()
        return data

    resp = asyncio.run(run())
    _, an, answers = _parse_answers(resp)
    assert an == 1 and socket.inet_ntoa(answers[0][1]) == "10.13.37.10"
