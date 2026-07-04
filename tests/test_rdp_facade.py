import asyncio
import socket
import ssl
import struct
from dataclasses import replace

from helpers import make_ctx

from impacket import ntlm as imp_ntlm

from rangefinder.config.model import ADUser, Identities
from rangefinder.config.services import RdpConfig
from rangefinder.facades.rdp import (
    PROTOCOL_HYBRID,
    PROTOCOL_RDP,
    PROTOCOL_SSL,
    RdpFacade,
    TSRequest,
    _cc,
    _ntlm_from_tsrequest,
    _ntlm_version,
    _parse_cr,
    _ts_request,
)


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# ------------------------------------------------------------------- wire-format units

def test_ntlm_version_packing():
    v = _ntlm_version("10.0.20348")
    assert v[0] == 10 and v[1] == 0
    assert struct.unpack("<H", v[2:4])[0] == 20348
    assert v[7] == 0x0F  # NTLMRevisionCurrent
    assert _ntlm_version("bogus")[:2] == b"\x0a\x00"  # falls back, never raises


def test_parse_cr_cookie_and_protocols():
    neg = struct.pack("<BBHI", 0x01, 0x00, 0x0008, PROTOCOL_HYBRID | PROTOCOL_SSL)
    ud = b"Cookie: mstshash=alice\r\n" + neg
    x224 = bytes([6 + len(ud), 0xE0]) + b"\x00\x00\x00\x00\x00" + ud
    cookie, requested = _parse_cr(x224)
    assert cookie == "alice"
    assert requested == (PROTOCOL_HYBRID | PROTOCOL_SSL)


def test_cc_frame_shape():
    frame = _cc(0x02, PROTOCOL_HYBRID, flags=0x03)
    assert frame[0] == 0x03 and frame[1] == 0x00                 # TPKT
    assert struct.unpack(">H", frame[2:4])[0] == len(frame)      # length
    assert frame[5] == 0xD0                                      # X.224 CC
    neg = frame[-8:]
    assert neg[0] == 0x02                                        # negotiation response
    assert struct.unpack("<I", neg[4:8])[0] == PROTOCOL_HYBRID


def test_tsrequest_roundtrip():
    ntlm_token = b"NTLMSSP\x00" + struct.pack("<I", 2) + b"payload-bytes"
    der = _ts_request(ntlm_token, version=6)
    from pyasn1.codec.der import decoder
    ts, _ = decoder.decode(der, asn1Spec=TSRequest())
    assert int(ts["version"]) == 6
    assert _ntlm_from_tsrequest(der, want_type=2) == ntlm_token
    assert _ntlm_from_tsrequest(der, want_type=3) is None  # wrong message type


# ------------------------------------------------------------------- live negotiation

def _recvn(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise EOFError()
        buf += chunk
    return buf


def _read_tpkt(s):
    hdr = _recvn(s, 4)
    return _recvn(s, struct.unpack(">H", hdr[2:4])[0] - 4)


def _read_der(s):
    head = _recvn(s, 2)
    first = head[1]
    if first < 0x80:
        return head + _recvn(s, first)
    n = first & 0x7F
    lb = _recvn(s, n)
    return head + lb + _recvn(s, int.from_bytes(lb, "big"))


def _cr(protocols, cookie=b"admin"):
    neg = struct.pack("<BBHI", 0x01, 0x00, 0x0008, protocols)
    ud = b"Cookie: mstshash=" + cookie + b"\r\n" + neg
    x224 = bytes([6 + len(ud), 0xE0]) + b"\x00\x00\x00\x00\x00" + ud
    return b"\x03\x00" + struct.pack(">H", 4 + len(x224)) + x224


def _negotiate(port, protocols):
    s = socket.create_connection(("127.0.0.1", port), timeout=6)
    s.sendall(_cr(protocols))
    ud = _read_tpkt(s)[7:]
    return s, ud[0], struct.unpack("<I", ud[4:8])[0]  # sock, pdu_type, value


def _tls(sock):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx.wrap_socket(sock, server_hostname="x")


async def _serve(cfg, ctx):
    facade = RdpFacade.from_config(cfg, ctx)
    facade.bind_host = "127.0.0.1"
    facade.port = cfg.port
    await facade.start()
    return facade


def test_nla_required_rejects_non_hybrid():
    async def run():
        ctx, sink = make_ctx()
        cfg = RdpConfig(port=_free_port(), nla_required=True)
        facade = await _serve(cfg, ctx)
        try:
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(None, _negotiate, cfg.port, PROTOCOL_SSL), sink
        finally:
            await facade.stop()

    (sock, pdu_type, code), sink = asyncio.run(run())
    sock.close()
    assert pdu_type == 0x03                 # Negotiation Failure
    assert code == 0x00000005               # HYBRID_REQUIRED_BY_SERVER (NLA required)
    neg = next(e for e in sink.events if e["event"]["action"] == "rdp_negotiate")
    assert neg["rangefinder"]["rdp"]["selected_protocol"] == "FAILURE"
    assert neg["rangefinder"]["rdp"]["cookie"] == "admin"


def test_hybrid_negotiate_tls_and_credssp_leak():
    """The crown jewel: HYBRID -> TLS cert -> CredSSP NTLM challenge leaking name/domain/OS."""
    from cryptography import x509

    ids = Identities(domain="acme.corp", netbios="ACME",
                     users=[ADUser(sam="svc-rdp", password="Summer2025!")])

    def client(port):
        sock, pdu_type, selected = _negotiate(port, PROTOCOL_HYBRID)
        assert pdu_type == 0x02 and selected == PROTOCOL_HYBRID
        tls = _tls(sock)
        cert = x509.load_der_x509_certificate(tls.getpeercert(True))
        # send NTLM Type1 wrapped in a TSRequest, read the Type2 back
        type1 = imp_ntlm.getNTLMSSPType1("WS", "", True)
        tls.sendall(_ts_request(type1.getData(), version=6))
        type2 = _ntlm_from_tsrequest(_read_der(tls), want_type=2)
        tls.close()
        chal = imp_ntlm.NTLMAuthChallenge(type2)
        avs = imp_ntlm.AV_PAIRS(chal["TargetInfoFields"])

        def av(k):
            v = avs[k]
            return v[1].decode("utf-16le") if v and v[1] else None

        ver = chal["Version"]
        return {
            "cn": cert.subject.rfc4514_string(),
            "netbios_computer": av(imp_ntlm.NTLMSSP_AV_HOSTNAME),
            "netbios_domain": av(imp_ntlm.NTLMSSP_AV_DOMAINNAME),
            "dns_domain": av(imp_ntlm.NTLMSSP_AV_DNS_DOMAINNAME),
            "version": f"{ver[0]}.{ver[1]}.{struct.unpack('<H', ver[2:4])[0]}",
        }

    async def run():
        ctx, sink = make_ctx()
        ctx = replace(ctx, host_name="FS01", identities=ids)
        cfg = RdpConfig(port=_free_port(), nla_required=True, os_version="10.0.17763")
        facade = await _serve(cfg, ctx)
        try:
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(None, client, cfg.port), sink
        finally:
            await facade.stop()

    result, sink = asyncio.run(run())
    assert result["cn"] == "CN=FS01"
    assert result["netbios_computer"] == "FS01"
    assert result["netbios_domain"] == "ACME"
    assert result["dns_domain"] == "ACME"
    assert result["version"] == "10.0.17763"   # OS build leak tracks os_version
    assert "rdp_ntlm_negotiate" in {e["event"]["action"] for e in sink.events}


def test_credssp_type3_validation():
    """A CredSSP Type-3 is validated against identities: right hash -> success, wrong -> alert."""
    ids = Identities(domain="acme.corp", netbios="ACME",
                     users=[ADUser(sam="svc-rdp", password="Summer2025!")])

    def client(port, password):
        sock, _, _ = _negotiate(port, PROTOCOL_HYBRID)
        tls = _tls(sock)
        type1 = imp_ntlm.getNTLMSSPType1("WS", "", True)
        tls.sendall(_ts_request(type1.getData(), version=6))
        type2 = _ntlm_from_tsrequest(_read_der(tls), want_type=2)
        type3, _ = imp_ntlm.getNTLMSSPType3(type1, type2, "svc-rdp", password, "ACME")
        tls.sendall(_ts_request(type3.getData(), version=6))
        tls.close()

    async def run(password):
        ctx, sink = make_ctx()
        ctx = replace(ctx, host_name="FS01", identities=ids)
        cfg = RdpConfig(port=_free_port())
        facade = await _serve(cfg, ctx)
        try:
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, client, cfg.port, password)
            await asyncio.sleep(0.2)  # let the server process the Type-3
        finally:
            await facade.stop()
        return sink

    good = asyncio.run(run("Summer2025!"))
    auth = next(e for e in good.events if e["event"]["action"] == "rdp_auth")
    assert auth["event"]["outcome"] == "success"
    assert auth["rangefinder"]["auth"]["user"] == "svc-rdp"
    assert auth["rangefinder"]["auth"]["method"] == "credssp-ntlm"

    bad = asyncio.run(run("WrongPassword!"))
    auth = next(e for e in bad.events if e["event"]["action"] == "rdp_auth")
    assert auth["event"]["outcome"] == "failure"
    assert auth["event"]["kind"] == "alert"
