"""RDP facade — X.224 security negotiation + TLS + CredSSP/NLA challenge.

impacket's server does not speak RDP, and a bare X.224 stub (the old ``banner`` decoy on
3389) is a giveaway: every real Windows host answers the RDP Negotiation Request, upgrades
to TLS presenting a machine certificate, and — when NLA is required — challenges over
CredSSP, which leaks its NetBIOS/DNS name, domain and OS build. This facade does exactly
that, so ``nmap --script rdp-enum-encryption,rdp-ntlm-info`` / ``rdp-sec-check`` see a
convincing, hardened RDP service and every probe is logged.

It deliberately stops where a real unauthenticated session would: after issuing the NTLM
Type-2 challenge (all rdp-ntlm-info needs), it validates any Type-3 against the range's
identities for telemetry, then drops — an attacker without valid CredSSP creds is rejected,
exactly as a hardened box rejects them. No RDP graphics/MCS layer is emulated.
"""

from __future__ import annotations

import asyncio
import struct

from pyasn1.codec.der import decoder as der_decoder
from pyasn1.codec.der import encoder as der_encoder
from pyasn1.type import namedtype, tag, univ

from rangefinder.config.services import RdpConfig
from rangefinder.facades.base import Facade, FacadeContext
from rangefinder.facades.registry import register
from rangefinder.telemetry import event as ev

# MS-RDPBCGR 2.2.1.1.1 requested / selected protocols (RDP Negotiation Request/Response).
PROTOCOL_RDP = 0x00000000
PROTOCOL_SSL = 0x00000001
PROTOCOL_HYBRID = 0x00000002
PROTOCOL_RDSTLS = 0x00000004
PROTOCOL_HYBRID_EX = 0x00000008
_PROTOCOL_NAMES = {
    PROTOCOL_RDP: "RDP", PROTOCOL_SSL: "SSL", PROTOCOL_HYBRID: "HYBRID",
    PROTOCOL_RDSTLS: "RDSTLS", PROTOCOL_HYBRID_EX: "HYBRID_EX",
}

# RDP Negotiation Response/Failure PDU types + failure codes (MS-RDPBCGR 2.2.1.2.1/2.2.1.2.2).
_TYPE_NEG_REQ = 0x01
_TYPE_NEG_RSP = 0x02
_TYPE_NEG_FAILURE = 0x03
_SSL_REQUIRED_BY_SERVER = 0x00000001
_HYBRID_REQUIRED_BY_SERVER = 0x00000005
# EXTENDED_CLIENT_DATA_SUPPORTED | DYNVC_GFX_PROTOCOL_SUPPORTED — a modern server sets these.
_NEG_RSP_FLAGS = 0x03

_IDLE_TIMEOUT_S = 15.0
# rdp-ntlm-info reads the Type-2 challenge and disconnects, so don't hold the connection
# long waiting for a Type-3 that a scanner will never send.
_CREDSSP_REPLY_TIMEOUT_S = 5.0


@register("rdp")
class RdpFacade(Facade):
    def __init__(self, *, cfg: RdpConfig, ctx: FacadeContext, service_id: str):
        super().__init__(
            bind_host=cfg.bind, port=cfg.port, ctx=ctx, service_id=service_id,
            protocol="ms-wbt-server",
        )
        self.cfg = cfg
        self._ntlm_version = _ntlm_version(cfg.os_version)
        self._ssl_ctx = None  # built at start(); needs the host cert

    @classmethod
    def from_config(cls, cfg: RdpConfig, ctx: FacadeContext) -> "RdpFacade":
        return cls(cfg=cfg, ctx=ctx, service_id=f"rdp-{cfg.port}")

    async def start(self) -> None:
        from rangefinder import tls

        # RDP presents a self-signed machine cert (CN = FQDN) after the TLS upgrade; reuse
        # the shared per-host backdated cert so ssl-cert / s_client see a real certificate.
        self._ssl_ctx = tls.server_context(self.host_name, self.tls_sans())
        await super().start()

    @property
    def _netbios_domain(self) -> str:
        ids = self.ctx.identities
        if ids and ids.netbios:
            return ids.netbios
        if ids and ids.domain:
            return ids.domain.split(".")[0].upper()
        return "WORKGROUP"

    async def handle(self, scope, reader, writer) -> None:
        try:
            x224 = await asyncio.wait_for(_read_tpkt(reader), timeout=_IDLE_TIMEOUT_S)
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, ValueError):
            return
        # X.224 Connection Request PDU code is 0xE0 in the upper nibble.
        if len(x224) < 2 or (x224[1] & 0xF0) != 0xE0:
            return

        cookie, requested = _parse_cr(x224)
        selected = self._select_protocol(requested)
        scope.emit(ev.rdp_negotiate(
            scope, requested=_protocol_list(requested),
            selected=_PROTOCOL_NAMES.get(selected, "NONE") if selected is not None else "FAILURE",
            nla_required=self.cfg.nla_required, cookie=cookie,
        ))

        if selected is None:
            code = _HYBRID_REQUIRED_BY_SERVER if self.cfg.nla_required else _SSL_REQUIRED_BY_SERVER
            writer.write(_cc(_TYPE_NEG_FAILURE, code, flags=0))
            await writer.drain()
            return

        writer.write(_cc(_TYPE_NEG_RSP, selected, flags=_NEG_RSP_FLAGS))
        await writer.drain()

        # SSL and HYBRID both upgrade to TLS; HYBRID additionally runs CredSSP over it.
        if not await self._start_tls(writer):
            return
        if selected in (PROTOCOL_HYBRID, PROTOCOL_HYBRID_EX):
            await self._credssp(scope, reader, writer)

    def _select_protocol(self, requested: int) -> int | None:
        """Server security policy. None => send a Negotiation Failure (client offer refused)."""
        if requested & PROTOCOL_HYBRID:
            return PROTOCOL_HYBRID
        if self.cfg.nla_required:
            return None  # -> HYBRID_REQUIRED_BY_SERVER
        if requested & PROTOCOL_SSL:
            return PROTOCOL_SSL
        return None  # plain RDP with no TLS -> SSL_REQUIRED_BY_SERVER

    async def _start_tls(self, writer) -> bool:
        # asyncio's stream-level start_tls is client-only, so drive the server-side upgrade
        # through the loop directly and rebind the writer to the new (encrypted) transport;
        # the same StreamReaderProtocol keeps feeding the existing reader with decrypted data.
        loop = asyncio.get_running_loop()
        transport = writer.transport
        protocol = transport.get_protocol()
        try:
            new_transport = await loop.start_tls(
                transport, protocol, self._ssl_ctx, server_side=True,
                ssl_handshake_timeout=_IDLE_TIMEOUT_S,
            )
        except Exception:
            return False
        writer._transport = new_transport
        return True

    async def _credssp(self, scope, reader, writer) -> None:
        try:
            req = await asyncio.wait_for(_read_der(reader), timeout=_IDLE_TIMEOUT_S)
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, ValueError):
            return
        type1 = _ntlm_from_tsrequest(req, want_type=0x01)
        if type1 is None:
            return
        scope.emit(ev.rdp_auth(scope, action="rdp_ntlm_negotiate", outcome="success"))

        type2, challenge8, _, _ = ntlm_build_challenge(
            type1, self.host_name.upper(), self._netbios_domain, version=self._ntlm_version)
        version = _tsrequest_version(req)
        writer.write(_ts_request(type2, version=version))
        await writer.drain()

        # Best-effort: a real client may follow with a Type-3 we can validate for telemetry
        # (rdp-ntlm-info stops after the challenge, so this often simply times out).
        try:
            resp = await asyncio.wait_for(_read_der(reader), timeout=_CREDSSP_REPLY_TIMEOUT_S)
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, ValueError):
            return
        type3 = _ntlm_from_tsrequest(resp, want_type=0x03)
        if type3 is None:
            return
        self._validate_type3(scope, type3, challenge8)

    def _validate_type3(self, scope, type3: bytes, challenge8: bytes) -> None:
        from rangefinder import ntlm as ntlm_mod

        domain, user, workstation, authed = "", "", "", False
        nthash = None
        ids = self.ctx.identities
        if ids:
            # Peek the username first so we can look up its NT hash, then validate.
            _, user_peek, _, _ = ntlm_mod.validate(type3, None, challenge8)
            for u in ids.users:
                if u.password and u.sam.lower() == user_peek.lower():
                    nthash = ntlm_mod.nt_hash(u.password)
                    break
        domain, user, workstation, authed = ntlm_mod.validate(type3, nthash, challenge8)
        scope.emit(ev.rdp_auth(
            scope, action="rdp_auth", kind="event" if authed else "alert",
            outcome="success" if authed else "failure",
            extra={"auth": {"domain": domain or None, "user": user or None,
                            "workstation": workstation or None, "method": "credssp-ntlm"}},
        ))


# ---------------------------------------------------------------- NTLM version helper

def _ntlm_version(os_version: str) -> bytes:
    """Pack "major.minor.build" into the 8-byte NTLM VERSION struct rdp-ntlm-info reads."""
    parts = (os_version or "10.0.0").split(".")
    try:
        major, minor = int(parts[0]), int(parts[1])
        build = int(parts[2]) if len(parts) > 2 else 0
    except ValueError:
        major, minor, build = 10, 0, 0
    # ProductMajor(1) ProductMinor(1) ProductBuild(2 LE) Reserved(3) NTLMRevisionCurrent(1)
    return struct.pack("<BBH3xB", major & 0xFF, minor & 0xFF, build & 0xFFFF, 0x0F)


def ntlm_build_challenge(*args, **kwargs):  # thin indirection so tests can monkeypatch
    from rangefinder.ntlm import build_challenge

    return build_challenge(*args, **kwargs)


# ---------------------------------------------------------------- TPKT / X.224 wire

async def _read_tpkt(reader: asyncio.StreamReader) -> bytes:
    """Read one TPKT-framed PDU and return its X.224 payload (bytes after the 4-byte TPKT)."""
    hdr = await reader.readexactly(4)
    if hdr[0] != 0x03:
        raise ValueError("not a TPKT frame")
    total = int.from_bytes(hdr[2:4], "big")
    if total < 4 or total > 4096:
        raise ValueError("implausible TPKT length")
    return await reader.readexactly(total - 4)


def _parse_cr(x224: bytes) -> tuple[str | None, int]:
    """Parse an X.224 Connection Request -> (mstshash cookie, requestedProtocols bitmask)."""
    user_data = x224[7:]  # LI(1) CR(1) DST(2) SRC(2) CLASS(1) then variable user data
    cookie = None
    if user_data.startswith(b"Cookie: mstshash="):
        end = user_data.find(b"\r\n")
        if end >= 0:
            cookie = user_data[len(b"Cookie: mstshash="):end].decode("latin-1", "replace")
            user_data = user_data[end + 2:]
    elif user_data.startswith(b"Cookie:") or user_data.startswith(b"mstshash="):
        end = user_data.find(b"\r\n")
        user_data = user_data[end + 2:] if end >= 0 else b""
    requested = PROTOCOL_RDP
    if len(user_data) >= 8 and user_data[0] == _TYPE_NEG_REQ:
        requested = int.from_bytes(user_data[4:8], "little")
    return cookie, requested


def _cc(neg_type: int, value: int, *, flags: int) -> bytes:
    """Build a TPKT + X.224 Connection Confirm carrying an RDP Negotiation Response/Failure."""
    neg = struct.pack("<BBHI", neg_type, flags, 0x0008, value)
    # X.224 CC: LI, 0xD0, DST-REF=0x0000, SRC-REF=0x1234, CLASS=0x00, then the 8-byte neg PDU.
    x224 = bytes([6 + len(neg), 0xD0]) + b"\x00\x00" + b"\x12\x34" + b"\x00" + neg
    return b"\x03\x00" + struct.pack(">H", 4 + len(x224)) + x224


def _protocol_list(mask: int) -> list[str]:
    if mask == PROTOCOL_RDP:
        return ["RDP"]
    return [name for bit, name in _PROTOCOL_NAMES.items() if bit and (mask & bit)]


# ---------------------------------------------------------------- CredSSP TSRequest

def _ctx_tag(n: int, constructed: bool = False):
    fmt = tag.tagFormatConstructed if constructed else tag.tagFormatSimple
    return tag.Tag(tag.tagClassContext, fmt, n)


class _NegoToken(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("negoToken", univ.OctetString().subtype(explicitTag=_ctx_tag(0))),
    )


class _NegoData(univ.SequenceOf):
    componentType = _NegoToken()


class TSRequest(univ.Sequence):
    """MS-CSSP 2.2.1 TSRequest (only the fields the NLA handshake uses)."""
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("version", univ.Integer().subtype(explicitTag=_ctx_tag(0))),
        namedtype.OptionalNamedType(
            "negoTokens", _NegoData().subtype(explicitTag=_ctx_tag(1, constructed=True))),
        namedtype.OptionalNamedType(
            "authInfo", univ.OctetString().subtype(explicitTag=_ctx_tag(2))),
        namedtype.OptionalNamedType(
            "pubKeyAuth", univ.OctetString().subtype(explicitTag=_ctx_tag(3))),
        namedtype.OptionalNamedType(
            "errorCode", univ.Integer().subtype(explicitTag=_ctx_tag(4))),
        namedtype.OptionalNamedType(
            "clientNonce", univ.OctetString().subtype(explicitTag=_ctx_tag(5))),
    )


async def _read_der(reader: asyncio.StreamReader) -> bytes:
    """Read exactly one DER SEQUENCE element (the TSRequest) off the TLS stream."""
    head = await reader.readexactly(2)
    if head[0] != 0x30:
        raise ValueError("not a DER SEQUENCE")
    first = head[1]
    if first < 0x80:
        return head + await reader.readexactly(first)
    n = first & 0x7F
    if not 1 <= n <= 4:
        raise ValueError("implausible DER length")
    len_bytes = await reader.readexactly(n)
    return head + len_bytes + await reader.readexactly(int.from_bytes(len_bytes, "big"))


def _ntlm_from_tsrequest(der: bytes, *, want_type: int) -> bytes | None:
    """Extract the NTLM message of ``want_type`` (1=negotiate, 3=authenticate) from a TSRequest."""
    try:
        ts, _ = der_decoder.decode(der, asn1Spec=TSRequest())
        tokens = ts.getComponentByName("negoTokens")
        if tokens is None or len(tokens) == 0:
            return None
        token = bytes(tokens[0].getComponentByName("negoToken"))
    except Exception:
        return None
    idx = token.find(b"NTLMSSP\x00")  # CredSSP carries the raw NTLMSSP token as the negoToken
    if idx < 0 or len(token) < idx + 12:
        return None
    ntlm = token[idx:]
    if int.from_bytes(ntlm[8:12], "little") != want_type:
        return None
    return ntlm


def _tsrequest_version(der: bytes) -> int:
    try:
        ts, _ = der_decoder.decode(der, asn1Spec=TSRequest())
        return min(int(ts.getComponentByName("version")), 6)
    except Exception:
        return 6


def _ts_request(nego_token: bytes, *, version: int) -> bytes:
    ts = TSRequest()
    ts["version"] = version
    # In-place nested assignment: pyasn1 auto-vivifies each component with the correct
    # explicitly-tagged schema ([1] NegoData -> SEQUENCE -> [0] negoToken OCTET STRING).
    ts["negoTokens"][0]["negoToken"] = nego_token
    return der_encoder.encode(ts)
