"""Minimal Kerberos KDC facade for AS-REP roasting.

Answers AS-REQ on 88 (UDP + TCP). For an account flagged ``no_preauth``
(DONT_REQUIRE_PREAUTH), it issues an AS-REP whose enc-part is encrypted with the account's
password-derived key — exactly the crackable material AS-REP roasting harvests, so
impacket's ``GetNPUsers.py`` retrieves a real ``$krb5asrep$`` hash. Accounts that require
pre-auth get ``KDC_ERR_PREAUTH_REQUIRED`` (so a roasting tool correctly skips them). Every
AS-REQ, issued AS-REP (roast = alert), and error is logged.

Deliberate limits: this is a roasting decoy, not a real KDC — it does not validate pre-auth
timestamps or issue usable service tickets (Kerberoasting / TGS follows). The TGT it embeds
is encrypted with a random krbtgt key the attacker never needs. Reuses impacket's krb5
crypto/ASN.1 primitives (existing dependency).
"""

from __future__ import annotations

import asyncio
import datetime
import struct
from types import SimpleNamespace

from rangefinder.config.services import KerberosConfig
from rangefinder.facades.base import Facade, FacadeContext
from rangefinder.facades.registry import register
from rangefinder.telemetry import event as ev

_RC4 = 23
_AES256 = 18
_AES128 = 17
_PA_ENC_TIMESTAMP = 2


@register("kerberos")
class KerberosFacade(Facade):
    def __init__(self, *, cfg: KerberosConfig, ctx: FacadeContext, service_id: str):
        super().__init__(
            bind_host=cfg.bind, port=cfg.port, ctx=ctx, service_id=service_id, protocol="kerberos"
        )
        self.cfg = cfg
        ids = ctx.identities
        self.realm = (cfg.realm or (ids.domain if ids else "example.local")).upper()
        self.users = {u.sam.lower(): u for u in (ids.users if ids else [])}
        self._udp = None
        self._tcp = None
        self._stopped: asyncio.Future | None = None
        self._k = None  # impacket krb5 handles, loaded lazily in start()

    @classmethod
    def from_config(cls, cfg: KerberosConfig, ctx: FacadeContext) -> "KerberosFacade":
        return cls(cfg=cfg, ctx=ctx, service_id=f"kerberos-{cfg.port}")

    async def handle(self, scope, reader, writer) -> None:
        raise NotImplementedError  # own transport (UDP + TCP)

    async def start(self) -> None:
        self._k = _load_krb5()
        loop = asyncio.get_running_loop()
        self._udp, _ = await loop.create_datagram_endpoint(
            lambda: _KrbUdpProtocol(self), local_addr=(self.bind_host, self.port)
        )
        self._tcp = await asyncio.start_server(self._handle_tcp, self.bind_host, self.port, reuse_address=True)
        self.ctx.emitter.emit(ev.service_listen(self))

    async def serve_forever(self) -> None:
        self._stopped = asyncio.get_running_loop().create_future()
        try:
            await self._stopped
        except asyncio.CancelledError:
            pass

    async def stop(self) -> None:
        if self._udp is not None:
            self._udp.close()
        if self._tcp is not None:
            self._tcp.close()
            try:
                await self._tcp.wait_closed()
            except Exception:
                pass
        if self._stopped is not None and not self._stopped.done():
            self._stopped.set_result(None)

    async def _handle_tcp(self, reader, writer) -> None:
        peer = writer.get_extra_info("peername")
        src_ip, src_port = (peer[0], peer[1]) if peer else (None, None)
        try:
            while True:
                header = await reader.readexactly(4)
                (length,) = struct.unpack("!I", header)
                data = await reader.readexactly(length)
                resp = self.build_response(data, src_ip, src_port)
                if resp is not None:
                    writer.write(struct.pack("!I", len(resp)) + resp)
                    await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    # ---- KDC logic ---------------------------------------------------------------
    def build_response(self, data: bytes, src_ip, src_port) -> bytes | None:
        if not data:
            return None
        # Application tag: [APPLICATION 10] AS-REQ = 0x6a, [APPLICATION 12] TGS-REQ = 0x6c.
        try:
            if data[0] == 0x6A:
                req, _ = self._k.decoder.decode(data, asn1Spec=self._k.AS_REQ())
                return self._handle_as_req(req, src_ip, src_port)
            # TGS-REQ (Kerberoasting) not implemented yet.
            self._emit_error(src_ip, src_port, None, "tgs_not_implemented")
            return self._build_error(self._k.KDC_ERR_SVC_UNAVAILABLE, self.realm, "krbtgt")
        except Exception:
            return None

    def _handle_as_req(self, req, src_ip, src_port) -> bytes:
        body = req["req-body"]
        user = str(body["cname"]["name-string"][0])
        realm = str(body["realm"]) or self.realm
        nonce = int(body["nonce"])
        etypes = [int(e) for e in body["etype"]]
        padata_types = [int(p["padata-type"]) for p in req["padata"]] if req["padata"].hasValue() else []
        has_preauth = _PA_ENC_TIMESTAMP in padata_types

        self.ctx.emitter.emit(ev.krb_event(
            self, "kerberos_as_req", category=["authentication"], etype=["start"],
            src_ip=src_ip, src_port=src_port,
            extra={"kerberos": {"user": user, "realm": realm, "preauth": has_preauth}},
        ))

        acct = self.users.get(user.lower())
        if acct is None:
            self._emit_error(src_ip, src_port, user, "principal_unknown")
            return self._build_error(self._k.KDC_ERR_C_PRINCIPAL_UNKNOWN, realm, user)

        # Known account, but not roastable (no key, or pre-auth genuinely required).
        if acct.password is None or (not acct.no_preauth and not has_preauth):
            self._emit_error(src_ip, src_port, user, "preauth_required")
            return self._build_error(self._k.KDC_ERR_PREAUTH_REQUIRED, realm, user)

        etype = _choose_etype(etypes)
        roastable = acct.no_preauth and not has_preauth
        self.ctx.emitter.emit(ev.krb_event(
            self, "kerberos_as_rep",
            category=["authentication"], etype=["start"],
            kind="alert" if roastable else "event", outcome="success",
            src_ip=src_ip, src_port=src_port,
            extra={"kerberos": {"user": user, "realm": realm, "etype": etype,
                                "asrep_roastable": roastable}},
        ))
        return self._build_as_rep(user, realm, acct.password, nonce, etype)

    def _emit_error(self, src_ip, src_port, user, reason) -> None:
        self.ctx.emitter.emit(ev.krb_event(
            self, "kerberos_error", category=["authentication"], etype=["info"],
            outcome="failure", src_ip=src_ip, src_port=src_port,
            extra={"kerberos": {"user": user, "error": reason}},
        ))

    # ---- message builders (impacket krb5) ----------------------------------------
    def _derive_key(self, password: str, user: str, etype: int):
        salt = None if etype == _RC4 else (self.realm + user)
        return self._k.string_to_key(etype, password, salt)

    def _build_as_rep(self, user, realm, password, nonce, etype) -> bytes:
        k = self._k
        now = datetime.datetime.now(datetime.timezone.utc)
        end = now + datetime.timedelta(hours=10)
        sesskey = b"\x11" * (16 if etype == _RC4 else 32)
        user_key = self._derive_key(password, user, etype)
        krbtgt_key = k.string_to_key(_RC4, self.cfg.krbtgt_password, None)

        # EncTicketPart -> encrypted with krbtgt key (attacker never reads it)
        etp = k.EncTicketPart()
        etp["flags"] = k.encodeFlags([])
        etp["key"] = k.noValue
        etp["key"]["keytype"] = etype
        etp["key"]["keyvalue"] = sesskey
        etp["crealm"] = realm
        k.seq_set(etp, "cname", k.Principal(user, type=k.NT_PRINCIPAL).components_to_asn1)
        etp["transited"] = k.noValue
        etp["transited"]["tr-type"] = 0
        etp["transited"]["contents"] = b""
        etp["authtime"] = k.KerberosTime.to_asn1(now)
        etp["endtime"] = k.KerberosTime.to_asn1(end)
        etp_enc = k.enctypes[_RC4].encrypt(krbtgt_key, 2, k.encoder.encode(etp), None)

        # EncASRepPart -> encrypted with the USER key (the roastable material)
        enc = k.EncASRepPart()
        enc["key"] = k.noValue
        enc["key"]["keytype"] = etype
        enc["key"]["keyvalue"] = sesskey
        enc["last-req"] = k.noValue
        enc["last-req"][0] = k.noValue
        enc["last-req"][0]["lr-type"] = 0
        enc["last-req"][0]["lr-value"] = k.KerberosTime.to_asn1(now)
        enc["nonce"] = nonce
        enc["flags"] = k.encodeFlags([])
        enc["authtime"] = k.KerberosTime.to_asn1(now)
        enc["endtime"] = k.KerberosTime.to_asn1(end)
        enc["srealm"] = realm
        k.seq_set(enc, "sname", k.Principal("krbtgt/%s" % realm, type=k.NT_SRV_INST).components_to_asn1)
        enc_cipher = k.enctypes[etype].encrypt(user_key, 3, k.encoder.encode(enc), None)

        asrep = k.AS_REP()
        asrep["pvno"] = 5
        asrep["msg-type"] = k.AS_REP_TAG
        asrep["crealm"] = realm
        k.seq_set(asrep, "cname", k.Principal(user, type=k.NT_PRINCIPAL).components_to_asn1)
        asrep["ticket"] = k.noValue
        t = asrep["ticket"]
        t["tkt-vno"] = 5
        t["realm"] = realm
        k.seq_set(t, "sname", k.Principal("krbtgt/%s" % realm, type=k.NT_SRV_INST).components_to_asn1)
        t["enc-part"] = k.noValue
        t["enc-part"]["etype"] = _RC4
        t["enc-part"]["kvno"] = 2
        t["enc-part"]["cipher"] = etp_enc
        asrep["enc-part"] = k.noValue
        asrep["enc-part"]["etype"] = etype
        asrep["enc-part"]["kvno"] = 2
        asrep["enc-part"]["cipher"] = enc_cipher
        return k.encoder.encode(asrep)

    def _build_error(self, error_code: int, realm: str, sname: str) -> bytes:
        k = self._k
        now = datetime.datetime.now(datetime.timezone.utc)
        err = k.KRB_ERROR()
        err["pvno"] = 5
        err["msg-type"] = k.KRB_ERROR_TAG
        err["stime"] = k.KerberosTime.to_asn1(now)
        err["susec"] = 0
        err["error-code"] = int(error_code)
        err["realm"] = realm
        k.seq_set(err, "sname", k.Principal("krbtgt/%s" % realm, type=k.NT_SRV_INST).components_to_asn1)
        return k.encoder.encode(err)


def _choose_etype(offered: list[int]) -> int:
    for pref in (_RC4, _AES256, _AES128):
        if pref in offered:
            return pref
    return offered[0] if offered else _RC4


class _KrbUdpProtocol(asyncio.DatagramProtocol):
    def __init__(self, facade: KerberosFacade):
        self.facade = facade
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        resp = self.facade.build_response(data, addr[0], addr[1])
        if resp is not None and self.transport is not None:
            self.transport.sendto(resp, addr)


def _load_krb5() -> SimpleNamespace:
    from pyasn1.codec.der import decoder, encoder
    from pyasn1.type.univ import noValue

    from impacket.krb5 import constants
    from impacket.krb5.asn1 import (
        AS_REP, AS_REQ, EncASRepPart, EncTicketPart, KRB_ERROR, seq_set,
    )
    from impacket.krb5.crypto import _enctype_table, string_to_key
    from impacket.krb5.types import KerberosTime, Principal

    return SimpleNamespace(
        decoder=decoder, encoder=encoder, noValue=noValue,
        AS_REQ=AS_REQ, AS_REP=AS_REP, EncASRepPart=EncASRepPart, EncTicketPart=EncTicketPart,
        KRB_ERROR=KRB_ERROR, seq_set=seq_set,
        string_to_key=string_to_key, enctypes=_enctype_table,
        Principal=Principal, KerberosTime=KerberosTime,
        NT_PRINCIPAL=constants.PrincipalNameType.NT_PRINCIPAL.value,
        NT_SRV_INST=constants.PrincipalNameType.NT_SRV_INST.value,
        AS_REP_TAG=int(constants.ApplicationTagNumbers.AS_REP.value),
        KRB_ERROR_TAG=int(constants.ApplicationTagNumbers.KRB_ERROR.value),
        encodeFlags=constants.encodeFlags,
        KDC_ERR_C_PRINCIPAL_UNKNOWN=int(constants.ErrorCodes.KDC_ERR_C_PRINCIPAL_UNKNOWN.value),
        KDC_ERR_PREAUTH_REQUIRED=int(constants.ErrorCodes.KDC_ERR_PREAUTH_REQUIRED.value),
        KDC_ERR_SVC_UNAVAILABLE=int(constants.ErrorCodes.KDC_ERR_SVC_UNAVAILABLE.value),
    )
