import datetime
from dataclasses import replace

from helpers import make_ctx

from rangefinder.config.model import ADUser, Identities
from rangefinder.config.services import KerberosConfig
from rangefinder.facades.kerberos import KerberosFacade, _load_krb5


def _identities():
    return Identities(
        domain="acme.corp",
        users=[
            ADUser(sam="svc-web", password="Autumn2025!", no_preauth=True),
            ADUser(sam="alice", password="Sup3r!"),  # requires preauth
        ],
    )


def _facade():
    ctx, _ = make_ctx()
    ctx = replace(ctx, identities=_identities())
    facade = KerberosFacade.from_config(KerberosConfig(port=88), ctx)
    facade._k = _load_krb5()  # normally loaded in start()
    return facade


def _as_req(user, realm="ACME.CORP", etypes=(23,)):
    from pyasn1.codec.der import encoder
    from impacket.krb5 import constants
    from impacket.krb5.asn1 import AS_REQ, seq_set, seq_set_iter
    from impacket.krb5.types import KerberosTime, Principal

    req = AS_REQ()
    req["pvno"] = 5
    req["msg-type"] = int(constants.ApplicationTagNumbers.AS_REQ.value)
    body = seq_set(req, "req-body")
    body["kdc-options"] = constants.encodeFlags([])
    seq_set(body, "cname", Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value).components_to_asn1)
    body["realm"] = realm
    seq_set(body, "sname", Principal("krbtgt/%s" % realm, type=constants.PrincipalNameType.NT_SRV_INST.value).components_to_asn1)
    body["till"] = KerberosTime.to_asn1(datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc))
    body["nonce"] = 12345
    seq_set_iter(body, "etype", list(etypes))
    return encoder.encode(req)


def test_asrep_roast_for_no_preauth_user():
    facade = _facade()
    resp = facade.build_response(_as_req("svc-web"), "10.0.0.9", 5000)
    # AS-REP is [APPLICATION 11] -> first byte 0x6b
    assert resp[0] == 0x6B
    from pyasn1.codec.der import decoder
    from impacket.krb5.asn1 import AS_REP
    from impacket.krb5.crypto import _enctype_table, string_to_key

    asrep, _ = decoder.decode(resp, asn1Spec=AS_REP())
    cipher = bytes(asrep["enc-part"]["cipher"])
    etype = int(asrep["enc-part"]["etype"])
    # The enc-part must decrypt with the account's password-derived key (i.e. it is the
    # crackable roast material).
    key = string_to_key(etype, "Autumn2025!", None)
    decrypted = _enctype_table[etype].decrypt(key, 3, cipher)
    assert decrypted  # decrypts cleanly -> a cracker would recover the password


def test_preauth_required_for_normal_user():
    facade = _facade()
    resp = facade.build_response(_as_req("alice"), "10.0.0.9", 5000)
    # KRB-ERROR is [APPLICATION 30] -> first byte 0x7e
    assert resp[0] == 0x7E
    from pyasn1.codec.der import decoder
    from impacket.krb5.asn1 import KRB_ERROR

    err, _ = decoder.decode(resp, asn1Spec=KRB_ERROR())
    assert int(err["error-code"]) == facade._k.KDC_ERR_PREAUTH_REQUIRED


def test_unknown_principal():
    facade = _facade()
    resp = facade.build_response(_as_req("nobody"), "10.0.0.9", 5000)
    from pyasn1.codec.der import decoder
    from impacket.krb5.asn1 import KRB_ERROR

    err, _ = decoder.decode(resp, asn1Spec=KRB_ERROR())
    assert int(err["error-code"]) == facade._k.KDC_ERR_C_PRINCIPAL_UNKNOWN


def test_tgs_rep_is_kerberoastable():
    # The TGS-REP's service ticket must decrypt with the SPN account's key (crackable).
    ctx, _ = make_ctx()
    ids = Identities(domain="acme.corp", users=[
        ADUser(sam="svc-sql", password="Summ3r2025!", spn="MSSQLSvc/app01.acme.corp:1433"),
    ])
    facade = KerberosFacade.from_config(KerberosConfig(port=88), replace(ctx, identities=ids))
    facade._k = _load_krb5()
    k = facade._k
    from impacket.krb5.crypto import _enctype_table, string_to_key

    reply_key = k.Key(23, b"\x22" * 16)
    raw = facade._build_tgs_rep("attacker", "MSSQLSvc/app01.acme.corp:1433", "Summ3r2025!", reply_key, 8, 0)
    from pyasn1.codec.der import decoder
    from impacket.krb5.asn1 import TGS_REP

    rep, _ = decoder.decode(raw, asn1Spec=TGS_REP())
    cipher = bytes(rep["ticket"]["enc-part"]["cipher"])
    spn_key = string_to_key(23, "Summ3r2025!", None)
    assert _enctype_table[23].decrypt(spn_key, 2, cipher)  # cracks to the SPN password
    # the reply enc-part must decrypt with the client's reply key
    assert _enctype_table[23].decrypt(reply_key, 8, bytes(rep["enc-part"]["cipher"]))


def test_telemetry_flags_roast_as_alert():
    ctx, sink = make_ctx()
    ctx = replace(ctx, identities=_identities())
    facade = KerberosFacade.from_config(KerberosConfig(port=88), ctx)
    facade._k = _load_krb5()
    facade.build_response(_as_req("svc-web"), "10.0.0.9", 5000)
    rep = next(e for e in sink.events if e["event"]["action"] == "kerberos_as_rep")
    assert rep["event"]["kind"] == "alert"
    assert rep["rangefinder"]["kerberos"]["asrep_roastable"] is True
