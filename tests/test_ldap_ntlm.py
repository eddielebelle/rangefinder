import asyncio
from dataclasses import replace

from helpers import make_ctx

from rangefinder.config.model import ADUser, Identities
from rangefinder.config.services import LdapConfig
from rangefinder.facades.base import ConnScope
from rangefinder.facades.ldap import LdapFacade


class _FakeWriter:
    def __init__(self):
        self.buf = b""

    def write(self, data):
        self.buf += data

    async def drain(self):
        pass


def _facade():
    ctx, sink = make_ctx()
    ids = Identities(domain="acme.corp", netbios="ACME",
                     users=[ADUser(sam="svc-web", password="Autumn2025!")])
    return LdapFacade.from_config(LdapConfig(port=389), replace(ctx, identities=ids)), sink


def _bind_result(buf):
    from pyasn1.codec.ber import decoder
    from pyasn1_modules import rfc2251 as L

    msg, _ = decoder.decode(buf, asn1Spec=L.LDAPMessage())
    br = msg["protocolOp"]["bindResponse"]
    creds = bytes(br["serverSaslCreds"]) if br["serverSaslCreds"].hasValue() else b""
    return int(br["resultCode"]), creds


async def _spnego_login(facade, password):
    from impacket.ntlm import getNTLMSSPType1, getNTLMSSPType3
    from impacket.spnego import SPNEGO_NegTokenInit, SPNEGO_NegTokenResp, TypesMech

    scope = ConnScope(facade, "10.0.0.9", 5000)
    state = {}

    type1 = getNTLMSSPType1("", "ACME")
    init = SPNEGO_NegTokenInit()
    init["MechTypes"] = [TypesMech["NTLMSSP - Microsoft NTLM Security Support Provider"]]
    init["MechToken"] = type1.getData()
    w1 = _FakeWriter()
    await facade._handle_spnego(scope, w1, 1, init.getData(), state)
    rc1, creds = _bind_result(w1.buf)
    assert rc1 == 14  # saslBindInProgress
    type2 = SPNEGO_NegTokenResp(creds)["ResponseToken"]

    type3, _ = getNTLMSSPType3(type1, bytes(type2), "svc-web", password, "acme.corp", "", "")
    resp = SPNEGO_NegTokenResp()
    resp["ResponseToken"] = type3.getData()
    w2 = _FakeWriter()
    await facade._handle_spnego(scope, w2, 2, resp.getData(), state)
    rc2, _ = _bind_result(w2.buf)
    return rc2


def test_ldap_ntlm_spnego_correct_password():
    facade, sink = _facade()
    rc = asyncio.run(_spnego_login(facade, "Autumn2025!"))
    assert rc == 0  # success
    assert any(e["event"]["action"] == "ldap_bind" and e["rangefinder"]["auth"]["result"] == "success"
               for e in sink.events)


def test_ldap_ntlm_spnego_wrong_password():
    facade, sink = _facade()
    rc = asyncio.run(_spnego_login(facade, "wrongpass"))
    assert rc == 49  # invalidCredentials
    assert any(e["event"]["action"] == "ldap_bind" and e["rangefinder"]["auth"]["result"] == "invalidCredentials"
               for e in sink.events)


def test_simple_bind_validates_known_users():
    """A known identity's wrong password must be rejected (like a real DC); unknown users and
    anonymous stay permissive so captured-directory replay keeps working."""
    import asyncio

    from pyasn1_modules import rfc2251 as L

    facade, _ = _facade()  # identities: svc-web / Autumn2025!
    scope = ConnScope(facade, "10.0.0.9", 5001)

    def simple_bind(dn, pw):
        br = L.BindRequest()
        br["version"] = 3
        br["name"] = dn
        br["authentication"]["simple"] = pw.encode()
        w = _FakeWriter()
        asyncio.run(facade._handle_bind(scope, w, 7, br))
        return _bind_result(w.buf)[0]

    assert simple_bind("svc-web@acme.corp", "Autumn2025!") == 0    # correct -> success
    assert simple_bind("svc-web@acme.corp", "WrongPass!") == 49    # wrong -> invalidCredentials
    assert simple_bind("cn=svc-web,cn=users,dc=acme,dc=corp", "x") == 49  # DN form, wrong
    assert simple_bind("cn=nobody,dc=acme,dc=corp", "whatever") == 0      # unknown -> permissive
    assert simple_bind("", "") == 0                                # anonymous -> success
