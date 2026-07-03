import base64
from dataclasses import replace

from helpers import make_ctx

from rangefinder.config.model import ADUser, Identities
from rangefinder.config.services import HttpConfig, HttpPath
from rangefinder.facades.base import ConnScope
from rangefinder.facades.http import HttpFacade, _Request


def _facade():
    ctx, sink = make_ctx()
    ids = Identities(domain="acme.corp", netbios="ACME",
                     users=[ADUser(sam="svc-web", password="Autumn2025!")])
    cfg = HttpConfig(port=80, paths={"/owa": HttpPath(body="INBOX", auth_ntlm=True)})
    return HttpFacade.from_config(cfg, replace(ctx, identities=ids)), sink


def _req(auth=None):
    headers = {"authorization": auth} if auth else {}
    return _Request("GET", "/owa", "/owa", None, "1.1", headers, 0, False)


def _b64(b):
    return base64.b64encode(b).decode()


def _handshake(facade, scope, password):
    from impacket.ntlm import getNTLMSSPType1, getNTLMSSPType3

    state = {}
    assert facade._ntlm_gate(scope, _req(), state)[0] == 401  # no creds -> challenge
    type1 = getNTLMSSPType1("", "ACME")
    g = facade._ntlm_gate(scope, _req("NTLM " + _b64(type1.getData())), state)
    assert g[0] == 401
    type2 = base64.b64decode(g[1]["WWW-Authenticate"].split(" ", 1)[1])
    type3, _ = getNTLMSSPType3(type1, type2, "svc-web", password, "acme.corp", "", "")
    return facade._ntlm_gate(scope, _req("NTLM " + _b64(type3.getData())), state)


def test_http_ntlm_correct_password():
    facade, sink = _facade()
    scope = ConnScope(facade, "10.0.0.9", 5000)
    assert _handshake(facade, scope, "Autumn2025!") is None  # authorized -> serve route
    assert any(e["event"]["action"] == "http_auth" and e["event"]["outcome"] == "success"
               for e in sink.events)


def test_http_ntlm_wrong_password():
    facade, sink = _facade()
    scope = ConnScope(facade, "10.0.0.9", 5000)
    g = _handshake(facade, scope, "wrongpass")
    assert g is not None and g[0] == 401  # rejected
    assert any(e["event"]["action"] == "http_auth" and e["event"]["outcome"] == "failure"
               for e in sink.events)
