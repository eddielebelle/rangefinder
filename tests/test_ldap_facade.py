import asyncio

from helpers import make_ctx

from pyasn1.codec.ber import decoder, encoder
from pyasn1_modules import rfc2251 as L

from rangefinder.config.model import ADGroup, ADUser, Identities
from rangefinder.config.services import LdapConfig
from rangefinder.facades.ldap import (
    Entry,
    LdapFacade,
    build_directory,
    eval_filter,
    in_scope,
)


def _identities():
    return Identities(
        domain="corp.local",
        netbios="CORP",
        groups=[ADGroup(name="Domain Admins", members=["administrator", "svc-backup"])],
        users=[
            ADUser(sam="administrator", display_name="Administrator", groups=["Domain Admins"]),
            ADUser(
                sam="svc-backup",
                display_name="Backup Service",
                groups=["Domain Admins"],
                description="pw: Winter2024!",
            ),
            ADUser(sam="jsmith", display_name="Jane Smith"),
        ],
    )


# ---------------------------------------------------------------- directory + filters


def test_build_computers():
    from rangefinder.config.model import Host
    from rangefinder.facades.ldap import build_computers

    hosts = [
        Host(id="dc01", hostname="DC01", ip="10.20.0.10", os="windows_server_2022",
             tags=["domain-controller"], services=[{"type": "ldap", "port": 389}]),
        Host(id="ws01", hostname="WS01", ip="10.20.0.101", os="windows_11",
             services=[{"type": "banner", "port": 445, "banner": "x"}]),
        Host(id="web01", hostname="WEB01", ip="10.20.0.30", os="ubuntu_22_04",
             services=[{"type": "http", "port": 80}]),
    ]
    entries = build_computers(hosts, "DC=acme,DC=corp", "acme.corp")
    dns = [e.dn for e in entries]
    # DC lands under the Domain Controllers OU; workstation under Computers; Linux excluded.
    assert "CN=DC01,OU=Domain Controllers,DC=acme,DC=corp" in dns
    assert "CN=WS01,CN=Computers,DC=acme,DC=corp" in dns
    assert not any("WEB01" in d for d in dns)
    dc = next(e for e in entries if e.dn.startswith("CN=DC01"))
    assert dc.get("sAMAccountName") == ["DC01$"]
    assert dc.get("operatingSystem") == ["Windows Server 2022 Standard"]


def test_build_directory():
    base, entries = build_directory(_identities(), "DC01", None)
    assert base == "DC=corp,DC=local"
    dns = [e.dn for e in entries]
    assert "CN=svc-backup" not in dns  # keyed by display_name
    svc = next(e for e in entries if e.get("sAMAccountName") == ["svc-backup"])
    assert svc.get("description") == ["pw: Winter2024!"]
    assert "CN=Domain Admins,CN=Users,DC=corp,DC=local" in svc.get("memberOf")


def test_in_scope():
    base = "DC=corp,DC=local"
    assert in_scope("CN=Users,DC=corp,DC=local", base, 2)  # subtree
    assert not in_scope("CN=Users,DC=corp,DC=local", base, 0)  # base
    assert in_scope(base, base, 0)
    assert in_scope("CN=Users,DC=corp,DC=local", base, 1)  # one level


def _filter(text_kind):
    return text_kind


def test_eval_equality_and_present():
    e = Entry("CN=x", {"objectClass": ["user"], "sAMAccountName": ["jsmith"]})
    f = L.Filter()
    ava = f.setComponentByName("equalityMatch").getComponentByName("equalityMatch")
    ava["attributeDesc"] = "sAMAccountName"
    ava["assertionValue"] = "JSMITH"  # case-insensitive
    assert eval_filter(f, e) is True

    fp = L.Filter()
    fp["present"] = "objectClass"
    assert eval_filter(fp, e) is True
    fp2 = L.Filter()
    fp2["present"] = "mail"
    assert eval_filter(fp2, e) is False


# ---------------------------------------------------------------------- wire protocol


def _ctx_with_identities():
    ctx, sink = make_ctx()
    # FacadeContext is frozen; rebuild with identities.
    from dataclasses import replace

    return replace(ctx, identities=_identities()), sink


async def _run_ldap_session(messages: list[bytes]) -> tuple[list, list]:
    ctx, sink = _ctx_with_identities()
    facade = LdapFacade.from_config(LdapConfig(port=389), ctx)
    facade.port = 0
    facade.bind_host = "127.0.0.1"
    await facade.start()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", facade.bound_port)
        for m in messages:
            writer.write(m)
        await writer.drain()
        writer.write_eof()
        raw = await reader.read(-1)
        writer.close()
        await writer.wait_closed()
    finally:
        await facade.stop()
    return _decode_all(raw), sink.events


def _decode_all(raw: bytes) -> list:
    out, rest = [], raw
    while rest:
        msg, rest = decoder.decode(rest, asn1Spec=L.LDAPMessage())
        out.append(msg)
    return out


def _bind_request(mid=1, name="", password=""):
    m = L.LDAPMessage()
    m["messageID"] = mid
    br = L.BindRequest()
    br["version"] = 3
    br["name"] = name
    br["authentication"]["simple"] = password.encode()
    m["protocolOp"]["bindRequest"] = br
    return encoder.encode(m)


def _search_request(mid, base, scope, filt):
    m = L.LDAPMessage()
    m["messageID"] = mid
    sr = L.SearchRequest()
    sr["baseObject"] = base
    sr["scope"] = scope
    sr["derefAliases"] = 0
    sr["sizeLimit"] = 0
    sr["timeLimit"] = 0
    sr["typesOnly"] = 0
    sr["filter"] = filt
    m["protocolOp"]["searchRequest"] = sr
    return encoder.encode(m)


def _present_filter(attr):
    f = L.Filter()
    f["present"] = attr
    return f


def test_anonymous_bind_success():
    responses, events = asyncio.run(_run_ldap_session([_bind_request()]))
    assert responses[0]["protocolOp"].getName() == "bindResponse"
    assert int(responses[0]["protocolOp"]["bindResponse"]["resultCode"]) == 0
    assert any(e["event"]["action"] == "ldap_bind" for e in events)


def test_rootdse_query():
    reqs = [_bind_request(), _search_request(2, "", 0, _present_filter("objectClass"))]
    responses, _ = asyncio.run(_run_ldap_session(reqs))
    entries = [r for r in responses if r["protocolOp"].getName() == "searchResEntry"]
    assert len(entries) == 1
    attrs = {str(a["type"]): [str(v) for v in a["vals"]] for a in entries[0]["protocolOp"]["searchResEntry"]["attributes"]}
    assert attrs["defaultNamingContext"] == ["DC=corp,DC=local"]
    assert attrs["supportedLDAPVersion"] == ["3"]


def test_subtree_search_returns_users_and_groups():
    reqs = [
        _bind_request(),
        _search_request(2, "DC=corp,DC=local", 2, _present_filter("objectClass")),
    ]
    responses, events = asyncio.run(_run_ldap_session(reqs))
    entries = [r for r in responses if r["protocolOp"].getName() == "searchResEntry"]
    dns = [str(r["protocolOp"]["searchResEntry"]["objectName"]) for r in entries]
    assert any("svc-backup" == _sam(r) for r in entries)
    assert "CN=Domain Admins,CN=Users,DC=corp,DC=local" in dns
    # the planted secret is enumerable
    svc = next(r for r in entries if _sam(r) == "svc-backup")
    attrs = {str(a["type"]): [str(v) for v in a["vals"]] for a in r_attrs(svc)}
    assert attrs["description"] == ["pw: Winter2024!"]
    done = [r for r in responses if r["protocolOp"].getName() == "searchResDone"]
    assert int(done[0]["protocolOp"]["searchResDone"]["resultCode"]) == 0
    assert any(e["event"]["action"] == "ldap_search" for e in events)


def r_attrs(resp):
    return resp["protocolOp"]["searchResEntry"]["attributes"]


def _sam(resp):
    for a in r_attrs(resp):
        if str(a["type"]).lower() == "samaccountname":
            return str(a["vals"][0])
    return None
