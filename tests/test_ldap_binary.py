"""Binary LDAP attribute fidelity (objectSid/GUID/cert): captured base64, served as raw octets.

The round-trip test serves a facade carrying a binary attribute, captures it back over the wire,
and asserts the bytes survive byte-identical — the drop that used to lose SID/GUID identifiers.
"""

import asyncio
import base64

from helpers import make_ctx

from rangefinder.capture import capture_ldap
from rangefinder.capture.ldap import _decode_text
from rangefinder.config.model import RangeConfig
from rangefinder.config.services import LdapConfig, LdapEntry
from rangefinder.facades.ldap import LdapFacade, _entry_from_config

# A realistic objectSid: contains bytes >= 0x80 (the RID / sub-authorities), so it is genuinely
# non-UTF-8 and must travel as binary, not text.
_SID = bytes([1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 0xD1, 0x9C, 0x11, 0x8B, 0xF4, 0x01, 0x00, 0x00])
_SID_B64 = base64.b64encode(_SID).decode()


def test_decode_text_rejects_binary():
    assert _decode_text([b"svc-account"]) == ["svc-account"]
    assert _decode_text([_SID]) is None                 # any non-UTF-8 value -> whole attr is binary
    assert _decode_text([b"ok", _SID]) is None          # mixed -> binary (single-syntax)


def test_entry_from_config_decodes_base64_to_bytes():
    e = LdapEntry(dn="CN=x", attributes={"cn": ["x"]}, binary_attributes={"objectSid": [_SID_B64]})
    entry = _entry_from_config(e)
    assert entry.attrs["cn"] == ["x"]
    assert entry.bin_attrs["objectSid"] == [_SID]       # raw bytes, ready to emit as octets


def test_config_with_binary_attributes_validates():
    RangeConfig.model_validate({
        "name": "r", "network": {"subnet": "10.0.0.0/24"},
        "hosts": [{"id": "dc", "hostname": "dc", "ip": "10.0.0.10", "services": [
            {"type": "ldap", "port": 389, "entries": [
                {"dn": "CN=svc,DC=corp,DC=local",
                 "attributes": {"cn": ["svc"]},
                 "binary_attributes": {"objectSid": [_SID_B64]}}]}]}],
    })


async def _serve_and_capture(entry, *, scrub=False):
    ctx, _ = make_ctx()
    facade = LdapFacade.from_config(
        LdapConfig(port=389, base_dn="DC=corp,DC=local", entries=[entry]), ctx)
    facade.bind_host = "127.0.0.1"
    facade.port = 0
    await facade.start()
    try:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None, lambda: capture_ldap("127.0.0.1", facade.bound_port, scrub=scrub))
    finally:
        await facade.stop()


def test_binary_attribute_round_trips_byte_identical():
    entry = LdapEntry(
        dn="CN=svc,DC=corp,DC=local",
        attributes={"cn": ["svc"], "objectClass": ["user"]},
        binary_attributes={"objectSid": [_SID_B64]},
    )
    service, warnings, report = asyncio.run(_serve_and_capture(entry))

    captured = {e["dn"]: e for e in service["entries"]}
    e = captured["CN=svc,DC=corp,DC=local"]
    assert e["attributes"]["cn"] == ["svc"]                       # text survives
    assert e["binary_attributes"]["objectSid"] == [_SID_B64]      # SID survives, byte-identical
    # provenance surfaces the binary capture as measured
    status = {i.field: i.status for i in report.items}
    assert status.get("binary_attributes") == "measured"


def test_non_ascii_text_survives_utf8_not_latin1():
    # Accented + CJK text: previously served as latin-1 (mojibake) or crashed on CJK. Must survive
    # as UTF-8 text, staying in attributes (not misclassified as binary).
    entry = LdapEntry(
        dn="CN=jose,DC=corp,DC=local",
        attributes={"cn": ["José García"], "displayName": ["日本語ユーザー"],
                    "objectClass": ["user"]},
    )
    service, _, _ = asyncio.run(_serve_and_capture(entry))
    e = {x["dn"]: x for x in service["entries"]}["CN=jose,DC=corp,DC=local"]
    assert e["attributes"]["cn"] == ["José García"]
    assert e["attributes"]["displayName"] == ["日本語ユーザー"]
    assert "binary_attributes" not in e or "cn" not in e["binary_attributes"]


def test_objectsid_routed_binary_even_when_utf8_valid():
    # An objectSid whose bytes happen to all be valid UTF-8 must still be carried as binary (by
    # name), not routed to the text path where scrubbing could corrupt it.
    ascii_sid = base64.b64encode(b"ABCDEFGH").decode()
    entry = LdapEntry(dn="CN=a,DC=corp,DC=local",
                      attributes={"objectClass": ["user"]},
                      binary_attributes={"objectSid": [ascii_sid]})
    service, _, _ = asyncio.run(_serve_and_capture(entry))
    e = {x["dn"]: x for x in service["entries"]}["CN=a,DC=corp,DC=local"]
    assert e["binary_attributes"]["objectSid"] == [ascii_sid]
    assert "objectSid" not in e.get("attributes", {})


def test_scrub_keeps_known_binary_drops_unknown():
    entry = LdapEntry(
        dn="CN=svc,DC=corp,DC=local",
        attributes={"objectClass": ["user"]},
        binary_attributes={"objectSid": [_SID_B64],
                           "customBlob": [base64.b64encode(bytes([0x80, 0xFF, 0x00])).decode()]},
    )
    service, _, _ = asyncio.run(_serve_and_capture(entry, scrub=True))
    e = {x["dn"]: x for x in service["entries"]}["CN=svc,DC=corp,DC=local"]
    binattrs = e.get("binary_attributes", {})
    assert "objectSid" in binattrs               # known identifier kept
    assert "customBlob" not in binattrs          # unknown binary dropped fail-closed under --scrub
