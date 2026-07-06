"""ACL capture: request nTSecurityDescriptor with the LDAP_SERVER_SD_FLAGS control, carry the SD
byte-identical, and be honest about the SACL gap.

nTSecurityDescriptor holds the owner/group/DACL — the ACEs BloodHound-style tooling walks to find
privilege-escalation paths. AD does not return it for a bare ``*`` (it must be named and scoped by
the SD_FLAGS control), so these tests cover both halves: capture actively requests it, and the
facade withholds it from ``*`` the way a real DC does.
"""

import asyncio
import base64
import socket

from helpers import make_ctx
from pyasn1.codec.ber import decoder, encoder
from pyasn1_modules import rfc2251 as L

from rangefinder.capture import capture_ldap
from rangefinder.capture.ldap import (
    _SD_FLAGS_OID,
    _Counter,
    _bind,
    _search,
    _sd_flags_control,
    _unbind,
)
from rangefinder.config.services import LdapConfig, LdapEntry
from rangefinder.facades.ldap import LdapFacade, _select_attrs

# A self-relative security descriptor blob with high bytes (genuinely binary, must travel as octets).
_SD = bytes([1, 0, 0x04, 0x80]) + bytes(range(0x60, 0xA0))
_SD_B64 = base64.b64encode(_SD).decode()
# A realistic objectSid (a normal attribute AD *does* return for "*").
_SID = bytes([1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 0xD1, 0x9C, 0x11, 0x8B, 0xF4, 0x01, 0x00, 0x00])
_SID_B64 = base64.b64encode(_SID).decode()

_BASE = "DC=corp,DC=local"


def test_sd_flags_control_encodes_owner_group_dacl():
    oid, criticality, value = _sd_flags_control(0x07)
    assert oid == _SD_FLAGS_OID == "1.2.840.113556.1.4.801"
    # Non-critical: a directory that doesn't implement the control ignores it and the search still
    # runs (returning no SD) rather than failing — that's what keeps capture fail-closed, not broken.
    assert criticality is False
    assert value == bytes.fromhex("3003020107")  # SEQUENCE { INTEGER 7 == OWNER|GROUP|DACL }


class _FakeSock:
    """A socket stub: records everything _search sends, replays a canned searchResDone back.

    Lets us assert the outgoing SEARCH message actually carries the SD_FLAGS control on the wire —
    the round-trip tests can't, because the facade ignores request controls, so a broken
    controls-attach block in _search would still let them pass.
    """

    def __init__(self, response: bytes):
        self.sent = b""
        self._buf = response

    def sendall(self, data: bytes):
        self.sent += data

    def recv(self, n: int) -> bytes:
        chunk, self._buf = self._buf[:n], self._buf[n:]
        return chunk


def _search_done_message(mid: int) -> bytes:
    m = L.LDAPMessage()
    m["messageID"] = mid
    done = L.SearchResultDone()
    done["resultCode"] = "success"
    done["matchedDN"] = ""
    done["errorMessage"] = ""
    m["protocolOp"]["searchResDone"] = done
    return encoder.encode(m)


def test_search_serializes_sd_flags_control_onto_the_wire():
    fake = _FakeSock(_search_done_message(5))
    _search(fake, 5, _BASE, 2, ["*", "nTSecurityDescriptor"], 5000,
            controls=[_sd_flags_control(0x07)])
    sent, _ = decoder.decode(fake.sent, asn1Spec=L.LDAPMessage())
    ctrls = sent["controls"]
    assert str(ctrls[0]["controlType"]) == _SD_FLAGS_OID
    assert bool(ctrls[0]["criticality"]) is False
    assert bytes(ctrls[0]["controlValue"]) == bytes.fromhex("3003020107")
    attrs = [str(a) for a in sent["protocolOp"]["searchRequest"]["attributes"]]
    assert "nTSecurityDescriptor" in attrs  # SD named explicitly (not volunteered by "*")


def test_select_attrs_withholds_sd_from_wildcard():
    attrs = {"objectSid": [_SID_B64], "nTSecurityDescriptor": [_SD_B64]}
    star = _select_attrs(attrs, ["*"])
    assert "objectSid" in star  # a normal attribute is still volunteered for "*"
    assert "nTSecurityDescriptor" not in star  # ...but the SD is not, matching a real DC
    assert "nTSecurityDescriptor" in _select_attrs(attrs, ["nTSecurityDescriptor"])  # named -> returned
    assert "nTSecurityDescriptor" in _select_attrs(attrs, ["*", "ntsecuritydescriptor"])  # case-insensitive


# --------------------------------------------------------------- serve + capture round trip


async def _serve_and_capture(entry, *, scrub=False):
    ctx, _ = make_ctx()
    facade = LdapFacade.from_config(LdapConfig(port=389, base_dn=_BASE, entries=[entry]), ctx)
    facade.bind_host = "127.0.0.1"
    facade.port = 0
    await facade.start()
    try:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None, lambda: capture_ldap("127.0.0.1", facade.bound_port, scrub=scrub))
    finally:
        await facade.stop()


def test_security_descriptor_round_trips_and_reports_provenance():
    entry = LdapEntry(
        dn="CN=svc,DC=corp,DC=local",
        attributes={"cn": ["svc"], "objectClass": ["user"]},
        binary_attributes={"nTSecurityDescriptor": [_SD_B64]},
    )
    service, _, report = asyncio.run(_serve_and_capture(entry))
    e = {x["dn"]: x for x in service["entries"]}["CN=svc,DC=corp,DC=local"]
    assert e["binary_attributes"]["nTSecurityDescriptor"] == [_SD_B64]  # ACL survives byte-identical
    status = {i.field: i.status for i in report.items}
    assert status["security_descriptors"] == "measured"
    # The SACL gap is surfaced, never silently claimed as captured.
    assert status["sacl"] == "unmeasurable"


def test_no_security_descriptor_reports_unmeasurable():
    entry = LdapEntry(dn="CN=plain,DC=corp,DC=local",
                      attributes={"cn": ["plain"], "objectClass": ["user"]})
    service, _, report = asyncio.run(_serve_and_capture(entry))
    items = {i.field: i for i in report.items}
    # No SD readable -> reported as an unmeasured gap (fail-closed), not fabricated as "none exist".
    assert items["security_descriptors"].status == "unmeasurable"
    assert items["security_descriptors"].value == "0"
    assert "sacl" not in items  # no SACL note when there was no SD to begin with


def test_scrub_keeps_security_descriptor():
    # The SD is an identifier, not a secret — --scrub must keep it (it's in the known-binary allow-list).
    entry = LdapEntry(dn="CN=svc,DC=corp,DC=local",
                      attributes={"objectClass": ["user"]},
                      binary_attributes={"nTSecurityDescriptor": [_SD_B64]})
    service, _, _ = asyncio.run(_serve_and_capture(entry, scrub=True))
    e = {x["dn"]: x for x in service["entries"]}["CN=svc,DC=corp,DC=local"]
    assert e["binary_attributes"]["nTSecurityDescriptor"] == [_SD_B64]


# --------------------------------------------------------------- over-the-wire withholding


def _raw_subtree_search(port, attributes):
    sock = socket.create_connection(("127.0.0.1", port), 5)
    try:
        counter = _Counter()
        assert _bind(sock, counter.next(), "", "") == 0  # anonymous bind
        out = _search(sock, counter.next(), _BASE, 2, attributes, 5000)
        _unbind(sock, counter.next())
        return {dn: (text, binary) for dn, text, binary in out}
    finally:
        sock.close()


async def _serve_and_query(entry, attributes):
    ctx, _ = make_ctx()
    facade = LdapFacade.from_config(LdapConfig(port=389, base_dn=_BASE, entries=[entry]), ctx)
    facade.bind_host = "127.0.0.1"
    facade.port = 0
    await facade.start()
    try:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None, lambda: _raw_subtree_search(facade.bound_port, attributes))
    finally:
        await facade.stop()


def test_facade_withholds_sd_from_wildcard_over_the_wire():
    entry = LdapEntry(
        dn="CN=svc,DC=corp,DC=local",
        attributes={"cn": ["svc"], "objectClass": ["user"]},
        binary_attributes={"nTSecurityDescriptor": [_SD_B64], "objectSid": [_SID_B64]},
    )
    dn = "CN=svc,DC=corp,DC=local"

    _, star_binary = asyncio.run(_serve_and_query(entry, ["*"]))[dn]
    assert "objectSid" in star_binary  # normal binary attr volunteered for "*"
    assert "nTSecurityDescriptor" not in star_binary  # SD withheld, as a real DC does

    _, named_binary = asyncio.run(_serve_and_query(entry, ["nTSecurityDescriptor"]))[dn]
    assert named_binary["nTSecurityDescriptor"] == [_SD_B64]  # returned when named
