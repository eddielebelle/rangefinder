"""Unified attack graph: extend reachable credentials through captured ACL control edges.

Confirms escalate_via_acls chains a credential path into identity-plane privilege escalation —
control a looted principal, act with its group memberships, follow GenericAll/DCSync ACL edges —
while staying fail-closed: an ACL edge whose trustee is NOT reachable never fires.
"""

import base64
import uuid

from impacket.ldap.ldaptypes import (
    ACCESS_ALLOWED_ACE, ACCESS_ALLOWED_OBJECT_ACE, ACCESS_MASK, ACL, ACE,
    LDAP_SID, SR_SECURITY_DESCRIPTOR)

from rangefinder.config.model import RangeConfig
from rangefinder.paths import compose_paths, escalate_via_acls

_GENERIC_ALL = 0x10000000
_GC = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
_GC_ALL = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
_BASE = "DC=corp,DC=local"


def _sid(c):
    s = LDAP_SID()
    s.fromCanonical(c)
    return s


def _sidb(c):
    return base64.b64encode(_sid(c).getData()).decode()


def _allow(mask, trustee):
    inner = ACCESS_ALLOWED_ACE()
    inner["Mask"] = ACCESS_MASK()
    inner["Mask"]["Mask"] = mask
    inner["Sid"] = _sid(trustee)
    ace = ACE()
    ace["AceType"] = 0
    ace["AceFlags"] = 0
    ace["Ace"] = inner
    return ace


def _obj(mask, trustee, guid):
    inner = ACCESS_ALLOWED_OBJECT_ACE()
    inner["Mask"] = ACCESS_MASK()
    inner["Mask"]["Mask"] = mask
    inner["Flags"] = 1
    inner["ObjectType"] = uuid.UUID(guid).bytes_le
    inner["InheritedObjectType"] = b""
    inner["Sid"] = _sid(trustee)
    ace = ACE()
    ace["AceType"] = 5
    ace["AceFlags"] = 0
    ace["Ace"] = inner
    return ace


def _sdb(aces, owner="S-1-5-21-1-2-3-512"):
    sd = SR_SECURITY_DESCRIPTOR()
    sd["Revision"] = b"\x01"
    sd["Sbz1"] = b"\x00"
    sd["Control"] = 0x8004
    sd["OwnerSid"] = _sid(owner)
    sd["GroupSid"] = b""
    sd["Sacl"] = b""
    dacl = ACL()
    dacl["AclRevision"] = 4
    dacl["Sbz1"] = 0
    dacl["Sbz2"] = 0
    dacl.aces = aces
    sd["Dacl"] = dacl
    return base64.b64encode(sd.getData()).decode()


def _ldap_entry(dn, sam, *, sid, member_of=None, sd_aces=None):
    attrs = {"sAMAccountName": [sam]}
    if member_of:
        attrs["memberOf"] = member_of
    binary = {"objectSid": [_sidb(sid)]}
    if sd_aces is not None:
        binary["nTSecurityDescriptor"] = [_sdb(sd_aces)]
    return {"dn": dn, "attributes": attrs, "binary_attributes": binary}


def _cfg(*, leak="LeakedPass12345", ldap_entries, users=None):
    return RangeConfig.model_validate({
        "name": "e", "network": {"subnet": "10.0.0.0/24"},
        "identities": {"domain": "corp.local",
                       "users": users or [{"sam": "svca", "password": leak}]},
        "hosts": [{"id": "dc", "hostname": "dc", "ip": "10.0.0.10", "services": [
            {"type": "smb", "port": 445, "shares": [
                {"name": "Public", "files": {"n.txt": f"password {leak} here"}}]},
            {"type": "ldap", "port": 389, "base_dn": _BASE, "entries": ldap_entries}]}]})


def _full_chain_cfg():
    return _cfg(ldap_entries=[
        _ldap_entry(f"CN=svca,{_BASE}", "svca", sid="S-1-5-21-1-2-3-1105",
                    member_of=[f"CN=Helpdesk,{_BASE}"]),
        _ldap_entry(f"CN=Helpdesk,{_BASE}", "Helpdesk", sid="S-1-5-21-1-2-3-1200"),
        _ldap_entry(f"CN=bob,{_BASE}", "bob", sid="S-1-5-21-1-2-3-1300",
                    sd_aces=[_allow(_GENERIC_ALL, "S-1-5-21-1-2-3-1200")]),          # Helpdesk -> GenericAll -> bob
        _ldap_entry(_BASE, "CORP", sid="S-1-5-21-1-2-3-1000",
                    sd_aces=[_obj(0x100, "S-1-5-21-1-2-3-1300", _GC),
                             _obj(0x100, "S-1-5-21-1-2-3-1300", _GC_ALL)]),          # bob -> DCSync -> domain
    ])


def test_credential_path_chains_into_acl_escalation_and_dcsync():
    cfg = _full_chain_cfg()
    graph = compose_paths(cfg)
    escalate_via_acls(graph, cfg)
    targets = {(e.target, e.right) for e in graph.escalations}
    assert ("bob", "GenericAll") in targets                       # reachable svca -> Helpdesk -> bob
    assert any(e.domain_compromise for e in graph.escalations)    # bob -> DCSync -> full compromise
    dc = next(e for e in graph.escalations if e.domain_compromise)
    assert any("helpdesk" in s.lower() for s in dc.steps)         # the chain runs through the group


def test_acl_edge_from_unreachable_principal_does_not_fire():
    # bob is NOT reachable (no leaked cred, not a member reachable via anyone), so his GenericAll
    # over the domain must NOT produce an escalation — fail-closed on an unreachable trustee.
    cfg = _cfg(ldap_entries=[
        _ldap_entry(f"CN=svca,{_BASE}", "svca", sid="S-1-5-21-1-2-3-1105"),         # reachable, no groups
        _ldap_entry(f"CN=bob,{_BASE}", "bob", sid="S-1-5-21-1-2-3-1300"),
        _ldap_entry(_BASE, "CORP", sid="S-1-5-21-1-2-3-1000",
                    sd_aces=[_allow(_GENERIC_ALL, "S-1-5-21-1-2-3-1300")]),          # bob -> GenericAll -> domain
    ])
    graph = compose_paths(cfg)
    escalate_via_acls(graph, cfg)
    assert graph.escalations == []          # svca can't reach bob, so bob's control never applies


def test_no_reachable_credential_means_no_escalation():
    # An ACL edge with no anonymously-reachable seed produces nothing (seeds gate the whole graph).
    cfg = _cfg(leak="unleaked", users=[{"sam": "svca", "password": "differentsecret999"}],
               ldap_entries=[
                   _ldap_entry(f"CN=svca,{_BASE}", "svca", sid="S-1-5-21-1-2-3-1105",
                               member_of=[f"CN=Helpdesk,{_BASE}"]),
                   _ldap_entry(f"CN=Helpdesk,{_BASE}", "Helpdesk", sid="S-1-5-21-1-2-3-1200"),
                   _ldap_entry(f"CN=bob,{_BASE}", "bob", sid="S-1-5-21-1-2-3-1300",
                               sd_aces=[_allow(_GENERIC_ALL, "S-1-5-21-1-2-3-1200")])])
    graph = compose_paths(cfg)  # svca's password ("differentsecret999") is not in the leak text
    assert graph.reachable == []
    assert escalate_via_acls(graph, cfg) == []


def test_degenerate_principal_name_does_not_fabricate_control():
    # A reachable account with a UPN that normalises to "" ("@corp.local") must NOT match an
    # empty-labelled trustee (blank sAMAccountName) and fabricate control (review fail-closed guard).
    cfg = RangeConfig.model_validate({
        "name": "e", "network": {"subnet": "10.0.0.0/24"},
        "identities": {"domain": "corp.local",
                       "users": [{"sam": "svc", "upn": "@corp.local", "password": "LeakedPass12345"}]},
        "hosts": [{"id": "dc", "hostname": "dc", "ip": "10.0.0.10", "services": [
            {"type": "smb", "port": 445, "shares": [
                {"name": "Public", "files": {"n.txt": "password LeakedPass12345 here"}}]},
            {"type": "ldap", "port": 389, "base_dn": _BASE, "entries": [
                _ldap_entry(f"CN=svc,{_BASE}", "svc", sid="S-1-5-21-1-2-3-1105"),
                {"dn": f"CN=blank,{_BASE}", "attributes": {"sAMAccountName": [""]},  # empty label
                 "binary_attributes": {"objectSid": [_sidb("S-1-5-21-1-2-3-1200")]}},
                _ldap_entry(f"CN=victim,{_BASE}", "victim", sid="S-1-5-21-1-2-3-1300",
                            sd_aces=[_allow(_GENERIC_ALL, "S-1-5-21-1-2-3-1200")])]}]}]})
    graph = compose_paths(cfg)
    assert graph.reachable  # svc is reachable
    escalate_via_acls(graph, cfg)
    assert "victim" not in {e.target for e in graph.escalations}  # empty-name match blocked
