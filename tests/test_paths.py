"""Estate attack-path composition: chain LOOT (read -> recover cred) and ACCESS (cred -> unlock
gated locations) edges into anon-rooted multi-hop paths, honestly (measured gating, never fabricate).
"""

import json

from rangefinder.config.model import RangeConfig
from rangefinder.paths import compose_paths, format_graph


def _cfg(hosts, identities=None):
    doc = {"name": "estate", "network": {"subnet": "10.0.0.0/24"}, "hosts": hosts}
    if identities:
        doc["identities"] = identities
    return RangeConfig.model_validate(doc)


def _smb(host_id, ip, shares):
    return {"id": host_id, "hostname": host_id, "ip": ip,
            "services": [{"type": "smb", "port": 445, "shares": shares}]}


def _reach(graph):
    return {r.secret_id: r for r in graph.reachable}


def test_recovered_from_anonymous_readable_is_zero_hop():
    # An anonymously-readable HTTP body leaks an SSH login -> recovered with no authentication pivot.
    cfg = _cfg([{
        "id": "web", "hostname": "web", "ip": "10.0.0.10", "services": [
            {"type": "http", "port": 80,
             "default_body": "deploy note: ssh root@web with S3cretSSHpass99",
             "paths": {}},
            {"type": "ssh", "port": 22, "accept_creds": {"root": "S3cretSSHpass99"}}]}])
    graph = compose_paths(cfg)
    assert len(graph.reachable) == 1
    r = graph.reachable[0]
    assert r.hops == 0 and "root" in r.usernames  # 0 pivots: grabbed straight from anon text
    assert r.grants == ["ssh@web"]
    assert r.steps[0] == "(anonymous access)"
    assert any("recover" in s for s in r.steps)


def test_ntlm_gated_route_body_is_not_anonymously_reachable():
    # A route gated by NTLM (empty auth_users) whose body leaks a credential must NOT be reachable
    # from an anonymous start — treating it as anon would fabricate a 0-hop path (the review fail-open).
    cfg = _cfg([{
        "id": "web", "hostname": "web", "ip": "10.0.0.10", "services": [
            {"type": "http", "port": 80, "paths": {
                "/portal": {"body": "internal: ssh svc with N0tAnonReadable99", "auth_ntlm": True}}},
            {"type": "ssh", "port": 22, "accept_creds": {"svc": "N0tAnonReadable99"}}]}])
    graph = compose_paths(cfg)
    assert graph.reachable == []                     # gated body isn't an anonymous loot source
    assert any("svc" in u.usernames for u in graph.unreachable)


def test_multi_hop_through_a_gated_share():
    # svca is leaked in an ANON share (1-hop); svcb is leaked only in a restrict_anonymous share on
    # another host. svca is a domain cred that unlocks that share -> svcb is reachable in TWO hops.
    cfg = _cfg(
        hosts=[
            _smb("h1", "10.0.0.10", [
                {"name": "Public", "files": {"note.txt": "the service logs in with PasswordAAA111"}}]),
            _smb("h2", "10.0.0.11", [
                {"name": "Private", "restrict_anonymous": True,
                 "files": {"backup.ini": "cred=PasswordBBB222"}}]),
        ],
        identities={"domain": "corp.local", "users": [
            {"sam": "svca", "password": "PasswordAAA111"},
            {"sam": "svcb", "password": "PasswordBBB222"}]},
    )
    graph = compose_paths(cfg)
    reach = _reach(graph)
    by_user = {tuple(r.usernames): r for r in graph.reachable}
    svca = next(r for names, r in by_user.items() if "svca" in names)
    svcb = next(r for names, r in by_user.items() if "svcb" in names)
    assert svca.hops == 0                    # recovered from an anon share (no pivot)
    assert svcb.hops == 1                     # one pivot: authenticate to h2, then loot svcb
    assert any("authenticate to h2" in s for s in svcb.steps)
    assert "smb@h2" in svca.grants  # a domain cred unlocks the gated share on the other host


def test_gated_leak_without_a_key_is_unreachable():
    # svcb is leaked only behind a restrict_anonymous share and nothing anon-rooted opens that host
    # -> the path fails closed: svcb is declared-but-unreachable, never fabricated as reachable.
    cfg = _cfg(
        hosts=[_smb("h2", "10.0.0.11", [
            {"name": "Private", "restrict_anonymous": True,
             "files": {"backup.ini": "cred=PasswordBBB222"}}])],
        identities={"domain": "corp.local", "users": [{"sam": "svcb", "password": "PasswordBBB222"}]},
    )
    graph = compose_paths(cfg)
    assert graph.reachable == []
    assert len(graph.unreachable) == 1
    assert "svcb" in graph.unreachable[0].usernames
    assert "foothold" in graph.unreachable[0].reason


def test_making_the_share_anonymous_makes_it_reachable():
    # Same estate as above but the share is anon-readable -> svcb becomes a 1-hop find. Confirms the
    # gating (not the leak) is what gates reachability — the fidelity point of PR #23.
    cfg = _cfg(
        hosts=[_smb("h2", "10.0.0.11", [
            {"name": "Private", "restrict_anonymous": False,
             "files": {"backup.ini": "cred=PasswordBBB222"}}])],
        identities={"domain": "corp.local", "users": [{"sam": "svcb", "password": "PasswordBBB222"}]},
    )
    graph = compose_paths(cfg)
    assert len(graph.reachable) == 1 and graph.reachable[0].hops == 0


def test_shared_password_names_the_correct_account_per_pivot():
    # svca (identity, SMB) and root (ssh) share a password -> one principal, two usernames. A gated
    # SMB share on h2 is unlocked via svca's SMB grant, so the auth step must name svca, not root.
    cfg = _cfg(
        hosts=[
            _smb("h1", "10.0.0.10", [
                {"name": "Public", "files": {"n.txt": "the pw is SharedPassXYZ99 fyi"}}]),
            {"id": "h2", "hostname": "h2", "ip": "10.0.0.11", "services": [
                {"type": "smb", "port": 445, "shares": [
                    {"name": "Private", "restrict_anonymous": True,
                     "files": {"c.ini": "next=SecondPass888aa"}}]},
                {"type": "ssh", "port": 22, "accept_creds": {"root": "SharedPassXYZ99"}}]},
        ],
        identities={"domain": "corp.local", "users": [
            {"sam": "svca", "password": "SharedPassXYZ99"},
            {"sam": "svcb", "password": "SecondPass888aa"}]},
    )
    graph = compose_paths(cfg)
    svcb = next(r for r in graph.reachable if "svcb" in r.usernames)
    auth = [s for s in svcb.steps if s.startswith("authenticate to h2")]
    assert auth and "as svca" in auth[0]      # the SMB account, not the shared-password ssh 'root'
    assert "as root" not in auth[0]


def test_short_secret_is_not_looted():
    # A sub-threshold password appearing in text must not seed a path (conservative leak match).
    cfg = _cfg(
        hosts=[_smb("h1", "10.0.0.10", [
            {"name": "Public", "files": {"n.txt": "password is abc"}}])],
        identities={"domain": "corp.local", "users": [{"sam": "svca", "password": "abc"}]},
    )
    graph = compose_paths(cfg)
    assert graph.reachable == []


def test_output_never_contains_raw_secrets():
    cfg = _cfg(
        hosts=[_smb("h1", "10.0.0.10", [
            {"name": "Public", "files": {"n.txt": "login PasswordAAA111 here"}}])],
        identities={"domain": "corp.local", "users": [{"sam": "svca", "password": "PasswordAAA111"}]},
    )
    graph = compose_paths(cfg)
    blob = format_graph(graph) + json.dumps(_as_json(graph))
    assert "PasswordAAA111" not in blob
    assert any(r.secret_id.startswith("secret#") for r in graph.reachable)


def test_composition_is_deterministic():
    cfg = _cfg(
        hosts=[_smb("h1", "10.0.0.10", [
            {"name": "Public", "files": {"a.txt": "PasswordAAA111", "b.txt": "PasswordAAA111"}}])],
        identities={"domain": "corp.local", "users": [{"sam": "svca", "password": "PasswordAAA111"}]},
    )
    a = [s for r in compose_paths(cfg).reachable for s in r.steps]
    b = [s for r in compose_paths(cfg).reachable for s in r.steps]
    assert a == b


def _as_json(graph):
    import dataclasses
    return dataclasses.asdict(graph)
