"""Cross-service coherence checking (rangefinder.coherence).

The check is advisory and observe-only: it surfaces reuse / leak / role-gap findings but never
fabricates a contradiction (a username is not a principal) and never asserts a leak from a short
coincidental substring.
"""

from rangefinder.coherence import check_coherence, format_report
from rangefinder.config.model import RangeConfig


def build(hosts, identities=None):
    cfg = {"name": "range", "network": {"subnet": "10.0.0.0/24"}, "hosts": hosts}
    if identities is not None:
        cfg["identities"] = identities
    return RangeConfig.model_validate(cfg)


def host(host_id, ip, *services):
    return {"id": host_id, "hostname": host_id, "ip": ip, "services": list(services)}


def ssh(port=22, **creds):
    return {"type": "ssh", "port": port, "accept_creds": dict(creds)}


# --------------------------------------------------------------- clean baseline

def test_clean_config_has_no_issues():
    cfg = build([host("web", "10.0.0.10", {"type": "http", "port": 80})])
    report = check_coherence(cfg)
    assert not report.has_findings
    assert "no cross-service issues" in format_report(report)


# --------------------------------------------------------------- no false contradictions

def test_same_local_username_different_passwords_is_not_a_contradiction():
    # Two hosts each with a local `root` at different passwords — normal on a real estate.
    cfg = build([
        host("a", "10.0.0.10", ssh(root="boxA-pw")),
        host("b", "10.0.0.11", ssh(root="boxB-pw")),
    ])
    report = check_coherence(cfg)
    # No identities, so nothing to reconcile and definitely no hard failure.
    assert not report.edges
    # Two distinct owners? No — both are `root`; owner is the username, so no reuse edge either.
    assert not any(e.kind == "credential-reuse" for e in report.edges)


def test_local_account_matching_domain_name_is_not_a_contradiction():
    # A local `administrator` login with a different password than the domain administrator.
    cfg = build(
        [host("box", "10.0.0.10", ssh(administrator="local-pw"))],
        identities={"domain": "corp.local",
                    "users": [{"sam": "administrator", "password": "domain-pw"}],
                    "groups": []},
    )
    report = check_coherence(cfg)
    # It is surfaced (backing warning) but never a fatal contradiction.
    assert isinstance(report.warnings, list)
    assert not any("different password" in w for w in report.warnings)


def test_empty_password_sentinel_not_treated_as_credential():
    cfg = build(
        [host("box", "10.0.0.10", ssh(svc=""))],  # reject-all / capture-only
        identities={"domain": "corp.local",
                    "users": [{"sam": "svc", "password": "REAL"}], "groups": []},
    )
    report = check_coherence(cfg)
    assert not report.edges  # the empty value never enters the secret graph


# --------------------------------------------------------------- login backing

def test_unbacked_login_flagged_once():
    cfg = build(
        [host("box", "10.0.0.10", ssh(root="pw"), {"type": "ldap", "port": 389})],
        identities={"domain": "corp.local", "users": [{"sam": "alice"}], "groups": []},
    )
    report = check_coherence(cfg)
    backing = [w for w in report.warnings if "no backing directory identity" in w]
    assert len(backing) == 1


# --------------------------------------------------------------- reuse (distinct owners)

def test_reuse_needs_two_distinct_owners():
    # admin and svc sharing one password = genuine reuse across accounts.
    cfg = build([host("box", "10.0.0.10", ssh(admin="Sh4red-Pass!", svc="Sh4red-Pass!"))])
    report = check_coherence(cfg)
    reuse = [e for e in report.edges if e.kind == "credential-reuse"]
    assert len(reuse) == 1


def test_account_backed_by_own_identity_is_not_reuse():
    # svc login backed by the svc directory entry with the same password — coherent, not reuse.
    cfg = build(
        [host("box", "10.0.0.10", ssh(svc="OwnPass1!"), {"type": "ldap", "port": 389})],
        identities={"domain": "corp.local",
                    "users": [{"sam": "svc", "password": "OwnPass1!"}], "groups": []},
    )
    report = check_coherence(cfg)
    assert not any(e.kind == "credential-reuse" for e in report.edges)


def test_default_krbtgt_placeholder_is_not_reuse():
    cfg = build([
        host("dc1", "10.0.0.10", {"type": "kerberos", "port": 88}),
        host("dc2", "10.0.0.11", {"type": "kerberos", "port": 88}),
    ])
    report = check_coherence(cfg)
    assert not any(e.kind == "credential-reuse" for e in report.edges)


# --------------------------------------------------------------- leaks (conservative)

def test_short_common_password_does_not_fabricate_a_leak():
    # "admin" (len 5) coincidentally in benign text must NOT produce an exploitable-leak.
    cfg = build([host(
        "box", "10.0.0.10",
        ssh(admin="admin"),
        {"type": "smb", "port": 445,
         "shares": [{"name": "s", "files": {"welcome.txt": "welcome to the admin portal"}}]},
    )])
    report = check_coherence(cfg)
    assert not any(e.kind == "exploitable-leak" for e in report.edges)


def test_substring_within_a_longer_token_is_not_a_leak():
    # "Backup#2024" as a substring of "MyBackup#2024x" is not a whole-token match.
    cfg = build([host(
        "box", "10.0.0.10",
        ssh(svc="Backup#2024"),
        {"type": "smb", "port": 445,
         "shares": [{"name": "s", "files": {"f.txt": "id=MyBackup#2024xyz"}}]},
    )])
    report = check_coherence(cfg)
    assert not any(e.kind == "exploitable-leak" for e in report.edges)


def test_leaked_live_credential_in_smb_file():
    cfg = build([host(
        "box", "10.0.0.10",
        ssh(admin="Hunter2-Strong!"),
        {"type": "smb", "port": 445,
         "shares": [{"name": "data", "files": {"notes.txt": "admin pw is Hunter2-Strong! keep safe"}}]},
    )])
    report = check_coherence(cfg)
    leaks = [e for e in report.edges if e.kind == "exploitable-leak"]
    assert len(leaks) == 1
    assert any("data/notes.txt" in loc for loc in leaks[0].locations)


def test_leaked_credential_in_smb_share_comment():
    cfg = build([host(
        "box", "10.0.0.10",
        ssh(svc="Backup#2024Key"),
        {"type": "smb", "port": 445,
         "shares": [{"name": "bk", "comment": "backup acct pw Backup#2024Key"}]},
    )])
    report = check_coherence(cfg)
    assert any(e.kind == "exploitable-leak" for e in report.edges)


def test_leaked_credential_in_http_body():
    cfg = build([host(
        "web", "10.0.0.10",
        ssh(admin="Hunter2-Strong!"),
        {"type": "http", "port": 80,
         "paths": {"/": {"body": "<!-- admin pw is Hunter2-Strong! -->"}}},
    )])
    report = check_coherence(cfg)
    assert any(e.kind == "exploitable-leak" for e in report.edges)


def test_leaked_credential_in_group_description():
    cfg = build(
        [host("dc", "10.0.0.10", ssh(svc="Backup#2024Key"), {"type": "ldap", "port": 389})],
        identities={"domain": "corp.local",
                    "users": [{"sam": "svc", "password": "Backup#2024Key"}],
                    "groups": [{"name": "Backups", "description": "svc pw Backup#2024Key"}]},
    )
    report = check_coherence(cfg)
    assert any(e.kind == "exploitable-leak" for e in report.edges)


def test_secret_never_appears_in_report_text():
    secret = "SuperSecretValue123"
    cfg = build([host("box", "10.0.0.10", ssh(admin=secret, svc=secret))])
    report = check_coherence(cfg)
    assert secret not in format_report(report)  # only the secret# token is shown


# --------------------------------------------------------------- role completeness

def test_identities_without_ldap_facade_warns():
    cfg = build(
        [host("box", "10.0.0.10", {"type": "http", "port": 80})],
        identities={"domain": "corp.local", "users": [{"sam": "alice"}], "groups": []},
    )
    report = check_coherence(cfg)
    assert any("no ldap facade" in w for w in report.warnings)


def test_roastable_without_kerberos_facade_warns():
    cfg = build(
        [host("dc", "10.0.0.10", {"type": "ldap", "port": 389})],
        identities={"domain": "corp.local",
                    "users": [{"sam": "svc", "spn": "HTTP/dc", "no_preauth": True}], "groups": []},
    )
    report = check_coherence(cfg)
    assert any("kerberos facade" in w for w in report.warnings)
