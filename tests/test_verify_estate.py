"""Estate-level credential-edge verification (verify_estate + credtest).

The anchor test serves a real asyncssh facade with a planted accept_cred and checks that the
validator actually authenticates the right secret and refuses a wrong one — a deterministic
end-to-end without a live estate.
"""

import socket

from rangefinder import credtest
from rangefinder.config.model import RangeConfig
from rangefinder.coherence import iter_credentials, iter_leaks
from rangefinder.verify import _ServedFacade, verify_estate


def _closed_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _cfg(services, identities=None):
    doc = {"name": "range", "network": {"subnet": "10.0.0.0/24"},
           "hosts": [{"id": "box", "hostname": "box", "ip": "10.0.0.10",
                      "os": "generic_linux", "services": services}]}
    if identities is not None:
        doc["identities"] = identities
    return RangeConfig.model_validate(doc)


# --------------------------------------------------------------- validators (fail-closed)

def test_ssh_validator_accepts_right_secret_refuses_wrong():
    with _ServedFacade({"type": "ssh", "port": 22,
                        "accept_creds": {"deploy": "S3cret-Deploy!"}}) as srv:
        assert credtest.validate_credential(
            "ssh", "127.0.0.1", srv.port, "deploy", "S3cret-Deploy!") is True
        assert credtest.validate_credential(
            "ssh", "127.0.0.1", srv.port, "deploy", "wrong-pass") is False


def test_validators_unreachable_return_none():
    port = _closed_port()
    for kind in ("ssh", "ldap", "smb", "http"):
        assert credtest.validate_credential(
            kind, "127.0.0.1", port, "u", "p", timeout=1.0) is None


def test_unknown_kind_is_none():
    assert credtest.validate_credential("telnet", "127.0.0.1", 23, "u", "p") is None


def test_http_validator_baseline_anchored():
    service = {"type": "http", "port": 80, "paths": {
        "/admin": {"auth_realm": "restricted", "auth_users": {"admin": "s3cret-pw"}, "body": "ok"},
        "/": {"body": "public home"},
    }}
    with _ServedFacade(service) as srv:
        h, p = "127.0.0.1", srv.port
        # protected route: right credential authenticates, wrong one is refused
        assert credtest.validate_credential("http", h, p, "admin", "s3cret-pw", path="/admin") is True
        assert credtest.validate_credential("http", h, p, "admin", "nope", path="/admin") is False
        # public route never challenges -> inconclusive, NEVER True (the fail-open we closed)
        assert credtest.validate_credential("http", h, p, "admin", "s3cret-pw", path="/") is None


def test_parse_targets_ipv6_and_ports():
    from rangefinder.cli import _parse_targets

    assert _parse_targets(["box=10.0.0.5:389"]) == {"box": ("10.0.0.5", 389)}
    assert _parse_targets(["box=10.0.0.5"]) == {"box": ("10.0.0.5", None)}
    assert _parse_targets(["box=fe80::1"]) == {"box": ("fe80::1", None)}          # bare IPv6, not mangled
    assert _parse_targets(["box=[2001:db8::5]:636"]) == {"box": ("2001:db8::5", 636)}
    assert _parse_targets(["box=[fe80::1]"]) == {"box": ("fe80::1", None)}


# --------------------------------------------------------------- extraction

def test_iter_credentials_covers_ssh_http_and_domain():
    cfg = _cfg(
        [{"type": "ssh", "port": 22, "accept_creds": {"deploy": "p1"}},
         {"type": "http", "port": 80, "paths": {"/a": {"auth_users": {"web": "p2"}}}},
         {"type": "ldap", "port": 389},
         {"type": "smb", "port": 445}],
        identities={"domain": "corp.local", "netbios": "CORP",
                    "users": [{"sam": "svc", "password": "p3"}], "groups": []},
    )
    claims = list(iter_credentials(cfg))
    kinds = sorted(c["kind"] for c in claims)
    assert kinds == ["http", "ldap", "smb", "ssh"]  # domain pw tested against both ldap and smb
    ldap = next(c for c in claims if c["kind"] == "ldap")
    assert ldap["username"] == "svc@corp.local"      # bind DN derived from sam@domain
    smb = next(c for c in claims if c["kind"] == "smb")
    assert smb["username"] == "svc" and smb["domain"] == "CORP"


def test_disabled_or_empty_credentials_skipped():
    cfg = _cfg(
        [{"type": "ssh", "port": 22, "accept_creds": {"svc": ""}}, {"type": "ldap", "port": 389}],
        identities={"domain": "corp.local",
                    "users": [{"sam": "off", "password": "x", "enabled": False}], "groups": []},
    )
    assert list(iter_credentials(cfg)) == []  # empty pw + disabled account both skipped


# --------------------------------------------------------------- verify_estate

def test_verify_estate_confirms_live_credential():
    cfg = _cfg([{"type": "ssh", "port": 22, "accept_creds": {"deploy": "Live-Pass-1!"}}])
    with _ServedFacade({"type": "ssh", "port": 22,
                        "accept_creds": {"deploy": "Live-Pass-1!"}}) as srv:
        report = verify_estate(cfg, {"box": ("127.0.0.1", srv.port)})
    assert len(report.confirmed) == 1
    assert report.confirmed[0].verdict == "measured-live"
    assert not report.exploitable          # confirmed but not leaked -> not exploitable
    assert report.ok


def test_verify_estate_flags_exploitable_leaked_credential():
    cfg = _cfg([
        {"type": "ssh", "port": 22, "accept_creds": {"deploy": "Leaked-Pass-99"}},
        {"type": "smb", "port": 445,
         "shares": [{"name": "ops", "files": {"notes.txt": "deploy pw Leaked-Pass-99 do not share"}}]},
    ])
    with _ServedFacade({"type": "ssh", "port": 22,
                        "accept_creds": {"deploy": "Leaked-Pass-99"}}) as srv:
        report = verify_estate(cfg, {"box": ("127.0.0.1", srv.port)})
    assert report.exploitable, "a live credential sitting in a readable file must be flagged"
    assert not report.ok       # exploitable path -> not ok (nonzero exit)


def test_verify_estate_refutes_wrong_config_credential():
    # The config claims deploy:StaleGuess, but the live service only accepts a different secret.
    cfg = _cfg([{"type": "ssh", "port": 22, "accept_creds": {"deploy": "StaleGuess1!"}}])
    with _ServedFacade({"type": "ssh", "port": 22,
                        "accept_creds": {"deploy": "Actual-Pass!"}}) as srv:
        report = verify_estate(cfg, {"box": ("127.0.0.1", srv.port)})
    assert len(report.refuted) == 1
    assert report.ok           # a refuted edge is not a finding


def test_verify_estate_untested_without_target():
    cfg = _cfg([{"type": "ssh", "port": 22, "accept_creds": {"deploy": "p"}}])
    report = verify_estate(cfg, {"other": ("127.0.0.1", 22)})  # no target for 'box'
    assert len(report.untested) == 1
    assert report.boundary  # untested is surfaced as a boundary, never scored
