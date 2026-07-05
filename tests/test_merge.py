"""Merging single-service captures into one estate twin (rangefinder.orchestrate.merge)."""

import pytest

from rangefinder.config.model import RangeConfig
from rangefinder.orchestrate.merge import merge_configs


def cfg(name, host_id, ip, service, *, subnet="10.0.0.0/24", hostname=None, **extra):
    """A single-host / single-service config the way `capture` emits one."""
    return {
        "name": name,
        "schema_version": 3,
        "network": {"subnet": subnet},
        "hosts": [{"id": host_id, "hostname": hostname or host_id,
                   "ip": ip, "os": "generic_linux", "services": [service]}],
        **extra,
    }


def svc(type_, port, **kw):
    return {"type": type_, "port": port, **kw}


def _validate(merged):
    """Every merge result must be a real, loadable RangeConfig."""
    return RangeConfig.model_validate(merged)


# --------------------------------------------------------------- same-host union

def test_same_id_unions_services():
    a = cfg("web", "web01", "10.0.0.5", svc("http", 80))
    b = cfg("web", "web01", "10.0.0.5", svc("ssh", 22))
    merged, warnings = merge_configs([a, b])

    _validate(merged)
    assert len(merged["hosts"]) == 1
    host = merged["hosts"][0]
    assert host["id"] == "web01"
    assert {s["port"] for s in host["services"]} == {80, 22}
    assert host["ip"] == "10.0.0.5"  # unique real IP is pinned


def test_same_id_identical_service_deduped():
    a = cfg("web", "web01", "10.0.0.5", svc("http", 80))
    b = cfg("web", "web01", "10.0.0.5", svc("http", 80))
    merged, warnings = merge_configs([a, b])

    host = merged["hosts"][0]
    assert len(host["services"]) == 1
    assert any("captured twice" in w for w in warnings)


def test_same_id_port_conflict_fails_closed():
    a = cfg("web", "web01", "10.0.0.5", svc("http", 80))
    b = cfg("web", "web01", "10.0.0.5", svc("banner", 80, protocol="redis"))
    with pytest.raises(ValueError, match=r"different services on port 80 \(http vs banner\)"):
        merge_configs([a, b])


def test_same_type_posture_drift_gets_clear_message():
    a = cfg("fs", "fs01", "10.0.0.5", svc("smb", 445, signing_required=True))
    b = cfg("fs", "fs01", "10.0.0.5", svc("smb", 445, signing_required=False))
    with pytest.raises(ValueError, match="posture drift"):
        merge_configs([a, b])


def test_measured_ip_beats_placeholder_on_union():
    a = cfg("dc", "dc01", "10.99.0.10", svc("ssh", 22))       # hostname capture -> placeholder
    b = cfg("dc", "dc01", "192.168.1.5", svc("ldap", 389))    # measured real address
    merged, warnings = merge_configs([a, b], subnet="192.168.1.0/24")
    assert merged["hosts"][0]["ip"] == "192.168.1.5"
    assert any("adopted measured ip" in w for w in warnings)


def test_specific_os_beats_generic_on_union():
    a = cfg("dc", "dc01", "10.0.0.5", svc("ldap", 389))
    a["hosts"][0]["os"] = "generic_linux"
    b = cfg("dc", "dc01", "10.0.0.5", svc("smb", 445))
    b["hosts"][0]["os"] = "windows_server_2019"
    merged, _ = merge_configs([a, b])
    assert merged["hosts"][0]["os"] == "windows_server_2019"


# --------------------------------------------------------------- distinct hosts

def test_distinct_real_ips_kept_and_subnet_covers_both():
    a = cfg("a", "hosta", "10.13.37.10", svc("http", 80), subnet="10.13.37.0/24")
    b = cfg("b", "hostb", "10.13.37.20", svc("ssh", 22), subnet="10.13.37.0/24")
    merged, warnings = merge_configs([a, b])

    cfg_model = _validate(merged)
    ips = {h.id: str(h.ip) for h in cfg_model.hosts}
    assert ips == {"hosta": "10.13.37.10", "hostb": "10.13.37.20"}
    assert str(cfg_model.network.subnet) == "10.13.37.0/24"
    assert not warnings  # nothing had to be reassigned


def test_placeholder_ip_collision_reallocated():
    # Two hostname captures both land on the 10.99.0.10 sentinel with distinct ids.
    a = cfg("a", "hosta", "10.99.0.10", svc("http", 80), subnet="10.99.0.0/24")
    b = cfg("b", "hostb", "10.99.0.10", svc("ssh", 22), subnet="10.99.0.0/24")
    merged, warnings = merge_configs([a, b])

    cfg_model = _validate(merged)  # would raise on duplicate IPs
    ips = {str(h.ip) for h in cfg_model.hosts}
    assert len(ips) == 2  # no longer collide
    assert all(ip.startswith("10.99.0.") for ip in ips)
    assert any("reassigned ip" in w for w in warnings)


def test_subnet_too_small_fails_closed():
    a = cfg("a", "hosta", "10.99.0.10", svc("http", 80))
    b = cfg("b", "hostb", "10.99.0.10", svc("ssh", 22))
    with pytest.raises(ValueError, match="too small"):
        merge_configs([a, b], subnet="10.99.0.0/32")


def test_tight_subnet_allocates_below_dot_ten():
    # A /29 has only offsets .1-.6, all below the .10 convention; allocation must fall back to them.
    a = cfg("a", "hosta", "10.99.0.10", svc("http", 80))
    b = cfg("b", "hostb", "10.99.0.10", svc("ssh", 22))
    merged, _ = merge_configs([a, b], subnet="10.0.0.0/29")
    cfg_model = _validate(merged)
    assert len({str(h.ip) for h in cfg_model.hosts}) == 2


def test_colliding_hostnames_disambiguated():
    # Distinct hosts that happen to share a hostname must not crash the merge (they used to fail
    # RangeConfig's duplicate-hostname check); the later one is renamed and surfaced.
    a = cfg("a", "hosta", "10.0.0.5", svc("http", 80), hostname="fileserver")
    b = cfg("b", "hostb", "10.0.0.6", svc("ssh", 22), hostname="fileserver")
    merged, warnings = merge_configs([a, b])
    names = {h.hostname for h in _validate(merged).hosts}
    assert names == {"fileserver", "fileserver-2"}
    assert any("renamed" in w for w in warnings)


# --------------------------------------------------------------- overrides / metadata

def test_name_and_subnet_overrides():
    a = cfg("a", "hosta", "10.99.0.10", svc("http", 80))
    b = cfg("b", "hostb", "10.99.0.10", svc("ssh", 22))
    merged, _ = merge_configs([a, b], name="estate", subnet="192.168.50.0/24")
    assert merged["name"] == "estate"
    assert merged["network"]["subnet"] == "192.168.50.0/24"
    assert all(str(h.ip).startswith("192.168.50.") for h in _validate(merged).hosts)


def test_schema_version_takes_max():
    a = cfg("a", "hosta", "10.0.0.5", svc("http", 80))
    b = cfg("b", "hostb", "10.0.0.6", svc("ssh", 22))
    a["schema_version"] = 2
    b["schema_version"] = 3
    merged, _ = merge_configs([a, b])
    assert merged["schema_version"] == 3


def test_identical_objectives_deduped_silently():
    obj = {"id": "leak", "title": "t", "description": "d"}
    a = cfg("a", "hosta", "10.0.0.5", svc("http", 80), objectives=[obj])
    b = cfg("b", "hostb", "10.0.0.6", svc("ssh", 22), objectives=[obj])
    merged, warnings = merge_configs([a, b])
    assert len(merged["objectives"]) == 1
    assert not any("redefined" in w for w in warnings)  # identical dup is harmless, no noise


def test_conflicting_objective_ids_warn():
    a = cfg("a", "hosta", "10.0.0.5", svc("http", 80),
            objectives=[{"id": "leak", "title": "one", "description": "d"}])
    b = cfg("b", "hostb", "10.0.0.6", svc("ssh", 22),
            objectives=[{"id": "leak", "title": "TWO", "description": "d"}])
    merged, warnings = merge_configs([a, b])
    assert len(merged["objectives"]) == 1
    assert merged["objectives"][0]["title"] == "one"  # first wins
    assert any("redefined with different content" in w for w in warnings)


def test_identities_same_domain_merged():
    a = cfg("a", "dc01", "10.0.0.5", svc("ldap", 389),
            identities={"domain": "corp.local",
                        "users": [{"sam": "alice"}], "groups": []})
    b = cfg("b", "dc02", "10.0.0.6", svc("ldap", 389),
            identities={"domain": "corp.local",
                        "users": [{"sam": "bob"}], "groups": []})
    merged, _ = merge_configs([a, b])
    sams = {u["sam"] for u in merged["identities"]["users"]}
    assert sams == {"alice", "bob"}


def test_cross_domain_identities_fails_closed():
    # One range twin holds one AD domain; merging two would either drop identity surface (under-
    # report) or serve it under the wrong domain (fabricate). Fail closed instead of either.
    a = cfg("a", "dc01", "10.0.0.5", svc("ldap", 389),
            identities={"domain": "corp.local", "users": [{"sam": "alice"}], "groups": []})
    b = cfg("b", "dc02", "10.0.0.6", svc("ldap", 389),
            identities={"domain": "dev.local", "users": [{"sam": "bob"}], "groups": []})
    with pytest.raises(ValueError, match="single AD domain"):
        merge_configs([a, b])


# --------------------------------------------------------------- composition

def test_remerge_is_idempotent_and_growable():
    a = cfg("a", "hosta", "10.13.37.10", svc("http", 80), subnet="10.13.37.0/24")
    b = cfg("b", "hostb", "10.13.37.20", svc("ssh", 22), subnet="10.13.37.0/24")
    first, _ = merge_configs([a, b])

    c = cfg("c", "hostc", "10.13.37.30", svc("smb", 445), subnet="10.13.37.0/24")
    grown, _ = merge_configs([first, c])

    model = _validate(grown)
    assert {h.id for h in model.hosts} == {"hosta", "hostb", "hostc"}


def test_empty_input_rejected():
    with pytest.raises(ValueError, match="at least one config"):
        merge_configs([])


# --------------------------------------------------------------- capture --append semantics

def test_append_adds_host_within_existing_subnet():
    # How `capture --append` calls merge: existing estate first, fresh single-service capture
    # second, pinned to the estate's own subnet.
    estate = cfg("corp", "dc", "10.20.0.10", svc("ldap", 389), subnet="10.20.0.0/24")
    fresh = cfg("box", "web", "10.99.0.10", svc("http", 80))  # placeholder-IP capture
    merged, _ = merge_configs([estate, fresh], subnet="10.20.0.0/24")

    model = _validate(merged)
    assert merged["name"] == "corp"                       # estate name kept
    assert str(model.network.subnet) == "10.20.0.0/24"    # estate subnet kept
    ids = {h.id: str(h.ip) for h in model.hosts}
    assert ids["dc"] == "10.20.0.10"                       # existing host pinned
    assert ids["web"].startswith("10.20.0.")              # new host allocated into the estate


def test_append_same_host_id_adds_service_to_that_host():
    estate = cfg("corp", "dc", "10.20.0.10", svc("ldap", 389), subnet="10.20.0.0/24")
    fresh = cfg("box", "dc", "10.20.0.10", svc("kerberos", 88), subnet="10.20.0.0/24")
    merged, _ = merge_configs([estate, fresh], subnet="10.20.0.0/24")
    model = _validate(merged)
    assert len(model.hosts) == 1
    assert {s.port for s in model.hosts[0].services} == {389, 88}


def test_grow_capture_report(tmp_path):
    from rangefinder.cli import _grow_capture_report

    estate = tmp_path / "estate.json"
    estate.write_text("{}")
    (tmp_path / "estate.capture-report.md").write_text("## dc ldap\n- measured: anon bind")

    grown = _grow_capture_report(estate, "## web http\n- measured: TRACE", "web (http)")
    assert "measured: anon bind" in grown   # prior provenance preserved
    assert "appended: web (http)" in grown   # new section labelled
    assert "measured: TRACE" in grown


def test_grow_capture_report_without_existing_sidecar(tmp_path):
    from rangefinder.cli import _grow_capture_report

    estate = tmp_path / "estate.json"  # no sibling sidecar
    grown = _grow_capture_report(estate, "## web http\n- measured: TRACE", "web (http)")
    assert "appended: web (http)" in grown
    assert "measured: TRACE" in grown
    assert "provenance not recorded" in grown  # base hosts' provenance flagged as unknown


def test_grow_capture_report_folds_in_coherence(tmp_path):
    from rangefinder.cli import _grow_capture_report

    estate = tmp_path / "estate.json"
    (tmp_path / "estate.capture-report.md").write_text("## dc\n- measured: x")
    grown = _grow_capture_report(estate, "## web\n- measured: y", "web (http)",
                                 "‼ possible-leak [secret#abcd1234]: ...")
    assert "Cross-service coherence" in grown
    assert "possible-leak" in grown


# --------------------------------------------------------------- --append reconciliation

def _estate(host_dict):
    return {"name": "corp", "schema_version": 3, "network": {"subnet": "10.0.0.0/24"},
            "hosts": [host_dict]}


def _new(host_id, ip, service):
    return {"name": "cap", "network": {"subnet": "10.0.0.0/24"},
            "hosts": [{"id": host_id, "hostname": host_id, "ip": ip,
                       "os": "generic_linux", "services": [service]}]}


def test_reconcile_refreshes_same_service():
    from rangefinder.cli import _reconcile_append

    existing = _estate({"id": "web", "hostname": "web", "ip": "10.0.0.10",
                        "os": "generic_linux", "services": [svc("http", 80, server_header="old")]})
    new = _new("web", "10.0.0.10", svc("http", 80, server_header="new"))
    warnings = []
    _reconcile_append(existing, new, "10.99.0.10", warnings)
    assert existing["hosts"][0]["services"] == []          # stale copy dropped
    assert any("refreshed" in w for w in warnings)
    merged, _ = merge_configs([existing, new])
    assert _validate(merged).hosts[0].services[0].server_header == "new"  # newer capture wins


def test_reconcile_unions_host_captured_by_ip():
    from rangefinder.cli import _reconcile_append

    existing = _estate({"id": "dc", "hostname": "dc.corp", "ip": "10.0.0.10",
                        "os": "generic_linux", "services": [svc("ldap", 389)]})
    new = _new("10-0-0-10", "10.0.0.10", svc("ssh", 22))  # captured by address -> IP-derived id
    warnings = []
    _reconcile_append(existing, new, "10.99.0.10", warnings)
    assert new["hosts"][0]["id"] == "dc"                    # adopted the existing host's id
    assert any("unioning onto it" in w for w in warnings)
    model = _validate(merge_configs([existing, new])[0])
    assert len(model.hosts) == 1
    assert {s.port for s in model.hosts[0].services} == {389, 22}


def test_reconcile_leaves_real_conflict_for_merge_to_fail_closed():
    from rangefinder.cli import _reconcile_append

    existing = _estate({"id": "web", "hostname": "web", "ip": "10.0.0.10",
                        "os": "generic_linux", "services": [svc("http", 80)]})
    new = _new("web", "10.0.0.10", svc("banner", 80, protocol="redis"))  # different service, same port
    _reconcile_append(existing, new, "10.99.0.10", [])
    assert existing["hosts"][0]["services"]                 # NOT dropped — it's a genuine conflict
    with pytest.raises(ValueError, match="different services on port 80"):
        merge_configs([existing, new])


# --------------------------------------------------------------- provenance stitching (CLI)

def test_combined_report_notes_missing_sidecar(tmp_path):
    from rangefinder.cli import _combined_capture_report

    captured = tmp_path / "ssh.json"
    captured.write_text("{}")
    (tmp_path / "ssh.capture-report.md").write_text("## ssh\n- measured: kex")
    authored = tmp_path / "hand.json"  # no sidecar beside it
    authored.write_text("{}")

    report = _combined_capture_report([captured, authored])
    assert "measured: kex" in report            # the captured source's tiering is carried
    assert "provenance unknown" in report        # the sidecar-less source is flagged, not omitted
    assert "from hand.json" in report
