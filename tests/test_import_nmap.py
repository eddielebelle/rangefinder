from pathlib import Path

import pytest

from rangefinder.config.model import RangeConfig
from rangefinder.importers import import_nmap

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def test_import_basic_scan():
    config, summary, warnings = import_nmap(FIXTURES / "nmap-basic.xml", name="corp-replica")
    # validates as a real config
    cfg = RangeConfig.model_validate(config)
    assert cfg.name == "corp-replica"
    assert summary["hosts"] == 2

    by_id = {h["id"]: h for h in config["hosts"]}
    assert set(by_id) == {"dc01", "web01"}
    assert by_id["dc01"]["os"] == "windows_server_2019"
    assert by_id["web01"]["os"] == "generic_linux"


def test_facade_mapping():
    config, _, _ = import_nmap(FIXTURES / "nmap-basic.xml")
    web = next(h for h in config["hosts"] if h["id"] == "web01")
    svc = {s["port"]: s for s in web["services"]}
    # ssh -> real ssh facade with reconstructed version
    assert svc[22]["type"] == "ssh"
    assert svc[22]["server_version"] == "OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
    # http and https (tunnel=ssl -> tls)
    assert svc[80]["type"] == "http" and svc[80]["server_header"] == "nginx 1.18.0"
    assert svc[443]["type"] == "http" and svc[443]["tls"] is True
    # mysql -> labelled banner decoy
    assert svc[3306]["type"] == "banner" and svc[3306]["protocol"] == "mysql"

    dc = next(h for h in config["hosts"] if h["id"] == "dc01")
    dsvc = {s["port"]: s for s in dc["services"]}
    assert dsvc[389]["type"] == "banner" and dsvc[389]["protocol"] == "ldap"


def test_subnet_override_must_contain_hosts():
    with pytest.raises(ValueError, match="does not contain"):
        import_nmap(FIXTURES / "nmap-basic.xml", subnet="192.168.5.0/24")


def test_derived_subnet():
    _, summary, _ = import_nmap(FIXTURES / "nmap-basic.xml")
    # 10.10.0.10 and 10.10.0.20 collapse to a /24 (capped)
    assert summary["subnet"] == "10.10.0.0/24"


def test_captures_misconfigs_from_nse_scripts():
    config, summary, _ = import_nmap(FIXTURES / "nmap-scripts.xml", name="corp")
    RangeConfig.model_validate(config)  # still valid with objectives

    obj_ids = {o["id"] for o in config["objectives"]}
    # exposed web paths -> objectives + routes
    assert "web01-exposed-git" in obj_ids
    assert "web01-exposed-admin" in obj_ids
    assert "web01-exposed-backup" in obj_ids
    # SMB null-session shares + LDAP anon + FTP anon
    assert "fs01-smb-null-session" in obj_ids
    assert "fs01-ldap-anon" in obj_ids
    assert "web01-exposed-git" in obj_ids

    web = next(h for h in config["hosts"] if h["id"] == "web01")
    http = next(s for s in web["services"] if s["type"] == "http")
    assert "/.git/HEAD" in http["paths"]
    assert http["paths"]["/.git/HEAD"]["vuln_id"] == "exposed-git-repo"
    assert http["paths"]["/admin"]["vuln_id"] == "exposed-admin"
    # a non-sensitive path is planted without a vuln tag
    assert "/images" in http["paths"] and "vuln_id" not in http["paths"]["/images"]

    # 445 promoted to a real smb facade with the enumerated shares (IPC$ dropped)
    fs = next(h for h in config["hosts"] if h["id"] == "fs01")
    smb = next(s for s in fs["services"] if s["type"] == "smb")
    share_names = {sh["name"] for sh in smb["shares"]}
    assert share_names == {"Finance", "HR", "IT"}
    assert smb["signing_required"] is False

    assert summary["scoreable_objectives"] >= 4


def test_ftp_anon_objective():
    config, _, _ = import_nmap(FIXTURES / "nmap-scripts.xml")
    assert any(o["id"].endswith("-ftp-anon") for o in config["objectives"])


def test_rejects_non_nmap_xml(tmp_path):
    bad = tmp_path / "bad.xml"
    bad.write_text("<foo/>")
    with pytest.raises(ValueError, match="not an nmap XML"):
        import_nmap(bad)
