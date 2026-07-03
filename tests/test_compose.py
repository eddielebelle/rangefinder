import json
from pathlib import Path

from rangefinder.config.loader import load_config
from rangefinder.orchestrate import build_compose, write_outputs

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "corp.json"


def test_compose_shape():
    cfg = load_config(EXAMPLE)
    compose = build_compose(cfg)
    assert compose["name"] == "corp"
    assert "version" not in compose  # deprecated key must be omitted
    ipam = compose["networks"]["range"]["ipam"]["config"][0]
    assert ipam["subnet"] == "10.13.37.0/24"
    assert ipam["gateway"] == "10.13.37.1"

    dc = compose["services"]["dc01"]
    assert dc["networks"]["range"]["ipv4_address"] == "10.13.37.10"
    assert "net.ipv4.ip_unprivileged_port_start=0" in dc["sysctls"]
    assert dc["command"] == ["run", "--host", "dc01", "--config", "/range/config.json"]

    attacker = compose["services"]["attacker"]
    assert attacker["profiles"] == ["attacker"]
    assert "NET_RAW" in attacker["cap_add"]


def test_write_outputs_is_valid_json(tmp_path):
    cfg = load_config(EXAMPLE)
    compose_path = write_outputs(cfg, tmp_path, EXAMPLE)
    assert compose_path.exists()
    # JSON is valid YAML; assert it parses as JSON too.
    parsed = json.loads(compose_path.read_text())
    assert parsed["services"]["web01"]["hostname"] == "WEB01"
    assert (tmp_path / "config.json").exists()


def test_no_attacker_flag():
    cfg = load_config(EXAMPLE)
    compose = build_compose(cfg, include_attacker=False)
    assert "attacker" not in compose["services"]
