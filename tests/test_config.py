from pathlib import Path

import pytest
from pydantic import ValidationError

from rangefinder.config.loader import ConfigError, load_config
from rangefinder.config.model import RangeConfig

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "corp.json"


def _base(**host_overrides):
    host = {
        "id": "h1",
        "hostname": "H1",
        "ip": "10.0.0.10",
        "services": [{"type": "http", "port": 80}],
    }
    host.update(host_overrides)
    return {
        "name": "r",
        "network": {"subnet": "10.0.0.0/24"},
        "hosts": [host],
    }


def test_example_loads():
    cfg = load_config(EXAMPLE)
    assert isinstance(cfg, RangeConfig)
    assert cfg.name == "corp"
    assert len(cfg.hosts) == 3
    assert cfg.get_host("web01").hostname == "WEB01"


def test_valid_minimal():
    cfg = RangeConfig.model_validate(_base())
    assert cfg.hosts[0].services[0].type == "http"


def test_ip_outside_subnet():
    with pytest.raises(ValidationError, match="not within subnet"):
        RangeConfig.model_validate(_base(ip="10.9.9.9"))


def test_duplicate_ports():
    with pytest.raises(ValidationError, match="duplicate service ports"):
        RangeConfig.model_validate(
            _base(services=[{"type": "http", "port": 80}, {"type": "banner", "port": 80, "banner": "x"}])
        )


def test_unknown_service_type():
    with pytest.raises(ValidationError):
        RangeConfig.model_validate(_base(services=[{"type": "quantumftp", "port": 21}]))


def test_ldap_requires_identities():
    with pytest.raises(ValidationError, match="requires top-level 'identities'"):
        RangeConfig.model_validate(_base(services=[{"type": "ldap", "port": 389}]))


def test_extra_field_forbidden():
    with pytest.raises(ValidationError):
        RangeConfig.model_validate(_base(bogus=True))


def test_missing_file():
    with pytest.raises(ConfigError, match="not found"):
        load_config("/nonexistent/range.json")
