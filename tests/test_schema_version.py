import json
from pathlib import Path

import pytest

from rangefinder.config.loader import ConfigError, load_config
from rangefinder.config.model import SCHEMA_VERSION
from rangefinder.importers import import_nmap

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _write(tmp_path, cfg) -> Path:
    p = tmp_path / "range.json"
    p.write_text(json.dumps(cfg))
    return p


def _base(**over):
    cfg = {
        "name": "r",
        "network": {"subnet": "10.0.0.0/24"},
        "hosts": [{"id": "h1", "hostname": "H1", "ip": "10.0.0.10",
                   "services": [{"type": "http", "port": 80}]}],
    }
    cfg.update(over)
    return cfg


def test_config_from_the_future_is_rejected(tmp_path):
    path = _write(tmp_path, _base(schema_version=SCHEMA_VERSION + 1))
    with pytest.raises(ConfigError, match="rebuild"):
        load_config(path)


def test_current_and_older_schema_load(tmp_path):
    assert load_config(_write(tmp_path, _base(schema_version=SCHEMA_VERSION))) is not None
    # a config with no stamp is fine (hand-authored, backward compatible)
    assert load_config(_write(tmp_path, _base())) is not None


def test_import_stamps_schema_version():
    config, _, _ = import_nmap(FIXTURES / "nmap-basic.xml")
    assert config["schema_version"] == SCHEMA_VERSION
