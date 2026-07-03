from rangefinder.config.model import RangeConfig
from rangefinder.scoring import parse_events, score


def _config():
    return RangeConfig.model_validate({
        "name": "r",
        "network": {"subnet": "10.0.0.0/24"},
        "hosts": [{"id": "h1", "hostname": "H1", "ip": "10.0.0.10",
                   "services": [{"type": "http", "port": 80}]}],
        "objectives": [
            {"id": "obj-web", "title": "Read web config", "description": "d",
             "detect": [{"label": "hit db.config",
                         "all": [{"field": "event.action", "equals": "http_request"},
                                 {"field": "url.path", "contains": "/backup/db.config"}]}]},
            {"id": "obj-multi", "title": "Recover cred (2 paths)", "description": "d",
             "detect": [
                 {"label": "web", "all": [{"field": "url.path", "contains": "/backup/db.config"}]},
                 {"label": "smb", "all": [{"field": "event.action", "equals": "smb_file_access"},
                                          {"field": "rangefinder.smb.path", "contains": "vault"}]},
             ]},
            {"id": "obj-none", "title": "Descriptive only", "description": "d"},  # no detect -> UNSCORED
        ],
    })


def _ev(**over):
    base = {"@timestamp": "2026-07-03T10:00:00.000Z", "event": {"action": "x"}, "source": {"ip": "10.0.0.9"}}
    base.update(over)
    return base


def test_met_and_source_tracking():
    cfg = _config()
    events = [
        _ev(**{"@timestamp": "2026-07-03T10:00:01.000Z", "event": {"action": "http_request"},
               "url": {"path": "/"}, "source": {"ip": "10.0.0.9"}}),
        _ev(**{"@timestamp": "2026-07-03T10:00:02.000Z", "event": {"action": "http_request"},
               "url": {"path": "/backup/db.config"}, "source": {"ip": "10.0.0.9"}}),
    ]
    results = {r.id: r for r in score(cfg, events)}
    assert results["obj-web"].met
    assert results["obj-web"].source_ip == "10.0.0.9"
    assert results["obj-web"].action == "http_request"
    assert results["obj-web"].match_count == 1


def test_multi_signal_any_path():
    cfg = _config()
    # only the SMB path occurs -> objective still met via that signal
    events = [_ev(**{"event": {"action": "smb_file_access"},
                     "rangefinder": {"smb": {"path": "vault-export.txt"}},
                     "source": {"ip": "10.0.0.5"}})]
    r = {x.id: x for x in score(cfg, events)}["obj-multi"]
    assert r.met and r.signal == "smb"
    assert r.source_ips == ["10.0.0.5"]


def test_unmet_and_unscored():
    cfg = _config()
    results = {r.id: r for r in score(cfg, [_ev(url={"path": "/robots.txt"}, event={"action": "http_request"})])}
    assert results["obj-web"].met is False and results["obj-web"].scoreable is True
    assert results["obj-none"].scoreable is False
    assert results["obj-none"].met is False


def _seq_config(**seq):
    base_seq = {"same_source": True, "steps": [
        {"label": "foothold", "all": [{"field": "event.action", "equals": "ssh_auth"},
                                      {"field": "event.outcome", "equals": "success"}]},
        {"label": "loot", "all": [{"field": "event.action", "equals": "smb_file_access"}]},
    ]}
    base_seq.update(seq)
    return RangeConfig.model_validate({
        "name": "r", "network": {"subnet": "10.0.0.0/24"},
        "hosts": [{"id": "h1", "hostname": "H1", "ip": "10.0.0.10",
                   "services": [{"type": "http", "port": 80}]}],
        "objectives": [{"id": "kc", "title": "Kill chain", "description": "d", "sequence": base_seq}],
    })


def _at(ts, action, ip, **extra):
    e = {"@timestamp": ts, "event": {"action": action}, "source": {"ip": ip}}
    if "outcome" in extra:
        e["event"]["outcome"] = extra["outcome"]
    return e


def test_sequence_met_in_order_same_source():
    cfg = _seq_config()
    events = [
        _at("2026-07-03T10:00:01.000Z", "ssh_auth", "10.0.0.9", outcome="success"),
        _at("2026-07-03T10:00:05.000Z", "smb_file_access", "10.0.0.9"),
    ]
    r = {x.id: x for x in score(cfg, events)}["kc"]
    assert r.met and r.kind == "sequence"
    assert r.source_ip == "10.0.0.9"
    assert [s["label"] for s in r.chain] == ["foothold", "loot"]


def test_sequence_not_met_out_of_order():
    cfg = _seq_config()
    events = [
        _at("2026-07-03T10:00:01.000Z", "smb_file_access", "10.0.0.9"),  # loot before foothold
        _at("2026-07-03T10:00:05.000Z", "ssh_auth", "10.0.0.9", outcome="success"),
    ]
    assert {x.id: x for x in score(cfg, events)}["kc"].met is False


def test_sequence_requires_same_source():
    cfg = _seq_config()
    events = [
        _at("2026-07-03T10:00:01.000Z", "ssh_auth", "10.0.0.9", outcome="success"),
        _at("2026-07-03T10:00:05.000Z", "smb_file_access", "10.0.0.8"),  # different attacker
    ]
    assert {x.id: x for x in score(cfg, events)}["kc"].met is False


def test_sequence_cross_source_when_allowed():
    cfg = _seq_config(same_source=False)
    events = [
        _at("2026-07-03T10:00:01.000Z", "ssh_auth", "10.0.0.9", outcome="success"),
        _at("2026-07-03T10:00:05.000Z", "smb_file_access", "10.0.0.8"),
    ]
    assert {x.id: x for x in score(cfg, events)}["kc"].met is True


def test_sequence_within_window():
    cfg = _seq_config(within="30s")
    too_slow = [
        _at("2026-07-03T10:00:00.000Z", "ssh_auth", "10.0.0.9", outcome="success"),
        _at("2026-07-03T10:05:00.000Z", "smb_file_access", "10.0.0.9"),  # 5 min later
    ]
    assert {x.id: x for x in score(cfg, too_slow)}["kc"].met is False
    in_time = [
        _at("2026-07-03T10:00:00.000Z", "ssh_auth", "10.0.0.9", outcome="success"),
        _at("2026-07-03T10:00:20.000Z", "smb_file_access", "10.0.0.9"),
    ]
    assert {x.id: x for x in score(cfg, in_time)}["kc"].met is True


def test_parse_events_tolerates_docker_prefix():
    lines = [
        'acme-web01  | {"@timestamp":"2026-07-03T10:00:00.000Z","event":{"action":"http_request"}}',
        "not json at all",
        '{"@timestamp":"2026-07-03T09:00:00.000Z","event":{"action":"connection_open"}}',
    ]
    events = parse_events(lines)
    assert len(events) == 2
    # sorted by @timestamp -> the 09:00 event comes first
    assert events[0]["event"]["action"] == "connection_open"
