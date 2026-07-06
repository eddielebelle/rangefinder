from rangefinder import detect as det


def _ev(**kw):
    """Build a minimal ECS-ish event; nested keys via dotted kwargs like action='smb_auth'."""
    e: dict = {"event": {}, "source": {}, "rangefinder": {}}
    e["event"]["action"] = kw.get("action")
    e["event"]["outcome"] = kw.get("outcome", "success")
    e["event"]["kind"] = kw.get("kind", "event")
    if "src_ip" in kw:
        e["source"]["ip"] = kw["src_ip"]
    if "method" in kw:
        e["rangefinder"]["auth"] = {"method": kw["method"]}
    if "vuln" in kw:
        e["rangefinder"]["vuln_id"] = kw["vuln"]
    return e


# ------------------------------------------------------------------- Sigma evaluator

def test_selection_and_dotted_fields():
    rule = {"detection": {"selection": {"event.action": "smb_auth",
                                        "rangefinder.auth.method": "anonymous"},
                          "condition": "selection"}}
    assert det.rule_matches(rule, _ev(action="smb_auth", method="anonymous"))
    assert not det.rule_matches(rule, _ev(action="smb_auth", method="ntlm"))
    assert not det.rule_matches(rule, _ev(action="ldap_search"))


def test_modifiers_and_value_lists():
    rule = {"detection": {"sel": {"event.action|contains": "auth",
                                  "event.outcome": ["success", "failure"]},
                          "condition": "sel"}}
    assert det.rule_matches(rule, _ev(action="smb_auth", outcome="failure"))
    assert not det.rule_matches(rule, _ev(action="smb_tree_connect", outcome="success"))


def test_condition_expressions():
    rule = {"detection": {
        "a": {"event.action": "smb_auth"},
        "filter": {"rangefinder.auth.method": "ntlm"},
        "condition": "a and not filter",
    }}
    assert det.rule_matches(rule, _ev(action="smb_auth", method="anonymous"))
    assert not det.rule_matches(rule, _ev(action="smb_auth", method="ntlm"))


def test_one_of_them():
    rule = {"detection": {
        "sel_a": {"event.action": "kerberos_as_rep"},
        "sel_b": {"event.action": "smb_auth"},
        "condition": "1 of sel_*",
    }}
    assert det.rule_matches(rule, _ev(action="smb_auth"))
    assert det.rule_matches(rule, _ev(action="kerberos_as_rep"))
    assert not det.rule_matches(rule, _ev(action="dns_query"))


# ------------------------------------------------------------------------- validation

def test_validate_true_and_false_positives():
    attack = [_ev(action="smb_auth", method="anonymous", src_ip="10.0.0.9")]
    benign = [_ev(action="smb_auth", method="ntlm", src_ip="10.0.0.5"),
              _ev(action="smb_tree_connect")]
    rule = {"title": "Anon SMB",
            "detection": {"sel": {"event.action": "smb_auth",
                                  "rangefinder.auth.method": "anonymous"},
                          "condition": "sel"}}
    v = det.validate(rule, attack, benign)
    assert v.true_positives == 1 and v.false_positives == 0
    assert v.ok and v.verdict == "VALID"


def test_validate_flags_noisy_rule():
    attack = [_ev(action="smb_auth", method="anonymous")]
    benign = [_ev(action="smb_auth", method="ntlm")]
    rule = {"title": "Too broad", "detection": {"sel": {"event.action": "smb_auth"},
                                                "condition": "sel"}}
    v = det.validate(rule, attack, benign)
    assert v.true_positives == 1 and v.false_positives == 1
    assert not v.ok and "NOISY" in v.verdict


def test_validate_flags_overfit_rule():
    attack = [_ev(action="smb_auth", method="anonymous", src_ip="10.0.0.9")]
    rule = {"title": "Overfit", "detection": {"sel": {"event.action": "smb_auth",
                                                      "source.ip": "10.0.0.9"},
                                              "condition": "sel"}}
    v = det.validate(rule, attack, [])
    assert v.true_positives == 1
    assert not v.ok and "source.ip" in v.overfit_fields


# ------------------------------------------------------------- template generation

def test_generate_and_validate_anonymous_smb():
    attack = [_ev(action="smb_auth", method="anonymous"),
              _ev(action="kerberos_as_rep", kind="alert")]
    benign = [_ev(action="smb_auth", method="ntlm")]
    rules = det.generate(attack)
    titles = {r["title"] for r in rules}
    assert "Anonymous (null-session) SMB logon" in titles
    assert "Kerberos AS-REP roasting" in titles
    # every generated rule fires on the attack it was generated from, clean on benign
    for rule in rules:
        v = det.validate(rule, attack, benign)
        assert v.true_positives >= 1 and v.false_positives == 0


# ------------------------------------------------- objective -> Sigma compilation

from types import SimpleNamespace  # noqa: E402

from rangefinder.config.model import Condition, Objective, Sequence, Signal  # noqa: E402


def _obj(oid="leak", *, detect=None, sequence=None, title="T", desc="D"):
    return Objective(id=oid, title=title, description=desc,
                     detect=detect or [], sequence=sequence)


def _range(name, objectives):
    # compile_objective/from_objectives only read .name and .objectives.
    return SimpleNamespace(name=name, objectives=objectives)


def test_compile_objective_single_condition_round_trips():
    obj = _obj(detect=[Signal(all=[Condition(field="event.action", equals="smb_auth")])])
    rule = det.compile_objective(obj, "corp")
    assert det.rule_matches(rule, _ev(action="smb_auth"))
    assert not det.rule_matches(rule, _ev(action="ldap_search"))
    assert rule["rangefinder_objective"] == "leak"


def test_compile_objective_conditions_within_signal_are_anded():
    obj = _obj(detect=[Signal(all=[
        Condition(field="event.action", equals="smb_auth"),
        Condition(field="rangefinder.auth.method", equals="anonymous"),
    ])])
    rule = det.compile_objective(obj, "corp")
    assert det.rule_matches(rule, _ev(action="smb_auth", method="anonymous"))
    assert not det.rule_matches(rule, _ev(action="smb_auth", method="ntlm"))  # one condition off


def test_compile_objective_signals_are_ored():
    obj = _obj(detect=[
        Signal(all=[Condition(field="event.action", equals="smb_auth")]),
        Signal(all=[Condition(field="event.action", equals="kerberos_as_rep")]),
    ])
    rule = det.compile_objective(obj, "corp")
    assert det.rule_matches(rule, _ev(action="smb_auth"))
    assert det.rule_matches(rule, _ev(action="kerberos_as_rep"))
    assert not det.rule_matches(rule, _ev(action="ldap_bind"))


def test_compile_objective_maps_modifiers():
    obj = _obj(detect=[Signal(all=[
        Condition(field="url.path", contains="admin"),
        Condition(field="rangefinder.vuln_id", regex=".+"),
    ])])
    detection = det.compile_objective(obj, "corp")["detection"]
    keys = {k for k in detection if k != "condition"}
    field_keys = {next(iter(detection[k])) for k in keys}
    assert "url.path|contains" in field_keys
    assert "rangefinder.vuln_id|re" in field_keys


def test_compile_objective_id_is_deterministic_and_range_scoped():
    obj = _obj(detect=[Signal(all=[Condition(field="event.action", equals="x")])])
    a = det.compile_objective(obj, "corp")["id"]
    b = det.compile_objective(obj, "corp")["id"]
    c = det.compile_objective(obj, "other")["id"]
    assert a == b          # stable across runs -> no SIEM content churn on redeploy
    assert a != c          # same objective id in a different range is a distinct rule


def test_compiled_rule_dropped_when_it_never_fires():
    # A ground-truth MISS (the range never emits the field) must fail validation, not ship dead.
    obj = _obj(detect=[Signal(all=[Condition(field="event.action", equals="never_emitted")])])
    rule = det.compile_objective(obj, "corp")
    v = det.validate(rule, [_ev(action="smb_auth")], [])
    assert v.true_positives == 0 and not v.ok


def test_from_objectives_skips_descriptive_and_sequence_only():
    describe = _obj("describe")  # no detect, no sequence
    seq = _obj("chain", sequence=Sequence(steps=[
        Signal(all=[Condition(field="event.action", equals="a")])]))
    real = _obj("leak", detect=[Signal(all=[Condition(field="event.action", equals="smb_auth")])])
    cfg = _range("corp", [describe, seq, real])
    rules = det.from_objectives(cfg)
    assert [r["rangefinder_objective"] for r in rules] == ["leak"]
    assert det.uncompiled_objectives(cfg) == ["chain"]  # sequence-only surfaced, describe omitted
    assert det.compile_objective(seq, "corp") is None


from rangefinder import scoring  # noqa: E402


def test_compiled_equals_is_case_sensitive_like_scoring():
    # equals is case-SENSITIVE in scoring; the compiled rule must not over-fire on case variants.
    signal = Signal(all=[Condition(field="event.action", equals="Admin")])
    obj = _obj(detect=[signal])
    rule = det.compile_objective(obj, "corp")
    same = _ev(action="Admin")
    variant = _ev(action="admin")
    # compiled rule agrees with the objective scorer on both the match and the case variant
    assert det.rule_matches(rule, same) is scoring._signal_matches(signal, same) is True
    assert det.rule_matches(rule, variant) is scoring._signal_matches(signal, variant) is False


def test_compiled_rule_matches_iff_objective_signal_matches():
    # Cross-check compile+evaluate against the objective scorer over equals/contains/regex + events.
    signals = [
        Signal(all=[Condition(field="event.action", equals="smb_auth")]),
        Signal(all=[Condition(field="url.path", contains="/Admin")]),          # contains: case-insensitive
        Signal(all=[Condition(field="rangefinder.vuln_id", regex="cve-.*")]),
    ]
    events = [
        _ev(action="smb_auth"), _ev(action="SMB_AUTH"),                        # equals case variance
        _ev(action="x", **{}),
    ]
    events[2]["url"] = {"path": "/admin/panel"}                                 # contains hit (diff case)
    events.append(_ev(vuln="cve-2021-1"))
    for sig in signals:
        rule = det.compile_objective(_obj(detect=[sig]), "corp")
        for ev in events:
            assert det.rule_matches(rule, ev) == scoring._signal_matches(sig, ev)


def test_dual_detect_and_sequence_objective_surfaces_uncompiled_sequence():
    # An objective with BOTH detect and sequence: detect half compiles, sequence half is surfaced
    # as uncompiled (not silently dropped).
    dual = _obj("dual",
                detect=[Signal(all=[Condition(field="event.action", equals="smb_auth")])],
                sequence=Sequence(steps=[Signal(all=[Condition(field="event.action", equals="a")])]))
    cfg = _range("corp", [dual])
    assert [r["rangefinder_objective"] for r in det.from_objectives(cfg)] == ["dual"]  # detect compiled
    assert det.uncompiled_objectives(cfg) == ["dual"]                                   # sequence surfaced
