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
