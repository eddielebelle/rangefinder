from rangefinder.capture.posture import ASSUMED, MEASURED, UNMEASURABLE, CaptureReport


def test_capture_report_tiers_and_markdown():
    r = CaptureReport(target="host.example", perspective="anonymous", protocol="smb")
    r.measured("signing_required", True, "negotiate")
    r.assumed("smb1_enabled", False, "not probed")
    r.unmeasurable("authenticated_surface", "unknown", "no creds")

    assert [i.status for i in r.items] == [MEASURED, ASSUMED, UNMEASURABLE]
    # booleans render as json-style true/false, not Python True/False
    assert r.tier(MEASURED)[0].value == "true"
    assert r.tier(ASSUMED)[0].value == "false"

    md = r.to_markdown()
    assert "# Capture report — host.example (smb)" in md
    assert "_Perspective: anonymous_" in md
    # all three tier headings present, each with its item
    assert "✓ MEASURED" in md and "signing_required" in md
    assert "⚠ ASSUMED" in md and "smb1_enabled" in md
    assert "✗ UNMEASURABLE" in md and "authenticated_surface" in md


def test_empty_tier_renders_none():
    r = CaptureReport(target="h", perspective="anon")
    r.measured("x", 1)
    md = r.to_markdown()
    # assumed + unmeasurable have no items -> explicit "(none)", never a silent gap
    assert md.count("(none)") == 2
