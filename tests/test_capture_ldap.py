import asyncio
from dataclasses import replace

from helpers import make_ctx

from rangefinder.capture import capture_ldap
from rangefinder.config.model import ADGroup, ADUser, Identities
from rangefinder.config.services import LdapConfig, LdapEntry
from rangefinder.facades.ldap import LdapFacade


def _identities():
    return Identities(
        domain="corp.local",
        groups=[ADGroup(name="Admins", members=["svc-x"])],
        users=[ADUser(sam="svc-x", display_name="Svc X",
                      description="backup acct password=Pass123!")],
    )


async def _capture_from_live_facade(scrub=False, *, allow_anonymous_bind=True,
                                    bind_dn="", password=""):
    ctx, _ = make_ctx()
    ctx = replace(ctx, identities=_identities())
    facade = LdapFacade.from_config(
        LdapConfig(port=389, allow_anonymous_bind=allow_anonymous_bind), ctx)
    facade.bind_host = "127.0.0.1"
    facade.port = 0
    await facade.start()
    try:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None, lambda: capture_ldap("127.0.0.1", facade.bound_port, scrub=scrub,
                                       bind_dn=bind_dn, password=password)
        )
    finally:
        await facade.stop()


def test_capture_records_directory():
    service, warnings, report = asyncio.run(_capture_from_live_facade())
    assert service["type"] == "ldap"
    assert service["allow_anonymous_bind"] is True
    assert service["base_dn"] == "DC=corp,DC=local"

    # provenance: anonymous bind is a measured fact, and the authenticated view is surfaced as
    # unmeasurable (the same fail-closed/surface discipline as SMB, now protocol-agnostic).
    assert report.protocol == "ldap"
    status = {i.field: i.status for i in report.items}
    assert status.get("allow_anonymous_bind") == "measured"
    assert any(i.status == "unmeasurable" and "authenticated" in i.field for i in report.items)

    # RootDSE captured as dn ""
    assert any(e["dn"] == "" for e in service["entries"])
    # the user + its leaked description came through
    user = next(e for e in service["entries"] if e["attributes"].get("sAMAccountName") == ["svc-x"])
    assert user["attributes"]["description"] == ["backup acct password=Pass123!"]
    assert any("Admins" in e["dn"] for e in service["entries"])


def test_captured_config_replays_faithfully():
    service, *_ = asyncio.run(_capture_from_live_facade())
    # Build a fresh facade from the captured entries (no identities) and confirm it
    # serves the same directory.
    ctx, _ = make_ctx()
    cfg = LdapConfig(port=389, base_dn=service["base_dn"],
                     entries=[LdapEntry(**e) for e in service["entries"]])
    replica = LdapFacade.from_config(cfg, ctx)
    assert replica.base_dn == "DC=corp,DC=local"
    assert any(e.get("sAMAccountName") == ["svc-x"] for e in replica.entries)
    # RootDSE replayed from the captured dn="" entry
    assert replica.root_dse.dn == ""


def test_capture_hardened_directory_denies_anon():
    """A DC that refuses the anonymous bind must be captured as a faithful hardened posture —
    not crash the capture, and not produce a twin that serves the directory to anon."""
    service, warnings, report = asyncio.run(
        _capture_from_live_facade(allow_anonymous_bind=False))

    assert service["allow_anonymous_bind"] is False
    status = {i.field: i.status for i in report.items}
    assert status.get("allow_anonymous_bind") == "measured"  # measured False, not assumed
    # anonymous couldn't enumerate the directory; only the (always-anon-readable) RootDSE returned
    assert all(e["dn"] == "" for e in service["entries"])
    assert any("anonymous bind rejected" in w for w in warnings)


def test_capture_credentialed_fails_closed_on_anon():
    """A credentialed capture must not hand its privileged view to anonymous clients even when
    the target *does* accept anon bind — the twin fails closed, and the report says why."""
    service, warnings, report = asyncio.run(
        _capture_from_live_facade(bind_dn="CN=svc-x,DC=corp,DC=local", password="x"))

    # target accepts anon (allow_anonymous_bind=True on the facade) but the twin denies it
    assert service["allow_anonymous_bind"] is False
    status = {i.field: i.status for i in report.items}
    assert status.get("anonymous_bind_accepted") == "measured"
    assert status.get("allow_anonymous_bind") == "assumed"  # fail-closed, flagged as an assumption
    # the credentialed view still came through (svc-x is present)
    assert any(e["attributes"].get("sAMAccountName") == ["svc-x"] for e in service["entries"])


def test_scrub_redacts_secret_attributes():
    service, *_ = asyncio.run(_capture_from_live_facade(scrub=True))
    user = next(e for e in service["entries"] if e["attributes"].get("sAMAccountName") == ["svc-x"])
    desc = user["attributes"]["description"][0]
    assert "Pass123" not in desc
    assert "REDACTED" in desc
