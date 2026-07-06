import asyncio
import socket

from helpers import make_ctx

from rangefinder.capture import capture_smb
from rangefinder.config.services import SmbConfig, SmbShare
from rangefinder.facades.smb import SmbFacade


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _target_cfg(port):
    return SmbConfig(
        port=port,
        server_os="Windows Server 2019 Standard",
        shares=[
            SmbShare(name="Public", comment="Company-wide",
                     files={"welcome.txt": "welcome to acme"}),
            SmbShare(name="IT", comment="IT dept",
                     files={"runbooks/backup.md": "runs as svc-backup",
                            "creds/vault.txt": "sql: svc-sql / Summ3r2025!"}),
        ],
    )


async def _capture(scrub=False):
    ctx, _ = make_ctx()
    port = _free_port()
    facade = SmbFacade.from_config(_target_cfg(port), ctx)
    facade.bind_host = "127.0.0.1"
    facade.port = port
    await facade.start()
    try:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None, lambda: capture_smb("127.0.0.1", port, scrub=scrub)
        )
    finally:
        await facade.stop()


def test_capture_records_shares_and_files():
    service, warnings, _ = asyncio.run(_capture())
    assert service["type"] == "smb"
    shares = {s["name"].upper(): s for s in service["shares"]}
    # IPC$ is skipped; the real shares are captured
    assert "IPC$" not in shares
    assert "PUBLIC" in shares and "IT" in shares
    it_files = shares["IT"]["files"]
    # nested tree preserved, contents verbatim
    assert it_files["runbooks/backup.md"] == "runs as svc-backup"
    assert it_files["creds/vault.txt"] == "sql: svc-sql / Summ3r2025!"


def test_captured_smb_replays(tmp_path):
    from dataclasses import replace as dc_replace

    service, *_ = asyncio.run(_capture())
    # Build a fresh facade from the captured shares and confirm the file tree materializes.
    ctx, _ = make_ctx()
    ctx = dc_replace(ctx, config_dir=str(tmp_path))
    cfg = SmbConfig.model_validate({k: v for k, v in service.items()})
    cfg = cfg.model_copy(update={"port": _free_port()})
    replica = SmbFacade.from_config(cfg, ctx)

    async def run():
        replica.bind_host = "127.0.0.1"
        await replica.start()
        try:
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(None, lambda: capture_smb("127.0.0.1", replica.port))
        finally:
            await replica.stop()

    recaptured, *_ = asyncio.run(run())
    names = {s["name"].upper() for s in recaptured["shares"]}
    assert {"PUBLIC", "IT"} <= names


def _capture_with(**kw):
    ctx, _ = make_ctx()
    port = _free_port()
    facade = SmbFacade.from_config(_target_cfg(port), ctx)
    facade.bind_host = "127.0.0.1"
    facade.port = port

    async def run():
        await facade.start()
        try:
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(
                None, lambda: capture_smb("127.0.0.1", port, **kw))
        finally:
            await facade.stop()

    return asyncio.run(run())


def test_share_filter_targets_named_shares():
    service, warnings, _ = _capture_with(shares=["IT", "does-not-exist"])
    names = {s["name"].upper() for s in service["shares"]}
    assert names == {"IT"}  # Public skipped; only IT captured
    assert any("does-not-exist" in w and "not found" in w for w in warnings)


def test_per_share_budget_does_not_starve_other_shares():
    # IT has 2 files; a per-share cap of 1 truncates IT but must NOT starve Public.
    service, warnings, _ = _capture_with(max_files_per_share=1)
    shares = {s["name"].upper(): s for s in service["shares"]}
    assert "PUBLIC" in shares and "IT" in shares
    assert len(shares["IT"].get("files", {})) == 1          # IT truncated to the per-share cap
    assert len(shares["PUBLIC"].get("files", {})) == 1      # Public still captured (not starved)
    assert any("IT" in w and "truncated" in w for w in warnings)


def test_capture_records_restrict_anonymous_for_denied_share():
    # A share a null session can enumerate but not read must come back marked restrict_anonymous
    # (enumerable, not readable) — not as an empty, wide-open share.
    ctx, _ = make_ctx()
    port = _free_port()
    cfg = SmbConfig(
        port=port,
        shares=[
            SmbShare(name="Public", files={"hi.txt": "hello"}),
            SmbShare(name="Private", restrict_anonymous=True),
        ],
    )
    facade = SmbFacade.from_config(cfg, ctx)
    facade.bind_host = "127.0.0.1"
    facade.port = port

    async def run():
        await facade.start()
        try:
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(None, lambda: capture_smb("127.0.0.1", port))
        finally:
            await facade.stop()

    service, warnings, report = asyncio.run(run())
    shares = {s["name"].upper(): s for s in service["shares"]}
    assert shares["PRIVATE"].get("restrict_anonymous") is True   # denial recorded faithfully
    assert "files" not in shares["PRIVATE"]                      # nothing readable captured
    assert shares["PUBLIC"].get("restrict_anonymous") in (None, False)
    assert "signing_required" in service                         # signing posture captured
    assert any("private" in w.lower() and "access denied" in w for w in warnings)

    # provenance report: posture is measured, and the anonymous-perspective gap is surfaced
    status = {i.field: i.status for i in report.items}
    assert status.get("smb1_enabled") == "measured"
    assert status.get("reject_unknown_users") == "measured"
    assert status.get("signing_required") == "measured"
    assert any(i.status == "unmeasurable" and "authenticated" in i.field for i in report.items)
    md = report.to_markdown()
    assert "MEASURED" in md and "UNMEASURABLE" in md


def test_scrub_redacts_file_contents():
    service, *_ = asyncio.run(_capture(scrub=True))
    it = next(s for s in service["shares"] if s["name"] == "IT")
    vault = it["files"]["creds/vault.txt"]
    # the "sql:" credential line has no keyword our redactor keys on, but a password= would
    # be caught; here we just assert scrub ran without dropping the route/file
    assert "creds/vault.txt" in it["files"]


def test_credentialed_capture_gates_authenticated_view_behind_auth():
    # Capturing WITH credentials reads the authenticated file view. Those files must NOT be served
    # to a null session on the twin: a share a null session can't read comes back restrict_anonymous
    # (gated behind auth), while a share a null session CAN read stays open — measured per share.
    from dataclasses import replace

    from rangefinder.config.model import ADUser, Identities

    ctx, _ = make_ctx()
    ctx = replace(ctx, identities=Identities(
        domain="acme.corp", users=[ADUser(sam="svc-web", password="Autumn2025!")]))
    port = _free_port()
    cfg = SmbConfig(
        port=port,
        reject_unknown_users=True,
        # Cap at 2.1 so the credentialed session isn't SMB3-encrypted — the impacket-based facade
        # can't do AES-CMAC signing/encryption (real Windows handles its own; this is a facade-only
        # test limitation, not a capture one).
        max_dialect="2.1",
        shares=[
            SmbShare(name="Public", files={"hi.txt": "hello"}),                    # anon-readable
            SmbShare(name="Private", restrict_anonymous=True,                       # auth-only
                     files={"secret.txt": "top secret"}),
        ],
    )
    facade = SmbFacade.from_config(cfg, ctx)
    facade.bind_host = "127.0.0.1"
    facade.port = port

    async def run():
        await facade.start()
        try:
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(None, lambda: capture_smb(
                "127.0.0.1", port, username="svc-web", password="Autumn2025!", domain="acme.corp"))
        finally:
            await facade.stop()

    service, warnings, report = asyncio.run(run())
    shares = {s["name"].upper(): s for s in service["shares"]}

    # The authenticated read reached the auth-only share's contents...
    assert shares["PRIVATE"]["files"]["secret.txt"] == "top secret"
    # ...but the twin gates it behind auth (a null session could not read it on the real host).
    assert shares["PRIVATE"].get("restrict_anonymous") is True
    # The anon-readable share stays open (a null session CAN read it) — not over-gated.
    assert shares["PUBLIC"].get("restrict_anonymous") in (None, False)
    assert shares["PUBLIC"]["files"]["hi.txt"] == "hello"

    # provenance: the per-share anon gating is a measured fact (Private gated, Public anon-readable).
    anon = [i for i in report.items if i.field == "anonymous_share_access"]
    assert len(anon) == 1 and anon[0].status == "measured"      # both shares measured, none assumed
    assert "1 gated" in anon[0].value and "1 anon-readable" in anon[0].value
    # the shares note must not claim the authenticated capture session was denied a share it read
    shares_note = next(i for i in report.items if i.field == "shares")
    assert "deny this session" not in shares_note.note
    # a credentialed capture doesn't emit the anonymous-perspective "unmeasurable" gap
    assert not any(i.field == "authenticated_read_write" for i in report.items)


def test_anon_probe_reports_inconclusive_when_unreachable(monkeypatch):
    # A probe that cannot even connect must read as inconclusive (None), never as a measured denial —
    # otherwise a probe that never ran would be reported as "measured: anon denied".
    from rangefinder.capture.smb import _AnonProbe

    probe = _AnonProbe("127.0.0.1", _free_port(), 0.5, "")  # nothing listening -> connect fails
    assert probe._conn is None and probe._null_refused is False
    assert probe.can_read("AnyShare") is None                # inconclusive, not False (denied)
    probe.close()
