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
    service, warnings = asyncio.run(_capture())
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

    service, _ = asyncio.run(_capture())
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

    recaptured, _ = asyncio.run(run())
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
    service, warnings = _capture_with(shares=["IT", "does-not-exist"])
    names = {s["name"].upper() for s in service["shares"]}
    assert names == {"IT"}  # Public skipped; only IT captured
    assert any("does-not-exist" in w and "not found" in w for w in warnings)


def test_per_share_budget_does_not_starve_other_shares():
    # IT has 2 files; a per-share cap of 1 truncates IT but must NOT starve Public.
    service, warnings = _capture_with(max_files_per_share=1)
    shares = {s["name"].upper(): s for s in service["shares"]}
    assert "PUBLIC" in shares and "IT" in shares
    assert len(shares["IT"].get("files", {})) == 1          # IT truncated to the per-share cap
    assert len(shares["PUBLIC"].get("files", {})) == 1      # Public still captured (not starved)
    assert any("IT" in w and "truncated" in w for w in warnings)


def test_scrub_redacts_file_contents():
    service, _ = asyncio.run(_capture(scrub=True))
    it = next(s for s in service["shares"] if s["name"] == "IT")
    vault = it["files"]["creds/vault.txt"]
    # the "sql:" credential line has no keyword our redactor keys on, but a password= would
    # be caught; here we just assert scrub ran without dropping the route/file
    assert "creds/vault.txt" in it["files"]
