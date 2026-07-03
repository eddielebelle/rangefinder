import asyncio
import socket

from helpers import make_ctx

from rangefinder.config.services import SmbConfig, SmbShare
from rangefinder.facades.smb import SmbFacade


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _client_enum(port: int):
    from impacket.smbconnection import SMBConnection

    conn = SMBConnection("127.0.0.1", "127.0.0.1", sess_port=port)
    conn.login("", "")  # null session
    shares = [s["shi1_netname"][:-1] for s in conn.listShares()]
    content = None
    for f in conn.listPath("backups", "*"):
        if f.get_longname() == "README.txt":
            content = "found"
    conn.close()
    return shares, content


def _cfg(port):
    return SmbConfig(
        port=port,
        server_os="Windows Server 2022 Standard 20348",
        shares=[
            SmbShare(name="SYSVOL", comment="Logon server share"),
            SmbShare(
                name="backups",
                comment="Nightly backup drop",
                files={"README.txt": "restore runs as svc-backup", "db/conn.txt": "pwd=Winter2024!"},
            ),
        ],
    )


def test_smb_share_enumeration_and_telemetry():
    async def run():
        ctx, sink = make_ctx()
        port = _free_port()
        facade = SmbFacade.from_config(_cfg(port), ctx)
        facade.bind_host = "127.0.0.1"
        facade.port = port
        await facade.start()
        try:
            shares, content = await asyncio.get_running_loop().run_in_executor(
                None, _client_enum, port
            )
        finally:
            await facade.stop()
        return shares, content, sink

    shares, content, sink = asyncio.run(run())
    upper = {s.upper() for s in shares}
    assert "SYSVOL" in upper
    assert "BACKUPS" in upper  # impacket normalizes share names to uppercase
    assert "IPC$" in upper  # impacket adds IPC$, required for share enumeration
    assert content == "found"

    actions = {e["event"]["action"] for e in sink.events}
    assert "smb_auth" in actions
    assert "smb_share_enum" in actions
    # the auth event captured the (anonymous) session
    auth = next(e for e in sink.events if e["event"]["action"] == "smb_auth")
    assert auth["rangefinder"]["auth"]["method"] == "anonymous"
