import asyncio
import socket

from helpers import make_ctx

from rangefinder.config.services import SshConfig
from rangefinder.facades.ssh import SshFacade


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


async def _run(cfg, client_coro):
    import asyncssh  # noqa: F401 (ensures dependency present)

    ctx, sink = make_ctx()
    port = _free_port()
    facade = SshFacade.from_config(cfg, ctx)
    facade.bind_host = "127.0.0.1"
    facade.port = port
    await facade.start()
    try:
        result = await client_coro(port)
    finally:
        await facade.stop()
    return result, sink


def test_password_attempt_captured_and_rejected():
    async def client(port):
        import asyncssh

        try:
            await asyncssh.connect(
                "127.0.0.1", port, username="root", password="hunter2",
                known_hosts=None, client_keys=None, preferred_auth=["password"],
            )
            return "connected"
        except asyncssh.PermissionDenied:
            return "denied"

    async def go():
        return await _run(SshConfig(port=22), client)

    result, sink = asyncio.run(go())
    assert result == "denied"
    pw = [
        e for e in sink.events
        if e["event"]["action"] == "ssh_auth" and e["rangefinder"]["auth"]["method"] == "password"
    ]
    assert pw, "expected a captured password attempt"
    assert pw[0]["rangefinder"]["auth"] == {"user": "root", "method": "password", "credential": "hunter2"}
    assert pw[0]["event"]["outcome"] == "failure"
    assert any(e["event"]["action"] == "connection_open" for e in sink.events)


def test_valid_creds_accepted_and_command_captured():
    async def client(port):
        import asyncssh

        async with asyncssh.connect(
            "127.0.0.1", port, username="admin", password="s3cret",
            known_hosts=None, client_keys=None, preferred_auth=["password"],
        ) as conn:
            # No command => interactive shell; feed commands over stdin.
            r = await conn.run(input="id\nexit\n")
            return r.stdout

    async def go():
        return await _run(SshConfig(port=22, accept_creds={"admin": "s3cret"}, motd="WELCOME"), client)

    output, sink = asyncio.run(go())
    assert "WELCOME" in output
    assert "command not found" in output
    assert any(
        e["event"]["action"] == "ssh_auth" and e["event"]["outcome"] == "success"
        for e in sink.events
    )
    cmds = [e["rangefinder"]["ssh"]["command"] for e in sink.events if e["event"]["action"] == "ssh_command"]
    assert "id" in cmds
