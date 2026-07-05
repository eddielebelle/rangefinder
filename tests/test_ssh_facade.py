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


def _serve_and(cfg, fn):
    """Start the SSH facade on a free port and run a sync fn(port) in an executor thread (so its
    internal asyncio.run / blocking sockets don't collide with the facade's event loop)."""
    async def go():
        ctx, _sink = make_ctx()
        port = _free_port()
        facade = SshFacade.from_config(cfg, ctx)
        facade.bind_host = "127.0.0.1"
        facade.port = port
        await facade.start()
        try:
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(None, lambda: fn(port))
        finally:
            await facade.stop()

    return asyncio.run(go())


def test_facade_advertises_captured_algorithms():
    """The twin advertises the captured KEX/MAC/host-key algorithms, not asyncssh's defaults —
    so a real host's weak-crypto exposure (and RSA host key) carries through to ssh-audit."""
    from rangefinder.capture.ssh import _read_kexinit

    cfg = SshConfig(port=22, kex_algs=["diffie-hellman-group14-sha1", "curve25519-sha256"],
                    host_key_algs=["ssh-rsa", "rsa-sha2-256"], mac_algs=["hmac-sha1", "hmac-sha2-256"])
    _, kex = _serve_and(cfg, lambda p: _read_kexinit("127.0.0.1", p, 5.0))
    assert "diffie-hellman-group14-sha1" in kex["kex"]        # weak KEX reproduced
    assert "hmac-sha1" in kex["mac_s2c"]                       # weak MAC reproduced
    assert any("rsa" in a for a in kex["host_key"])            # RSA host key advertised
    assert not any("ed25519" in a for a in kex["host_key"])    # not the default ed25519


def test_facade_gates_password_auth():
    """auth_methods pins which auth the twin offers: a captured pubkey-only host must not present
    a password (or keyboard-interactive) brute-force surface it doesn't have."""
    from rangefinder.capture.ssh import _probe_auth_methods

    pubkey_only = _serve_and(SshConfig(port=22, auth_methods=["publickey"]),
                             lambda p: _probe_auth_methods("127.0.0.1", p, 5.0))
    assert pubkey_only == ["publickey"]

    with_pw = _serve_and(SshConfig(port=22, auth_methods=["publickey", "password"]),
                         lambda p: _probe_auth_methods("127.0.0.1", p, 5.0))
    assert "password" in with_pw


def test_capture_measures_ssh_posture():
    from rangefinder.capture.ssh import capture_ssh

    cfg = SshConfig(port=22, kex_algs=["diffie-hellman-group14-sha1", "curve25519-sha256"],
                    host_key_algs=["ssh-rsa"], mac_algs=["hmac-sha1", "hmac-sha2-256"],
                    auth_methods=["publickey"])
    service, _warnings, report = _serve_and(cfg, lambda p: capture_ssh("127.0.0.1", p, timeout=5.0))
    assert "diffie-hellman-group14-sha1" in service["kex_algs"]
    assert service["auth_methods"] == ["publickey"]
    status = {i.field: (i.status, i.value) for i in report.items}
    assert status["weak_algorithms"][0] == "measured"
    assert "hmac-sha1" in status["weak_algorithms"][1]


def test_verify_ssh_round_trips():
    from rangefinder.verify import verify_ssh

    cfg = SshConfig(port=22, kex_algs=["diffie-hellman-group14-sha1", "curve25519-sha256"],
                    host_key_algs=["ssh-rsa", "rsa-sha2-256"], mac_algs=["hmac-sha1", "hmac-sha2-256"],
                    auth_methods=["publickey"])
    report = _serve_and(cfg, lambda p: verify_ssh("127.0.0.1", p, timeout=6.0))
    assert report.total >= 3
    assert report.matched == report.total, [(d.key, d.detail) for d in report.divergences]
    assert not any(d.kind == "posture" for d in report.divergences)


def test_capture_unreachable_host_fails_closed_to_pubkey_only():
    """A host we couldn't measure at all (unreachable) must not leave auth_methods unset — that
    would fall back to the password-advertising default and fabricate a brute-force surface."""
    from rangefinder.capture.ssh import capture_ssh

    port = _free_port()  # nothing is listening here
    service, _warnings, _report = capture_ssh("127.0.0.1", port, timeout=1.0)
    assert service["auth_methods"] == ["publickey"]   # fail-closed, no fabricated password auth
    assert "kex_algs" not in service                   # nothing measured


def test_accept_creds_login_works_even_when_auth_methods_pubkey_only():
    """An authored login point (accept_creds) is a deliberate objective, so the password path stays
    open even on a captured pubkey-only host — the auth gate must not silently kill it."""
    async def client(port):
        import asyncssh

        async with asyncssh.connect(
            "127.0.0.1", port, username="admin", password="s3cret",
            known_hosts=None, client_keys=None, preferred_auth=["password"],
        ) as conn:
            r = await conn.run(input="whoami\nexit\n")
            return r.stdout

    async def go():
        return await _run(
            SshConfig(port=22, accept_creds={"admin": "s3cret"}, auth_methods=["publickey"]), client)

    _output, sink = asyncio.run(go())
    assert any(e["event"]["action"] == "ssh_auth" and e["event"]["outcome"] == "success"
               for e in sink.events)


def test_kexinit_parser_rejects_malformed_packets():
    import io
    import struct

    import pytest

    from rangefinder.capture.ssh import _parse_kexinit, _read_packet

    # padding-length byte larger than the packet body -> clean rejection, not a negative slice
    f = io.BytesIO(struct.pack(">I", 3) + bytes([250, 1, 2]))
    with pytest.raises(ValueError):
        _read_packet(f)
    # a name-list claiming more bytes than remain -> clean rejection, not an out-of-range read
    with pytest.raises(ValueError):
        _parse_kexinit(bytes([20]) + b"\x00" * 16 + struct.pack(">I", 100))
