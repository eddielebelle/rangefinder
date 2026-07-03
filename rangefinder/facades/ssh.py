"""Real SSH facade backed by asyncssh.

Unlike the banner SSH decoy, this performs a genuine SSH key exchange, so clients get
past the version string into authentication — where every attempted username/password (and
public-key fingerprint) is captured as telemetry and then rejected. With ``accept_creds``
set, matching logins are accepted and dropped into a minimal fake shell that captures the
commands typed. asyncssh is asyncio-native, so the server runs directly on the host event
loop (no thread).

Deliberate limits: the shell is a decoy — it does not execute anything, just captures
commands and replies "command not found". No SFTP, port forwarding, or real filesystem.
"""

from __future__ import annotations

import asyncio
import logging
import uuid

from rangefinder.config.services import SshConfig
from rangefinder.facades.base import Facade, FacadeContext
from rangefinder.facades.registry import register
from rangefinder.telemetry import event as ev


@register("ssh")
class SshFacade(Facade):
    def __init__(self, *, cfg: SshConfig, ctx: FacadeContext, service_id: str):
        super().__init__(
            bind_host=cfg.bind, port=cfg.port, ctx=ctx, service_id=service_id, protocol="ssh"
        )
        self.cfg = cfg
        self._server = None
        self._host_key = None
        self._stopped: asyncio.Future | None = None
        # id(connection) -> {conn_id, src_ip, src_port}; lets the shell correlate to the
        # connection that authenticated.
        self._conns: dict[int, dict] = {}

    @classmethod
    def from_config(cls, cfg: SshConfig, ctx: FacadeContext) -> "SshFacade":
        return cls(cfg=cfg, ctx=ctx, service_id=f"ssh-{cfg.port}")

    async def handle(self, scope, reader, writer) -> None:
        raise NotImplementedError  # asyncssh owns the transport

    async def start(self) -> None:
        import asyncssh

        logging.getLogger("asyncssh").setLevel(logging.CRITICAL)
        self._host_key = asyncssh.generate_private_key("ssh-ed25519")
        server_version = self.cfg.server_version.removeprefix("SSH-2.0-")

        # Subclass asyncssh.SSHServer lazily (kept out of module import so the CLI does
        # not pay the asyncssh import unless an SSH host actually runs).
        server_factory = _make_server_factory(self)

        self._server = await asyncssh.listen(
            self.bind_host,
            self.port,
            server_factory=server_factory,
            server_host_keys=[self._host_key],
            server_version=server_version,
            process_factory=self._shell,
            login_timeout=20,
        )
        self.ctx.emitter.emit(ev.service_listen(self))

    async def serve_forever(self) -> None:
        self._stopped = asyncio.get_running_loop().create_future()
        try:
            await self._stopped
        except asyncio.CancelledError:
            pass

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            try:
                await self._server.wait_closed()
            except Exception:
                pass
        if self._stopped is not None and not self._stopped.done():
            self._stopped.set_result(None)

    def _info(self, conn) -> dict:
        return self._conns.get(id(conn), {})

    async def _shell(self, process) -> None:
        conn = process.get_extra_info("connection")
        info = self._conns.get(id(conn), {})
        user = process.get_extra_info("username") or "user"

        def capture(command: str) -> None:
            self.ctx.emitter.emit(
                ev.ssh_command(
                    self,
                    src_ip=info.get("src_ip"),
                    src_port=info.get("src_port"),
                    conn_id=info.get("conn_id"),
                    username=user,
                    command=command,
                )
            )

        # Non-interactive: `ssh host "cmd"` carries the command out-of-band.
        if process.command:
            capture(process.command)
            process.stdout.write(f"-bash: {process.command}: command not found\r\n")
            process.exit(127)
            return

        host = self.ctx.host_name.lower()
        prompt = f"{user}@{host}:~$ "
        if self.cfg.motd:
            process.stdout.write(self.cfg.motd.replace("\n", "\r\n") + "\r\n")
        process.stdout.write(prompt)
        try:
            async for line in process.stdin:
                cmd = line.strip()
                if not cmd:
                    process.stdout.write(prompt)
                    continue
                capture(cmd)
                if cmd in ("exit", "logout"):
                    break
                process.stdout.write(f"-bash: {cmd}: command not found\r\n{prompt}")
        except Exception:
            pass
        process.exit(0)


def _make_server_factory(facade: SshFacade):
    """Build a per-connection asyncssh.SSHServer subclass bound to *facade*."""
    import asyncssh

    class _CaptureServer(asyncssh.SSHServer):
        def __init__(self):
            self.conn = None
            self.info: dict = {}

        def connection_made(self, conn) -> None:
            self.conn = conn
            peer = conn.get_extra_info("peername")
            src_ip, src_port = (peer[0], peer[1]) if peer else (None, None)
            self.info = {"conn_id": uuid.uuid4().hex, "src_ip": src_ip, "src_port": src_port}
            facade._conns[id(conn)] = self.info
            facade.ctx.emitter.emit(ev.ssh_connection(facade, "connection_open", **self.info))

        def connection_lost(self, exc) -> None:
            if self.conn is not None:
                facade._conns.pop(id(self.conn), None)
            facade.ctx.emitter.emit(ev.ssh_connection(facade, "connection_close", **self.info))

        def begin_auth(self, username: str) -> bool:
            return True  # always require auth

        def password_auth_supported(self) -> bool:
            return True

        def validate_password(self, username: str, password: str) -> bool:
            accepted = facade.cfg.accept_creds.get(username) == password
            facade.ctx.emitter.emit(
                ev.ssh_auth(
                    facade,
                    **self.info,
                    username=username,
                    method="password",
                    credential=password,
                    outcome="success" if accepted else "failure",
                )
            )
            return accepted

        def public_key_auth_supported(self) -> bool:
            return True

        def validate_public_key(self, username: str, key) -> bool:
            try:
                fp = key.get_fingerprint()
            except Exception:
                fp = None
            facade.ctx.emitter.emit(
                ev.ssh_auth(
                    facade,
                    **self.info,
                    username=username,
                    method="publickey",
                    credential=fp,
                    outcome="failure",
                )
            )
            return False  # never accept keys; push clients to password so we capture it

    return _CaptureServer
