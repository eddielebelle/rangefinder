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
        # Host keys of the captured type(s) — the key type is what determines the host-key
        # algorithms advertised in KEXINIT (a real host on ssh-rsa reads as ssh-rsa, not ed25519).
        host_keys = _host_keys(self.cfg.host_key_algs)
        self._host_key = host_keys[0]
        server_version = self.cfg.server_version.removeprefix("SSH-2.0-")

        # Reproduce the captured algorithm posture where measured; asyncssh's modern defaults stand
        # in (fail-closed) where it wasn't. Each captured list is filtered to what asyncssh can
        # actually serve — dropping KEXINIT extension markers (ext-info-s, kex-strict-*) and any
        # algorithm asyncssh doesn't implement (fail-closed: under-advertise, never crash/fabricate).
        alg_kwargs: dict = {}
        for cfg_list, kind, kwarg in (
            (self.cfg.kex_algs, "kex", "kex_algs"),
            (self.cfg.encryption_algs, "encryption", "encryption_algs"),
            (self.cfg.mac_algs, "mac", "mac_algs"),
            (self.cfg.host_key_algs, "sig", "signature_algs"),
        ):
            if cfg_list:
                algs = _serviceable(kind, cfg_list)
                if algs:
                    alg_kwargs[kwarg] = algs

        # Subclass asyncssh.SSHServer lazily (kept out of module import so the CLI does
        # not pay the asyncssh import unless an SSH host actually runs).
        server_factory = _make_server_factory(self)

        self._server = await asyncssh.listen(
            self.bind_host,
            self.port,
            server_factory=server_factory,
            server_host_keys=host_keys,
            server_version=server_version,
            process_factory=self._shell,
            login_timeout=20,
            **alg_kwargs,
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


# Host-key / signature algorithm -> the asyncssh key type whose presence advertises it. Multiple
# algorithms (ssh-rsa / rsa-sha2-*) map to one key; we generate one key per distinct type.
_HOSTKEY_TYPE = {
    "ssh-ed25519": "ssh-ed25519",
    "ssh-rsa": "ssh-rsa", "rsa-sha2-256": "ssh-rsa", "rsa-sha2-512": "ssh-rsa",
    "ecdsa-sha2-nistp256": "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384": "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521": "ecdsa-sha2-nistp521",
    "ssh-dss": "ssh-dss",
}


def _serviceable(kind: str, algs: list[str]) -> list[str]:
    """Keep only algorithms asyncssh can serve, preserving order. Drops KEXINIT extension markers
    (ext-info-s, kex-strict-*) and anything asyncssh doesn't implement."""
    import asyncssh.encryption
    import asyncssh.kex
    import asyncssh.mac
    import asyncssh.public_key

    getter = {
        "kex": asyncssh.kex.get_kex_algs,
        "encryption": asyncssh.encryption.get_encryption_algs,
        "mac": asyncssh.mac.get_mac_algs,
        "sig": asyncssh.public_key.get_public_key_algs,
    }[kind]
    ok = {a.decode() if isinstance(a, bytes) else a for a in getter()}
    return [a for a in algs if a in ok]


def _host_keys(host_key_algs: list[str] | None):
    """Generate host keys matching the captured host-key algorithms (ed25519 by default). The key
    *type* is what makes asyncssh advertise that host-key algorithm in KEXINIT."""
    import asyncssh

    if not host_key_algs:
        return [asyncssh.generate_private_key("ssh-ed25519")]
    keytypes: list[str] = []
    for alg in host_key_algs:
        kt = _HOSTKEY_TYPE.get(alg)
        if kt and kt not in keytypes:
            keytypes.append(kt)
    keys = []
    for kt in keytypes:
        try:
            keys.append(asyncssh.generate_private_key(kt))
        except Exception:
            pass  # asyncssh can't generate this type -> skip it (fail-closed: don't fabricate)
    return keys or [asyncssh.generate_private_key("ssh-ed25519")]


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
            # An authored login point (accept_creds) always needs the password path, even on a
            # captured pubkey-only host — the planted credential is a deliberate objective, not a
            # measurement gap. Otherwise gate on the measured methods.
            if facade.cfg.accept_creds:
                return True
            methods = facade.cfg.auth_methods
            return "password" in methods if methods is not None else True

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
            methods = facade.cfg.auth_methods
            return "publickey" in methods if methods is not None else True

        def kbdint_auth_supported(self) -> bool:
            # asyncssh offers keyboard-interactive as a password path; gate it on the measured
            # methods so a captured pubkey-only host doesn't advertise a password surface via kbdint.
            methods = facade.cfg.auth_methods
            return "keyboard-interactive" in methods if methods is not None else False

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
