"""SMB facade backed by impacket's SMB server.

Rather than hand-rolling SMB2 + NTLM + DCE/RPC + SRVSVC, this drives impacket's
``SimpleSMBServer`` config-driven: each configured share is materialized as a backing
directory of files, so ``smbclient -L`` / ``enum4linux`` list the shares AND read the
planted files, and NTLM authentication attempts are captured as telemetry.

impacket's server is a blocking threaded socketserver, so the facade runs it on a daemon
thread and bridges lifecycle to the asyncio supervisor. Telemetry is derived by attaching
a logging handler to impacket's server logger and translating its records into ECS events
(the log stream is otherwise suppressed so it never pollutes the JSON telemetry on stdout).

Deliberate limits: `readonly` is advisory (not enforced); one SMB facade per host is
assumed (the log handler is process-wide). It renders shares for enumeration; it is not a
hardened file server.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import shutil
import tempfile
import threading
import uuid

from rangefinder.config.services import SmbConfig, SmbShare
from rangefinder.facades.base import Facade, FacadeContext
from rangefinder.facades.registry import register
from rangefinder.telemetry import event as ev

# Attach at the top "impacket" logger: connection/auth records come from
# impacket.smbserver (child, propagates up) while NetrShareEnum is logged on "impacket"
# itself, so only the root of the tree sees both.
_LOGGER_NAME = "impacket"


@register("smb")
class SmbFacade(Facade):
    def __init__(self, *, cfg: SmbConfig, ctx: FacadeContext, service_id: str):
        super().__init__(
            bind_host=cfg.bind, port=cfg.port, ctx=ctx, service_id=service_id, protocol="smb"
        )
        self.cfg = cfg
        self._srv = None
        self._inner = None
        self._thread: threading.Thread | None = None
        self._root: str | None = None
        self._handler: logging.Handler | None = None
        self._stopped: asyncio.Future | None = None

    @classmethod
    def from_config(cls, cfg: SmbConfig, ctx: FacadeContext) -> "SmbFacade":
        return cls(cfg=cfg, ctx=ctx, service_id=f"smb-{cfg.port}")

    async def handle(self, scope, reader, writer) -> None:
        # Never used: impacket owns the sockets, so start/serve_forever/stop are
        # overridden and the base asyncio connection path is bypassed.
        raise NotImplementedError

    async def start(self) -> None:
        # Lazy import: impacket is heavy, so only pay for it when an SMB host runs.
        from impacket import smbserver

        self._root = tempfile.mkdtemp(prefix="rangefinder-smb-")
        srv = smbserver.SimpleSMBServer(listenAddress=self.bind_host, listenPort=self.port)
        srv.setSMB2Support(True)

        inner = srv.getServer()
        # No public setters for these; they populate the negotiate/session response that
        # nmap smb-os-discovery reads.
        inner._SMBSERVER__serverOS = self.cfg.server_os
        inner._SMBSERVER__serverName = self.ctx.host_name.upper()

        for share in self.cfg.shares:
            path = self._materialize(share)
            srv.addShare(share.name, path, share.comment)

        # NTLM validation: register each identities account's NT hash. impacket then
        # validates authenticated logons (pass-the-hash succeeds with the right hash, wrong
        # hash fails) while null-session enumeration still works.
        ids = self.ctx.identities
        if ids:
            from binascii import hexlify

            from impacket.ntlm import compute_nthash

            for u in ids.users:
                if u.password:
                    srv.addCredential(u.sam, 0, "", hexlify(compute_nthash(u.password)).decode())

        self._install_telemetry()

        self._srv = srv
        self._inner = inner
        self._thread = threading.Thread(target=srv.start, name=self.service_id, daemon=True)
        self._thread.start()
        self.ctx.emitter.emit(ev.service_listen(self))

    async def serve_forever(self) -> None:
        self._stopped = asyncio.get_running_loop().create_future()
        try:
            await self._stopped
        except asyncio.CancelledError:
            pass

    async def stop(self) -> None:
        if self._inner is not None:
            try:
                self._inner.shutdown()  # breaks serve_forever (server_close alone won't)
                self._inner.server_close()
            except Exception:
                pass
        if self._thread is not None:
            self._thread.join(timeout=3)
        self._remove_telemetry()
        if self._root and os.path.isdir(self._root):
            shutil.rmtree(self._root, ignore_errors=True)
        if self._stopped is not None and not self._stopped.done():
            self._stopped.set_result(None)

    # ---- backing files ----------------------------------------------------------
    def _materialize(self, share: SmbShare) -> str:
        assert self._root is not None
        share_dir = os.path.join(self._root, share.name)
        os.makedirs(share_dir, exist_ok=True)
        for rel, content in share.files.items():
            full = os.path.normpath(os.path.join(share_dir, rel))
            # Refuse path traversal out of the share directory.
            if not full.startswith(os.path.abspath(share_dir) + os.sep) and full != share_dir:
                if not full.startswith(share_dir + os.sep):
                    continue
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "w", encoding="utf-8") as fh:
                fh.write(content)
            if share.readonly:
                os.chmod(full, 0o444)  # advisory only
        return share_dir

    # ---- telemetry from impacket's log stream ------------------------------------
    def _install_telemetry(self) -> None:
        logger = logging.getLogger(_LOGGER_NAME)
        logger.setLevel(logging.INFO)
        # Stop impacket records bubbling to the root logger (keeps its formatted output
        # off stdout, where it would pollute the JSON telemetry stream).
        logger.propagate = False
        self._handler = _SmbTelemetryHandler(self)
        logger.addHandler(self._handler)

    def _remove_telemetry(self) -> None:
        if self._handler is not None:
            logger = logging.getLogger(_LOGGER_NAME)
            logger.removeHandler(self._handler)
            logger.propagate = True
            self._handler = None


class _SmbTelemetryHandler(logging.Handler):
    """Translates impacket smbserver log records into ECS telemetry events.

    impacket serves each connection on its own thread, so the thread id correlates a
    connection's records (open -> auth -> tree connect -> file access -> close).
    """

    def __init__(self, facade: SmbFacade):
        super().__init__(level=logging.INFO)
        self.facade = facade
        self._conns: dict[int, dict] = {}  # thread id -> {ip, port, conn_id}

    def emit(self, record: logging.LogRecord) -> None:  # noqa: A003 (logging API)
        try:
            self._translate(record.getMessage(), record.thread)
        except Exception:
            pass

    def _emit(self, action, *, category, etype, tid, kind="event", outcome="unknown", extra=None):
        conn = self._conns.get(tid, {})
        self.facade.ctx.emitter.emit(
            ev.smb_event(
                self.facade,
                action,
                category=category,
                etype=etype,
                kind=kind,
                outcome=outcome,
                src_ip=conn.get("ip"),
                src_port=conn.get("port"),
                conn_id=conn.get("conn_id"),
                extra=extra,
            )
        )

    def _translate(self, msg: str, tid: int) -> None:
        m = re.search(r"Incoming connection \(([^,]+),(\d+)\)", msg)
        if m:
            self._conns[tid] = {"ip": m.group(1), "port": int(m.group(2)), "conn_id": uuid.uuid4().hex}
            self._emit(
                "connection_open", category=["network"], etype=["connection", "start"],
                tid=tid, outcome="success",
            )
            return

        m = re.search(r"AUTHENTICATE_MESSAGE \((.*?)\\(.*?),(.*?)\)", msg)
        if m:
            # Record the attempt; the outcome is emitted on the following success line or on
            # connection close (a failed logon never logs "authenticated successfully").
            domain, user, workstation = m.group(1), m.group(2), m.group(3)
            conn = self._conns.setdefault(tid, {})
            conn["pending_auth"] = {
                "domain": domain or None,
                "user": user or None,
                "workstation": workstation or None,
                "method": "anonymous" if not user else "ntlm",
            }
            return

        if "authenticated successfully" in msg:
            self._flush_auth(tid, "success")
            return

        m = re.search(r"NetrShareEnum", msg)
        if m:
            self._emit("smb_share_enum", category=["network"], etype=["access"], tid=tid, outcome="success")
            return

        m = re.search(r"Connecting Share\(\d+:(.+)\)", msg)
        if m and m.group(1) != "IPC$":
            self._emit(
                "smb_tree_connect", category=["network"], etype=["access"], tid=tid,
                outcome="success", extra={"smb": {"share": m.group(1)}},
            )
            return

        m = re.search(r"smb2(?:Create|Read): (.+)", msg)
        if m:
            target = m.group(1)
            if target not in ("srvsvc", "wkssvc", "lsarpc", "samr") and not target.endswith(("/.", "/..")):
                self._emit(
                    "smb_file_access", category=["file"], etype=["access"], tid=tid,
                    outcome="success", extra={"smb": {"path": os.path.basename(target.rstrip("/")) or target}},
                )
            return

        m = re.search(r"Closing down connection \(([^,]+),(\d+)\)", msg)
        if m:
            self._flush_auth(tid, "failure")  # an unconfirmed auth attempt = a failed logon
            self._emit("connection_close", category=["network"], etype=["connection", "end"], tid=tid, outcome="success")
            self._conns.pop(tid, None)
            return

    def _flush_auth(self, tid: int, outcome: str) -> None:
        conn = self._conns.get(tid)
        if not conn or "pending_auth" not in conn:
            return
        auth = conn.pop("pending_auth")
        # An anonymous/null bind that never "authenticated successfully" on close is normal
        # enumeration, not a failed logon — don't cry wolf.
        if outcome == "failure" and auth["method"] == "anonymous":
            return
        self._emit(
            "smb_auth", category=["authentication"], etype=["start"], tid=tid,
            kind="alert" if outcome == "failure" else "event",
            outcome=outcome, extra={"auth": auth},
        )
