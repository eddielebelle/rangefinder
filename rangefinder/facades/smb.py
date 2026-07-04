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
import hashlib
import logging
import os
import re
import shutil
import struct
import tempfile
import threading
import time
import uuid

from rangefinder.config.services import SmbConfig, SmbShare
from rangefinder.facades.base import Facade, FacadeContext
from rangefinder.facades.registry import register
from rangefinder.telemetry import event as ev

# Attach at the top "impacket" logger: connection/auth records come from
# impacket.smbserver (child, propagates up) while NetrShareEnum is logged on "impacket"
# itself, so only the root of the tree sees both.
_LOGGER_NAME = "impacket"

# SMB2 dialect wire values (stable protocol constants; hardcoded so the config layer never
# imports impacket). impacket's SimpleSMBServer hardcodes the 2.0.2 negotiate ceiling, an
# identical b'A'*16 ServerGuid on every host, and SystemTime == ServerStartTime (so the box
# looks freshly booted at every negotiate) — all three are obvious emulation tells. The
# negotiate realism hook below overwrites them per host.
_DIALECTS = {"2.0.2": 0x0202, "2.1": 0x0210, "3.0": 0x0300, "3.1.1": 0x0311}
_DIALECT_311 = 0x0311

# SMB2 negotiate-context types + capability values (MS-SMB2 2.2.3.1 / 2.2.4). A 3.1.1
# negotiate response MUST carry a preauth-integrity context or clients reject it; encryption
# and signing contexts are what nmap's smb2-capabilities reads to report a modern service.
_CTX_PREAUTH_INTEGRITY = 0x0001
_CTX_ENCRYPTION = 0x0002
_CTX_SIGNING = 0x0008
_HASH_SHA512 = 0x0001
_CIPHER_AES128_GCM = 0x0002
_SIGNALG_AES_CMAC = 0x0001


def _pack_negotiate_contexts() -> tuple[int, bytes]:
    """Build the negotiate-context list for a 3.1.1 response -> (count, 8-byte-aligned bytes).

    Advertises SHA-512 preauth integrity (mandatory, with a fresh 32-byte salt), AES-128-GCM
    encryption, and AES-CMAC signing — the profile a modern Windows 3.1.1 server presents.
    Each SMB2_NEGOTIATE_CONTEXT is ContextType(2) DataLength(2) Reserved(4) then Data, and
    every context after the first starts on an 8-byte boundary relative to the list start.
    """
    preauth = struct.pack("<HHH", 1, 32, _HASH_SHA512) + os.urandom(32)
    encryption = struct.pack("<HH", 1, _CIPHER_AES128_GCM)
    signing = struct.pack("<HH", 1, _SIGNALG_AES_CMAC)
    contexts = [
        (_CTX_PREAUTH_INTEGRITY, preauth),
        (_CTX_ENCRYPTION, encryption),
        (_CTX_SIGNING, signing),
    ]
    out = bytearray()
    for i, (ctype, data) in enumerate(contexts):
        if i:
            out += b"\x00" * ((8 - len(out) % 8) % 8)  # align each context start to 8 bytes
        out += struct.pack("<HHL", ctype, len(data), 0) + data
    return len(contexts), bytes(out)


def _attach_negotiate_contexts(cmd) -> None:
    """Populate a SMB2Negotiate_Response with a 3.1.1 negotiate-context list.

    The context list begins on an 8-byte boundary after the security buffer; NegotiateContext
    Offset is measured from the start of the SMB2 header (the security buffer sits at 0x80).
    """
    count, ctx_bytes = _pack_negotiate_contexts()
    sec_end = int(cmd["SecurityBufferOffset"]) + int(cmd["SecurityBufferLength"])
    neg_offset = (sec_end + 7) & ~7
    cmd["NegotiateContextCount"] = count
    cmd["NegotiateContextOffset"] = neg_offset
    cmd["Padding"] = b"\x00" * (neg_offset - sec_end)
    cmd["NegotiateContextList"] = ctx_bytes


def _server_identity(host_name: str) -> tuple[bytes, int]:
    """Return a stable per-host ``(server_guid_16b, uptime_offset_seconds)``.

    Derived from the host name so it is unique per host yet identical across restarts of the
    same host — exactly how a real machine's SMB ServerGUID behaves (it persists across
    reboots). The uptime offset backdates the apparent boot time by 1h–45d so a container
    that started seconds ago still reports a plausible multi-day uptime.
    """
    h = hashlib.sha256(("rangefinder-smb-guid:" + host_name).encode()).digest()
    guid = h[:16]
    uptime = 3600 + int.from_bytes(h[16:20], "big") % (45 * 86400)
    return guid, uptime


# A real file server's files carry mtimes spread across months/years. impacket serves each
# backing file's real filesystem mtime, so writing them all at container start leaves every
# file (and directory) stamped with one identical timestamp — a glaring "this whole estate was
# provisioned moments ago" tell. Spread each file across 7 days–3 years before now, hashed from
# host + path so it's unique per file and stable per host.
_MTIME_MIN = 7 * 86400
_MTIME_SPAN = 3 * 365 * 86400 - _MTIME_MIN


def _backdated_mtime(host_name: str, key: str) -> float:
    h = int(hashlib.sha256(f"rangefinder-mtime:{host_name}:{key}".encode()).hexdigest(), 16)
    return time.time() - (_MTIME_MIN + h % _MTIME_SPAN)


def _select_dialect(smb2, recv_packet, is_smb1: bool, ceiling: int) -> int | None:
    """Highest dialect the client offered that we support and is <= ceiling, else None.

    None means "leave impacket's default (2.0.2)": either an SMB1 negotiate (which only ever
    reaches 2.0.2 in impacket) or a client whose offers don't intersect our ladder. Parsing
    honours DialectCount so the negotiate-context bytes trailing a 3.1.1 request are not
    misread as bogus dialects.
    """
    if is_smb1:
        return None
    try:
        neg = smb2.SMB2Negotiate(recv_packet["Data"])
        count = int(neg["DialectCount"])
        offered = list(neg["Dialects"])[:count]
    except Exception:
        return None
    supported = set(_DIALECTS.values())
    candidates = [d for d in offered if d in supported and d <= ceiling]
    return max(candidates) if candidates else None


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
        # Per-host stable SMB identity; boot epoch is fixed once at start() so SystemTime
        # advances while ServerStartTime stays put (real uptime), not "booted this instant".
        self._server_guid, self._uptime_offset = _server_identity(ctx.host_name)
        self._boot_epoch: float | None = None

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
        # Per-connection handler threads must be daemons: otherwise server_close() joins
        # them at shutdown and a stuck/unclosed client connection would hang stop() forever.
        inner.daemon_threads = True
        # No public setters for these; they populate the negotiate/session response that
        # nmap smb-os-discovery reads.
        inner._SMBSERVER__serverOS = self.cfg.server_os
        inner._SMBSERVER__serverName = self.ctx.host_name.upper()
        self._boot_epoch = time.time() - self._uptime_offset
        self._install_negotiate_realism(inner)

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

    # ---- negotiate realism -------------------------------------------------------
    def _install_negotiate_realism(self, inner) -> None:
        """Hook SMB2_NEGOTIATE to fix impacket's hardcoded emulation tells.

        Overwrites the response with (1) this host's stable ServerGuid, (2) a fixed past
        ServerStartTime + live SystemTime, (3) the highest common dialect up to the configured
        ceiling, and (4) — when 3.1.1 is negotiated — the mandatory preauth-integrity plus
        encryption/signing negotiate contexts, so recon tooling sees a modern service. Wraps
        rather than replaces the original handler so impacket's session-blob construction is
        preserved.

        Signing note: impacket's server signs with HMAC-SHA256 (the 2.x algorithm), so it
        cannot honour the AES-CMAC signing a real 3.1.1 client would use. We therefore leave
        SecurityMode at "enabled, not required" for 3.1.1 (a signed/credentialed session is a
        deeper tier we don't implement); ``signing_required`` still applies to <=3.0.
        """
        from impacket import smb3structs as smb2
        from impacket.smb import POSIXtoFT

        original = inner.hookSmb2Command(smb2.SMB2_NEGOTIATE, None)
        ceiling = _DIALECTS[self.cfg.max_dialect]
        guid = self._server_guid

        def _hook(conn_id, smb_server, recv_packet, is_smb1=False):
            result = original(conn_id, smb_server, recv_packet, is_smb1)
            try:
                cmd = result[1][0]["Data"]
                cmd["ServerGuid"] = guid
                now = int(time.time())
                cmd["SystemTime"] = POSIXtoFT(now)
                cmd["ServerStartTime"] = POSIXtoFT(int(self._boot_epoch or now))
                chosen = _select_dialect(smb2, recv_packet, is_smb1, ceiling)
                if chosen is not None:
                    cmd["DialectRevision"] = chosen
                if chosen == _DIALECT_311:
                    cmd["SecurityMode"] = 0x1  # ENABLED only (see signing note above)
                    _attach_negotiate_contexts(cmd)
                else:
                    cmd["SecurityMode"] = 0x3 if self.cfg.signing_required else 0x1
            except Exception:
                # Never let a realism tweak break the handshake — fall back to impacket's
                # (working, if less convincing) response.
                pass
            return result

        inner.hookSmb2Command(smb2.SMB2_NEGOTIATE, _hook)

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
            # Backdate the file (before chmod, while still owner-writable) so it doesn't read
            # as freshly provisioned. Key on the logical share path, not the random temp root,
            # so the age is stable per host across restarts.
            mt = _backdated_mtime(self.ctx.host_name, f"{share.name}/{rel}")
            os.utime(full, (mt, mt))
            if share.readonly:
                os.chmod(full, 0o444)  # advisory only
        # Directory mtimes: a real directory's mtime tracks its newest entry. Walk bottom-up
        # so children are already stamped, then set each dir to its newest child (or its own
        # backdated time when empty) — otherwise every dir keeps the "created just now" mtime.
        for dirpath, dirnames, filenames in os.walk(share_dir, topdown=False):
            children = [os.path.join(dirpath, n) for n in dirnames + filenames]
            newest = (max(os.stat(c).st_mtime for c in children) if children
                      else _backdated_mtime(self.ctx.host_name, os.path.relpath(dirpath, self._root)))
            os.utime(dirpath, (newest, newest))
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
