import asyncio
import socket
import struct

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


def test_pass_the_hash_validation():
    from binascii import hexlify
    from dataclasses import replace

    from impacket.ntlm import compute_nthash

    from rangefinder.config.model import ADUser, Identities

    good = hexlify(compute_nthash("Autumn2025!")).decode()

    def client(port, nthash):
        from impacket.smbconnection import SMBConnection

        c = None
        try:
            c = SMBConnection("127.0.0.1", "127.0.0.1", sess_port=port)
            c.login("svc-web", "", "acme.corp", nthash=nthash)
            return True
        except Exception:
            return False
        finally:
            if c is not None:
                try:
                    c.close()  # close even on failure so the server logs the disconnect
                except Exception:
                    pass

    async def run():
        ctx, sink = make_ctx()
        ctx = replace(ctx, identities=Identities(
            domain="acme.corp", users=[ADUser(sam="svc-web", password="Autumn2025!")]))
        port = _free_port()
        cfg = SmbConfig(port=port, shares=[SmbShare(name="PUBLIC", files={"a.txt": "x"})])
        facade = SmbFacade.from_config(cfg, ctx)
        facade.bind_host = "127.0.0.1"
        facade.port = port
        await facade.start()
        try:
            loop = asyncio.get_running_loop()
            ok = await loop.run_in_executor(None, client, port, good)
            bad = await loop.run_in_executor(None, client, port, "00" * 16)
        finally:
            await facade.stop()
        return ok, bad, sink

    ok, bad, sink = asyncio.run(run())
    assert ok is True    # pass-the-hash with the right NT hash succeeds
    assert bad is False  # wrong hash is rejected
    outcomes = {(e["rangefinder"]["auth"]["user"], e["event"]["outcome"])
                for e in sink.events if e["event"]["action"] == "smb_auth"}
    assert ("svc-web", "success") in outcomes
    assert ("svc-web", "failure") in outcomes


# --------------------------------------------------------------- negotiate realism

def _raw_negotiate(port: int, dialects: list[int]):
    """Send a real SMB2 NEGOTIATE offering ``dialects`` and return the parsed response.

    Bypasses impacket's client (which defaults to an SMB1 negotiate that only reaches 2.0.2)
    so we can inspect the server's dialect choice, ServerGuid and timestamps directly.
    """
    import struct

    from impacket import smb3structs as smb2

    pkt = smb2.SMB2Packet()
    pkt["Command"] = smb2.SMB2_NEGOTIATE
    neg = smb2.SMB2Negotiate()
    neg["DialectCount"] = len(dialects)
    neg["SecurityMode"] = 1
    neg["Capabilities"] = 0
    neg["ClientGuid"] = b"\x11" * 16
    neg["Dialects"] = dialects
    pkt["Data"] = neg
    body = pkt.getData()

    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    try:
        s.sendall(struct.pack(">I", len(body)) + body)
        ln = struct.unpack(">I", s.recv(4))[0]
        buf = b""
        while len(buf) < ln:
            buf += s.recv(ln - len(buf))
    finally:
        s.close()
    resp_pkt = smb2.SMB2Packet(buf)
    return smb2.SMB2Negotiate_Response(resp_pkt["Data"])


def _serve(cfg, hostname="fs01"):
    from dataclasses import replace

    ctx, _ = make_ctx()
    ctx = replace(ctx, host_name=hostname)
    facade = SmbFacade.from_config(cfg, ctx)
    facade.bind_host = "127.0.0.1"
    facade.port = cfg.port
    return facade


def test_negotiate_realism_guid_time_dialect():
    import time

    from rangefinder.facades.smb import _server_identity

    async def run():
        cfg = SmbConfig(port=_free_port(), max_dialect="3.0",
                        shares=[SmbShare(name="Data", files={"a.txt": "x"})])
        facade = _serve(cfg, "fs01")
        await facade.start()
        try:
            loop = asyncio.get_running_loop()
            full_ladder = [0x0202, 0x0210, 0x0300, 0x0302, 0x0311]
            return await loop.run_in_executor(None, _raw_negotiate, cfg.port, full_ladder)
        finally:
            await facade.stop()

    resp = asyncio.run(run())

    # (1) highest common dialect <= ceiling, not impacket's hardcoded 2.0.2
    assert resp["DialectRevision"] == 0x0300
    # (2) per-host stable ServerGuid, not impacket's b'A' * 16
    expected_guid, _ = _server_identity("fs01")
    assert bytes(resp["ServerGuid"]) == expected_guid
    assert bytes(resp["ServerGuid"]) != b"A" * 16
    # (3) signing REQUIRED bit is set (default signing_required=True)
    assert resp["SecurityMode"] & 0x2
    # (4) ServerStartTime is a plausible past boot, distinct from a live SystemTime
    def _epoch(ft):
        return ft / 1e7 - 11644473600
    sys_t, start_t = _epoch(resp["SystemTime"]), _epoch(resp["ServerStartTime"])
    assert abs(sys_t - time.time()) < 30          # SystemTime is now
    assert 3000 < (sys_t - start_t) < 46 * 86400   # uptime hours..~45 days, not zero


def test_server_guid_unique_per_host():
    from rangefinder.facades.smb import _server_identity

    async def guid_for(hostname):
        cfg = SmbConfig(port=_free_port(), shares=[SmbShare(name="Data")])
        facade = _serve(cfg, hostname)
        await facade.start()
        try:
            loop = asyncio.get_running_loop()
            resp = await loop.run_in_executor(None, _raw_negotiate, cfg.port, [0x0202])
            return bytes(resp["ServerGuid"])
        finally:
            await facade.stop()

    g1 = asyncio.run(guid_for("dc01"))
    g2 = asyncio.run(guid_for("ws01"))
    assert g1 != g2
    # stable: same host name -> same GUID (persists across "reboots")
    assert g1 == _server_identity("dc01")[0]


def test_signing_optional_and_dialect_ceiling():
    async def run():
        cfg = SmbConfig(port=_free_port(), signing_required=False, max_dialect="2.1",
                        shares=[SmbShare(name="Data")])
        facade = _serve(cfg, "ws01")
        await facade.start()
        try:
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(None, _raw_negotiate, cfg.port,
                                              [0x0202, 0x0210, 0x0300])
        finally:
            await facade.stop()

    resp = asyncio.run(run())
    assert resp["SecurityMode"] & 0x2 == 0     # not required
    assert resp["SecurityMode"] & 0x1          # still enabled
    assert resp["DialectRevision"] == 0x0210   # ceiling caps 3.0 offer down to 2.1


def _parse_contexts(resp) -> dict:
    """Decode a 3.1.1 negotiate response's context list -> {context_type: data_bytes}."""
    blob = bytes(resp["NegotiateContextList"])
    out, i = {}, 0
    for _ in range(int(resp["NegotiateContextCount"])):
        i += (8 - i % 8) % 8  # each context starts 8-byte aligned
        ctype, dlen = struct.unpack("<HH", blob[i:i + 4])
        out[ctype] = blob[i + 8:i + 8 + dlen]
        i += 8 + dlen
    return out


def test_negotiate_311_contexts():
    """3.1.1 is negotiated with a valid preauth-integrity context (mandatory) plus encryption
    and signing capability contexts — what recon tooling reads as a modern Windows service."""
    async def run():
        cfg = SmbConfig(port=_free_port(), max_dialect="3.1.1",
                        shares=[SmbShare(name="Data", files={"a.txt": "x"})])
        facade = _serve(cfg, "dc01")
        await facade.start()
        try:
            loop = asyncio.get_running_loop()
            ladder = [0x0202, 0x0210, 0x0300, 0x0302, 0x0311]
            return await loop.run_in_executor(None, _raw_negotiate, cfg.port, ladder)
        finally:
            await facade.stop()

    resp = asyncio.run(run())
    assert resp["DialectRevision"] == 0x0311
    assert int(resp["NegotiateContextCount"]) == 3
    assert int(resp["NegotiateContextOffset"]) % 8 == 0
    # impacket can't do 3.x AES-CMAC signing, so 3.1.1 advertises signing but does not require it
    assert resp["SecurityMode"] & 0x2 == 0

    ctx = _parse_contexts(resp)
    preauth = ctx[0x0001]  # SMB2_PREAUTH_INTEGRITY_CAPABILITIES (mandatory)
    hash_count, salt_len, hash_alg = struct.unpack("<HHH", preauth[:6])
    assert hash_count == 1 and hash_alg == 0x0001  # SHA-512
    assert salt_len == 32 and len(preauth) == 6 + 32
    assert struct.unpack("<H", ctx[0x0002][2:4])[0] == 0x0002  # AES-128-GCM
    assert struct.unpack("<H", ctx[0x0008][2:4])[0] == 0x0001  # AES-CMAC signing


def test_311_salt_is_fresh_per_negotiate():
    """The preauth salt must be random per negotiate, not a fixed constant."""
    async def run():
        cfg = SmbConfig(port=_free_port(), max_dialect="3.1.1", shares=[SmbShare(name="D")])
        facade = _serve(cfg, "dc01")
        await facade.start()
        try:
            loop = asyncio.get_running_loop()
            a = await loop.run_in_executor(None, _raw_negotiate, cfg.port, [0x0311])
            b = await loop.run_in_executor(None, _raw_negotiate, cfg.port, [0x0311])
            return _parse_contexts(a)[0x0001][6:], _parse_contexts(b)[0x0001][6:]
        finally:
            await facade.stop()

    salt_a, salt_b = asyncio.run(run())
    assert salt_a != salt_b and len(salt_a) == 32


def test_backing_file_mtimes_backdated_and_varied(tmp_path):
    """Backing files must not all share the container-boot timestamp — that reads as an estate
    provisioned moments ago. Each file gets a distinct, backdated mtime; dirs are backdated too."""
    import os
    import time
    from dataclasses import replace

    ctx, _ = make_ctx()
    ctx = replace(ctx, host_name="FS01")
    cfg = SmbConfig(port=_free_port(), shares=[SmbShare(name="HR", files={
        "salaries-2025.csv": "a,b", "policies/leave.txt": "x", "readme.txt": "y"})])
    facade = SmbFacade.from_config(cfg, ctx)
    facade._root = str(tmp_path)
    share_dir = facade._materialize(cfg.shares[0])

    now = time.time()
    file_mtimes = []
    for root, _, files in os.walk(share_dir):
        for f in files:
            file_mtimes.append(os.stat(os.path.join(root, f)).st_mtime)
    assert len(file_mtimes) == 3
    for m in file_mtimes:
        assert 86400 < (now - m) < 3 * 365 * 86400 + 86400   # 1 day .. ~3 years old
    assert len({round(m) for m in file_mtimes}) == 3          # all distinct (not one boot stamp)
    assert (now - os.stat(share_dir).st_mtime) > 86400        # directory backdated as well


# ------------------------------------------------------- access-surface fidelity


def _serve_shares(shares, hostname="fs01"):
    cfg = SmbConfig(port=_free_port(), shares=shares)
    facade = _serve(cfg, hostname)
    facade.port = cfg.port
    return facade, cfg.port


def test_readonly_share_rejects_anonymous_write():
    """A readonly share must reject writes with ACCESS_DENIED — not silently accept a file
    drop. Serving captured shares open to anonymous write is the false-CRITICAL the twin eval
    surfaced (real servers deny it)."""
    import io

    def client(port, share):
        from impacket.smbconnection import SMBConnection

        c = SMBConnection("127.0.0.1", "127.0.0.1", sess_port=port)
        c.login("", "")  # null session
        try:
            c.putFile(share, "canary.txt", io.BytesIO(b"owned").read)
            return "written"
        except Exception as exc:
            return type(exc).__name__ + ":" + str(exc)
        finally:
            c.close()

    async def run(readonly):
        shares = [SmbShare(name="drop", readonly=readonly, files={"a.txt": "x"})]
        facade, port = _serve_shares(shares)
        await facade.start()
        try:
            return await asyncio.get_running_loop().run_in_executor(None, client, port, "drop")
        finally:
            await facade.stop()

    ro = asyncio.run(run(True))
    rw = asyncio.run(run(False))
    assert "ACCESS_DENIED" in ro          # readonly => write refused, the faithful behaviour
    assert rw == "written"                # readonly=False => write accepted (control)


def test_ipc_share_does_not_serve_working_directory():
    """IPC$ must not browse the process CWD (inside the container, /app — leaking the
    rangefinder install and provenance). It is re-pointed at an empty jail dir."""
    def client(port):
        from impacket.smbconnection import SMBConnection

        c = SMBConnection("127.0.0.1", "127.0.0.1", sess_port=port)
        c.login("", "")
        try:
            names = {f.get_longname() for f in c.listPath("IPC$", "*")}
        except Exception as exc:
            names = {"__error__:" + type(exc).__name__}
        finally:
            c.close()
        return names

    async def run():
        facade, port = _serve_shares([SmbShare(name="Data", files={"a.txt": "x"})])
        await facade.start()
        try:
            return await asyncio.get_running_loop().run_in_executor(None, client, port)
        finally:
            await facade.stop()

    names = asyncio.run(run())
    # The repo root (this test's CWD) has these; they must NOT leak through IPC$.
    assert "pyproject.toml" not in names
    assert "rangefinder" not in names
    assert names <= {".", ".."} or all(n.startswith("__error__") for n in names)


def test_restrict_anonymous_share_enumerable_but_not_connectable():
    """A restrict_anonymous share is listed to a null session (enumeration transfers) but a
    null-session tree connect is refused — reproducing 'enumerable, not readable' instead of
    serving the share wide open (the eval's core faithfulness gap)."""
    def client(port):
        from impacket.smbconnection import SMBConnection

        c = SMBConnection("127.0.0.1", "127.0.0.1", sess_port=port)
        c.login("", "")  # null session
        shares = {s["shi1_netname"][:-1].upper() for s in c.listShares()}
        try:
            c.connectTree("Private")
            connect = "granted"
        except Exception as exc:
            connect = "denied:" + str(exc)
        # a normal share is still reachable in the same session
        try:
            c.connectTree("Public")
            public = "granted"
        except Exception as exc:
            public = "denied:" + str(exc)
        c.close()
        return shares, connect, public

    async def run():
        shares = [
            SmbShare(name="Public", files={"hello.txt": "hi"}),
            SmbShare(name="Private", restrict_anonymous=True),
        ]
        facade, port = _serve_shares(shares)
        await facade.start()
        try:
            return await asyncio.get_running_loop().run_in_executor(None, client, port)
        finally:
            await facade.stop()

    shares, connect, public = asyncio.run(run())
    assert "PRIVATE" in shares            # enumerable (the one finding that transfers)
    assert "PUBLIC" in shares
    assert "ACCESS_DENIED" in connect     # but a null session cannot connect it
    assert public == "granted"            # normal shares unaffected


# ------------------------------------------------------- auth/protocol posture


def test_smb1_refused_by_default_accepted_when_enabled():
    """SMB1 (NT LM 0.12) is a facade default impacket answers even with SMB2 on. A captured host
    with SMB1 disabled must refuse it — the twin should present SMB2/3-only unless smb1_enabled."""
    def client(port):
        from impacket.smbconnection import SMBConnection

        out = {}
        try:  # SMB2 path unaffected
            c = SMBConnection("127.0.0.1", "127.0.0.1", sess_port=port)
            c.login("", "")
            out["smb2"] = "ok"
            c.close()
        except Exception as exc:
            out["smb2"] = "ERR:" + type(exc).__name__
        try:  # pure SMB1 negotiate
            c = SMBConnection("127.0.0.1", "127.0.0.1", sess_port=port, preferredDialect="NT LM 0.12")
            c.login("", "")
            out["smb1"] = "accepted"
            c.close()
        except Exception:
            out["smb1"] = "refused"
        return out

    async def run(smb1_enabled):
        # reject_unknown_users=False here so SMB1 null login isn't also gated by the
        # guest-disable credential — this test isolates the smb1_enabled knob.
        cfg = SmbConfig(port=_free_port(), smb1_enabled=smb1_enabled, reject_unknown_users=False,
                        shares=[SmbShare(name="Data", files={"a.txt": "x"})])
        facade = _serve(cfg, "fs01")
        await facade.start()
        try:
            return await asyncio.get_running_loop().run_in_executor(None, client, cfg.port)
        finally:
            await facade.stop()

    off = asyncio.run(run(False))
    on = asyncio.run(run(True))
    assert off["smb2"] == "ok" and off["smb1"] == "refused"   # default: SMB1 off, SMB2 fine
    assert on["smb1"] == "accepted"                            # opt-in restores SMB1


def test_unknown_user_rejected_by_default_guest_when_opted_out():
    """impacket maps any credential to guest when no accounts are registered, so a bogus login
    'authenticates' — a false finding. reject_unknown_users (default) must refuse unknown accounts
    while leaving null-session enumeration open."""
    def client(port):
        from impacket.smbconnection import SMBConnection

        out = {}
        try:  # null session still enumerates
            c = SMBConnection("127.0.0.1", "127.0.0.1", sess_port=port)
            c.login("", "")
            out["null"] = "ok:" + str(len(c.listShares()))
            c.close()
        except Exception as exc:
            out["null"] = "ERR:" + type(exc).__name__
        try:  # bogus credential
            c = SMBConnection("127.0.0.1", "127.0.0.1", sess_port=port)
            c.login("nobody", "wrongpass")
            out["bogus"] = "accepted"
            c.close()
        except Exception:
            out["bogus"] = "rejected"
        return out

    async def run(reject):
        cfg = SmbConfig(port=_free_port(), reject_unknown_users=reject,
                        shares=[SmbShare(name="Data", files={"a.txt": "x"})])
        facade = _serve(cfg, "fs01")
        await facade.start()
        try:
            return await asyncio.get_running_loop().run_in_executor(None, client, cfg.port)
        finally:
            await facade.stop()

    strict = asyncio.run(run(True))
    lax = asyncio.run(run(False))
    assert strict["null"].startswith("ok") and strict["bogus"] == "rejected"   # default: reject
    assert lax["bogus"] == "accepted"                                          # opt-out: guest map


def test_default_client_negotiates_configured_dialect():
    """impacket's default client (like nmap/Windows) sends an SMB1 multi-protocol negotiate
    offering 'SMB 2.???'. impacket upgrades it but hardcodes 2.0.2 — the twin must instead honour
    the captured max_dialect, or it fingerprints as SMB 2.0.2 while the real host reports 3.1.1."""
    def client(port):
        from impacket.smbconnection import SMBConnection

        c = SMBConnection("127.0.0.1", "127.0.0.1", sess_port=port)
        c.login("", "")
        d = c.getDialect()
        c.close()
        return d

    async def run(max_dialect):
        cfg = SmbConfig(port=_free_port(), max_dialect=max_dialect,
                        shares=[SmbShare(name="Data", files={"a.txt": "x"})])
        facade = _serve(cfg, "fs01")
        await facade.start()
        try:
            return await asyncio.get_running_loop().run_in_executor(None, client, cfg.port)
        finally:
            await facade.stop()

    assert asyncio.run(run("3.1.1")) == 0x0311   # not impacket's hardcoded 0x0202
    assert asyncio.run(run("3.0")) == 0x0300
    assert asyncio.run(run("2.1")) == 0x0210


def test_select_dialect_ignores_negotiate_context_noise():
    """A 3.1.1 request trails negotiate-context bytes after the dialect array; parsing must
    honour DialectCount so those bytes aren't misread as bogus dialects (and picked)."""
    from impacket import smb3structs as smb2

    from rangefinder.facades.smb import _select_dialect

    neg = smb2.SMB2Negotiate()
    neg["DialectCount"] = 1
    neg["Dialects"] = [0x0311]
    neg["NegotiateContextList"] = b"\x02\x03\x00\x03\x00\x03\x00\x03"  # would look like dialects
    pkt = smb2.SMB2Packet()
    pkt["Command"] = smb2.SMB2_NEGOTIATE
    pkt["Data"] = neg

    recv = smb2.SMB2Packet(pkt.getData())
    # 3.1.1-only client, ceiling 3.0 -> no common dialect -> fall back (None), never the noise
    assert _select_dialect(smb2, recv, False, 0x0300) is None


def test_smb1_negotiate_fingerprints_as_microsoft_ds_not_router():
    """nmap -sV probes SMB with an SMB1 multi-protocol negotiate (SMBProgNeg). impacket's fallback
    answers with a minimal DialectIndex=0xFFFF response that nmap hard-matches as 'routersetup'
    (a Nortel/D-Link router) — a fidelity tell. The facade must instead answer like Windows (NT LM
    0.12 with a full NT-security body, Flags1 0x88) so nmap reports microsoft-ds."""
    import re
    import socket

    from rangefinder.config.services import SmbConfig, SmbShare

    probe = (b"\x00\x00\x00\xa4\xffSMBr\x00\x00\x00\x00\x08\x01\x40\x00\x00\x00\x00\x00\x00"
             b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x06\x00\x00\x01\x00\x00\x81\x00\x02"
             b"PC NETWORK PROGRAM 1.0\x00\x02MICROSOFT NETWORKS 1.03\x00\x02MICROSOFT NETWORKS 3.0\x00"
             b"\x02LANMAN1.0\x00\x02LM1.2X002\x00\x02Samba\x00\x02NT LANMAN 1.0\x00\x02NT LM 0.12\x00")
    cfg = SmbConfig(port=_free_port(), smb1_enabled=False, shares=[SmbShare(name="D")])
    facade = _serve(cfg, "fs01")

    async def run():
        await facade.start()
        try:
            loop = asyncio.get_running_loop()

            def send():
                s = socket.create_connection(("127.0.0.1", facade.port), 5)
                s.sendall(probe)
                s.settimeout(4)
                data = s.recv(4096)
                s.close()
                return data

            return await loop.run_in_executor(None, send)
        finally:
            await facade.stop()

    resp = asyncio.run(run())
    # microsoft-ds: SMB1 NEGOTIATE reply, Flags1 0x88, then the rich NT-security body
    assert re.match(rb"^\x00\x00\x00.\xffSMBr\x00\x00\x00\x00\x88\x01@", resp, re.S)
    # NOT routersetup: the minimal Flags1 0x80 / DialectIndex 0xFFFF reply
    assert not re.match(rb"^\x00\x00\x00.\xffSMBr\x00\x00\x00\x00\x80", resp, re.S)
