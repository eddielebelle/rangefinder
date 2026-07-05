"""Capture a live SSH server's crypto + auth posture into a faithful ``ssh`` facade.

Record-replay, at the recon level ``ssh-audit`` / ``nmap ssh2-enum-algos`` operate at: read the
server's version banner and its KEXINIT name-lists (offered KEX / host-key / cipher / MAC
algorithms — sent in the clear before any crypto, so no handshake is needed), and probe the auth
methods it advertises. The facade (real asyncssh, configured) then advertises the *same* posture,
so a weak-algorithm or password-auth exposure on the real host carries through to the twin.

Fail-closed: an algorithm list we could not read leaves the twin on asyncssh's modern defaults —
worst case we under-report, never fabricate a weak-crypto finding the real host doesn't have.
"""

from __future__ import annotations

import socket
import struct

# Algorithms flagged as weak/deprecated by ssh-audit and friends — surfaced in the report so the
# capture states the exposure, not just the raw lists.
_WEAK = {
    "diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1", "rsa1024-sha1", "gss-group1-sha1-toWM5Slw5Ew8Mqkay+al2g==",
    "3des-cbc", "blowfish-cbc", "cast128-cbc", "arcfour", "arcfour128", "arcfour256",
    "aes128-cbc", "aes192-cbc", "aes256-cbc", "rijndael-cbc@lysator.liu.se",
    "hmac-md5", "hmac-md5-96", "hmac-sha1", "hmac-sha1-96", "umac-64@openssh.com",
    "hmac-md5-etm@openssh.com", "hmac-sha1-etm@openssh.com", "umac-64-etm@openssh.com",
    "ssh-dss", "ssh-rsa",
}

_SSH_MSG_KEXINIT = 20


def capture_ssh(host: str, port: int = 22, *, timeout: float = 5.0) -> tuple[dict, list[str], "CaptureReport"]:
    """Read an SSH server's posture and return (ssh_service_config, warnings, capture_report)."""
    from rangefinder.capture.posture import CaptureReport

    warnings: list[str] = []
    server_version: str | None = None
    kex: dict | None = None
    try:
        server_version, kex = _read_kexinit(host, port, timeout)
    except Exception as exc:
        warnings.append(f"could not read SSH KEXINIT ({exc}); crypto posture unmeasured "
                        "(twin stays on modern defaults — fail-closed)")

    auth_methods = _probe_auth_methods(host, port, timeout)

    service: dict = {"type": "ssh", "port": port}
    if server_version:
        service["server_version"] = server_version.removeprefix("SSH-2.0-")
    if kex is not None:
        service["kex_algs"] = kex["kex"]
        service["host_key_algs"] = kex["host_key"]
        service["encryption_algs"] = kex["enc_s2c"]  # server -> client ciphers
        service["mac_algs"] = kex["mac_s2c"]
    if auth_methods is not None:
        service["auth_methods"] = auth_methods
    else:
        # Fail closed *unconditionally* — never leave auth_methods unset (the config default
        # advertises password), which would fabricate a brute-force surface on a host we could not
        # measure (reachable-but-probe-failed, or fully unreachable alike).
        service["auth_methods"] = ["publickey"]
        warnings.append("SSH auth methods not measured; assumed publickey-only (fail-closed)")

    # asyncssh advertises the full RSA host-key family (including the SHA-1 ssh-rsa) for any RSA
    # host key, and can't reproduce sk-*/cert host keys — surface both so the report is honest
    # about where the twin's host-key posture may diverge (verify flags it too).
    if kex is not None:
        hk = kex["host_key"]
        if any("rsa" in a for a in hk) and not any(a == "ssh-rsa" for a in hk):
            warnings.append("host offers RSA host keys without ssh-rsa; the asyncssh twin will "
                            "still advertise ssh-rsa (backend limit) — verify will flag it")
        unreproducible = [a for a in hk if a.startswith("sk-") or "-cert-" in a or "cert-v01" in a]
        if unreproducible:
            warnings.append(f"host-key algorithms not reproducible by the asyncssh backend: "
                            f"{', '.join(unreproducible)} (twin falls back to a plain key)")

    report = CaptureReport(target=f"{host}:{port}", perspective="unauthenticated SSH client",
                           protocol="ssh")
    if server_version:
        report.measured("server_version", server_version, "version banner")
    if kex is not None:
        report.measured("kex_algs", ", ".join(kex["kex"]) or "(none)", "KEXINIT")
        report.measured("host_key_algs", ", ".join(kex["host_key"]) or "(none)", "KEXINIT")
        report.measured("encryption_algs", ", ".join(kex["enc_s2c"]) or "(none)", "KEXINIT (s2c)")
        report.measured("mac_algs", ", ".join(kex["mac_s2c"]) or "(none)", "KEXINIT (s2c)")
        weak = _weak_offered(kex)
        if weak:
            report.measured("weak_algorithms", ", ".join(sorted(weak)),
                            "known-weak algorithms offered — reproduced so the finding transfers")
    else:
        for f in ("kex_algs", "host_key_algs", "encryption_algs", "mac_algs"):
            report.assumed(f, "(asyncssh modern defaults)",
                           "KEXINIT unread; the twin advertises modern defaults (fail-closed)")
    if auth_methods is not None:
        report.measured("auth_methods", ", ".join(auth_methods) or "(none)",
                        "advertised after a 'none' auth request"
                        + (" — password auth enabled (brute-forceable)"
                           if "password" in auth_methods else ""))
    elif kex is not None:
        report.assumed("auth_methods", "publickey", "not measured; assumed publickey-only (fail-closed)")

    warnings.append(f"captured SSH posture for {host}:{port}"
                    + (f" ({server_version})" if server_version else ""))
    return service, warnings, report


def _weak_offered(kex: dict) -> set[str]:
    offered = set(kex["kex"]) | set(kex["host_key"]) | set(kex["enc_s2c"]) | set(kex["mac_s2c"])
    return offered & _WEAK


# --------------------------------------------------------------------- KEXINIT reader


def _read_kexinit(host: str, port: int, timeout: float) -> tuple[str, dict]:
    """Do the SSH version exchange and read + parse the server's KEXINIT (both cleartext, pre-KEX).

    Returns (server_version_string, {kex, host_key, enc_c2s, enc_s2c, mac_c2s, mac_s2c, ...}).
    """
    sock = socket.create_connection((host, port), timeout)
    sock.settimeout(timeout)
    f = sock.makefile("rb")
    try:
        # Version exchange: the server may emit pre-banner lines before its "SSH-..." identifier.
        server_version = None
        for _ in range(64):
            line = f.readline()
            if not line:
                raise EOFError("connection closed during version exchange")
            s = line.rstrip(b"\r\n")
            if s.startswith(b"SSH-"):
                server_version = s.decode("latin-1", "replace")
                break
        if server_version is None:
            raise ValueError("no SSH version string received")
        sock.sendall(b"SSH-2.0-rangefinder-capture\r\n")

        # The server's first binary packet is its KEXINIT; skip any debug/ignore packets first.
        for _ in range(8):
            payload = _read_packet(f)
            if payload and payload[0] == _SSH_MSG_KEXINIT:
                return server_version, _parse_kexinit(payload)
        raise ValueError("no KEXINIT packet received")
    finally:
        try:
            f.close()
            sock.close()
        except OSError:
            pass


def _read_packet(f) -> bytes:
    """Read one unencrypted SSH binary packet and return its payload."""
    header = f.read(4)
    if len(header) < 4:
        raise EOFError("short packet header")
    (plen,) = struct.unpack(">I", header)
    if plen < 1 or plen > 1_000_000:
        raise ValueError(f"implausible packet length {plen}")
    body = f.read(plen)
    if len(body) < plen:
        raise EOFError("short packet body")
    pad_len = body[0]
    if pad_len > len(body) - 1:  # padding can't exceed the packet — reject rather than mis-slice
        raise ValueError(f"padding length {pad_len} exceeds packet body {len(body)}")
    return body[1:len(body) - pad_len]


def _parse_kexinit(payload: bytes) -> dict:
    if len(payload) < 1 + 16:
        raise ValueError("KEXINIT payload too short")
    off = 1 + 16  # skip msg type byte + 16-byte cookie
    names: list[list[str]] = []
    for _ in range(10):  # ten name-lists per RFC 4253
        if off + 4 > len(payload):
            raise ValueError("truncated KEXINIT (name-list length)")
        (nlen,) = struct.unpack(">I", payload[off:off + 4])
        off += 4
        if off + nlen > len(payload):
            raise ValueError("truncated KEXINIT (name-list body)")
        raw = payload[off:off + nlen].decode("ascii", "replace")
        off += nlen
        names.append([n for n in raw.split(",") if n])
    return {
        "kex": names[0], "host_key": names[1],
        "enc_c2s": names[2], "enc_s2c": names[3],
        "mac_c2s": names[4], "mac_s2c": names[5],
        "comp_c2s": names[6], "comp_s2c": names[7],
    }


# ------------------------------------------------------------------ auth-method probe


def _probe_auth_methods(host: str, port: int, timeout: float) -> list[str] | None:
    """The auth methods the server advertises (e.g. publickey / password), or None if inconclusive.

    Uses asyncssh's client helper, which completes the key exchange and reads the server's method
    list from its response to a 'none' auth request — the same signal ``ssh -v`` shows.
    """
    import asyncio

    import asyncssh

    async def _go():
        return await asyncio.wait_for(
            asyncssh.get_server_auth_methods(host, port=port, username="rangefinder-probe"),
            timeout)

    try:
        return list(asyncio.run(_go()))
    except Exception:
        return None
