"""Capture a live SMB server's readable shares into a faithful ``smb`` facade.

Record-replay at the given access level (null session by default): list shares, walk the
file tree each one exposes, and record the files actually readable. The smb facade replays
them as real backing files — so if a share is null-session readable on the real server, it
is on the replica, with the same tree. No misconfig detection: the exposure is whatever the
capture could reach.

The access *decision* is recorded too, not just the readable files. A share that enumerates
but refuses a null session (STATUS_ACCESS_DENIED on listing) is marked ``restrict_anonymous``
so the twin reproduces the denial — otherwise it would serve an empty share wide open and an
agent would report a write/read exposure that does not exist on the real server. The server's
signing posture (``signing_required``) is captured for the same reason.

Uses impacket's SMB client (already a dependency). Text files are captured verbatim; binary
and oversized files are recorded by name with a placeholder so the tree stays faithful
without bloating the config. ``scrub=True`` redacts secrets in captured text.
"""

from __future__ import annotations

import io

from rangefinder.capture.posture import CaptureReport, PostureItem
from rangefinder.capture.scrub import Scrubber

# Shares that are administrative / non-file — skip (a null session can't read them anyway).
_SKIP_SHARES = {"IPC$", "ADMIN$", "PRINT$"}

# SMB2 dialect wire value -> config string (0x0302 has no config literal; map down to 3.0).
_DIALECT_NAME = {0x0202: "2.0.2", 0x0210: "2.1", 0x0300: "3.0", 0x0302: "3.0", 0x0311: "3.1.1"}

# Fixed, obviously-fake identity for the unknown-user probe (a hardened host rejects it; a
# guest-mapping host accepts it). No randomness needed — the point is that it does not exist.
_PROBE_USER = "rangefinder_probe"
_PROBE_PASS = "rf-not-a-real-password"


def capture_smb(
    host: str,
    port: int = 445,
    *,
    username: str = "",
    password: str = "",
    domain: str = "",
    timeout: float = 5.0,
    max_files: int = 2000,
    max_files_per_share: int = 200,
    shares: list[str] | None = None,
    max_file_size: int = 65_536,
    scrub: bool = False,
) -> tuple[dict, list[str], CaptureReport]:
    """Enumerate shares/files and return (smb_service_config, warnings, capture_report).

    The file budget is **per share** (``max_files_per_share``) so one large share (a media
    library, say) can't starve the rest; ``max_files`` is an overall safety ceiling. ``shares``
    restricts the capture to named shares (case-insensitive) — target the ones that matter and
    skip media/photo shares that are all placeholders anyway.

    The capture also actively probes the host's security *posture* (SMB1 availability, whether
    unknown accounts are rejected, signing, dialect) and records each with its provenance in the
    returned :class:`CaptureReport` — so the twin reproduces measured behaviour and the reviewer
    sees exactly which fields are measured vs. fail-closed assumptions.
    """
    from impacket.smbconnection import SMBConnection, SessionError
    from impacket.nt_errors import STATUS_ACCESS_DENIED

    warnings: list[str] = []
    scrubber = Scrubber() if scrub else None
    want = {s.strip().lower() for s in shares} if shares else None
    anonymous = not username  # null session: denials become restrict_anonymous, not empty shares
    perspective = "anonymous / null session" if anonymous else f"authenticated as {username!r}"
    report = CaptureReport(target=host, perspective=perspective, protocol="smb")
    conn = SMBConnection(host, host, sess_port=port, timeout=timeout)
    try:
        conn.login(username, password, domain)
        server_os = conn.getServerOS() or "Windows"
        report.items.append(PostureItem("server_os", "measured", server_os))

        # --- security posture: measure, else fail closed and say so -----------------
        try:
            signing_required = bool(conn.isSigningRequired())
            report.items.append(PostureItem(
                "signing_required", "measured", str(signing_required).lower(),
                "negotiate SecurityMode"))
        except Exception:
            signing_required = True  # fail closed: claim required rather than invent an exposure
            report.items.append(PostureItem(
                "signing_required", "assumed", "true", "could not read negotiate; assumed required"))

        dialect = conn.getDialect()
        max_dialect = _DIALECT_NAME.get(dialect)
        if max_dialect:
            report.items.append(PostureItem("max_dialect", "measured", max_dialect, "negotiated"))
        else:
            max_dialect = "3.1.1"
            report.items.append(PostureItem(
                "max_dialect", "assumed", max_dialect,
                f"negotiated dialect {dialect!r} has no config mapping; assumed modern"))

        smb1_enabled = _probe_smb1(host, port, timeout)
        report.items.append(PostureItem(
            "smb1_enabled", "measured", str(smb1_enabled).lower(),
            "NT LM 0.12 negotiate " + ("answered" if smb1_enabled else "refused")))

        reject = _probe_reject_unknown(host, port, timeout, domain)
        if reject is None:
            reject_unknown_users = True  # fail closed: reject rather than fabricate a guest bypass
            report.items.append(PostureItem(
                "reject_unknown_users", "assumed", "true",
                "unknown-user probe inconclusive; assumed hardened"))
        else:
            reject_unknown_users = reject
            report.items.append(PostureItem(
                "reject_unknown_users", "measured", str(reject).lower(),
                "bogus login " + ("rejected" if reject else "accepted as guest")))

        shares_cfg: list[dict] = []
        overall = _Budget(max_files)
        seen: set[str] = set()

        for share in conn.listShares():
            name = _cstr(share["shi1_netname"])
            comment = _cstr(share["shi1_remark"])
            if name.upper() in _SKIP_SHARES or name.endswith("$"):
                continue
            seen.add(name.lower())
            if want is not None and name.lower() not in want:
                continue

            files: dict[str, str] = {}
            per_share = _Budget(max_files_per_share)
            denied = False
            try:
                _walk(conn, name, "", files, _Pair(per_share, overall), max_file_size,
                      scrubber, warnings)
            except SessionError as exc:
                if exc.getErrorCode() == STATUS_ACCESS_DENIED:
                    denied = True
                    warnings.append(f"share {name!r}: access denied at this access level "
                                    f"(recorded as enumerable, not readable)")
                else:
                    warnings.append(f"share {name!r}: not fully readable ({exc})")
            except Exception as exc:  # not a disk share / transient error
                warnings.append(f"share {name!r}: not fully readable at this access level ({exc})")

            entry: dict = {"name": name, "comment": comment, "readonly": True}
            # A null session that was refused read access is a faithful "enumerable but not
            # readable" share: mark it so the twin reproduces the denial rather than serving an
            # empty share wide open. (With credentials, a denial can't be modelled as anonymous.)
            if denied and anonymous and not files:
                entry["restrict_anonymous"] = True
            if files:
                entry["files"] = files
            shares_cfg.append(entry)
            if per_share.exhausted():
                warnings.append(f"share {name!r}: truncated at {max_files_per_share} files")
            if overall.exhausted():
                warnings.append(f"overall file cap {max_files} reached; capture truncated")
                break

        if want:
            for missing in sorted(want - seen):
                warnings.append(f"requested share {missing!r} not found on {host}")
    finally:
        try:
            conn.close()
        except Exception:
            pass

    service: dict = {"type": "smb", "port": port, "server_os": server_os,
                     "signing_required": signing_required, "smb1_enabled": smb1_enabled,
                     "reject_unknown_users": reject_unknown_users, "max_dialect": max_dialect,
                     "shares": shares_cfg}
    total = sum(len(s.get("files", {})) for s in shares_cfg)

    # Share access is a measured fact: names enumerated, how many refused this session, how many
    # yielded files. The report states it so "empty share" vs "denied share" is never ambiguous.
    n_restricted = sum(1 for s in shares_cfg if s.get("restrict_anonymous"))
    n_withfiles = sum(1 for s in shares_cfg if s.get("files"))
    report.items.append(PostureItem(
        "shares", "measured", f"{len(shares_cfg)} enumerable",
        f"{n_restricted} deny this session, {n_withfiles} readable ({total} file(s))"))

    # The authenticated surface is unknowable from an anonymous capture — no default is right.
    if anonymous:
        report.items.append(PostureItem(
            "authenticated_read_write", "unmeasurable", "unknown",
            "captured anonymously; what a valid user can read/write was not measured. "
            "Re-capture with -u/-p to measure, or the twin presents these shares as deny-all."))

    warnings.append(f"captured {len(shares_cfg)} share(s), {total} file(s) from {host}")
    return service, warnings, report


def _probe_smb1(host: str, port: int, timeout: float) -> bool:
    """True if the host answers a legacy SMB1 (NT LM 0.12) negotiate, else False.

    Forces an SMB1-only negotiate on a fresh connection. A modern host with SMB1 disabled
    refuses it (negotiate/parse/logon failure) -> False. The main capture already proved TCP
    reachability, so a failure here is a genuine SMB1 refusal, not a transport blip.
    """
    from impacket.smbconnection import SMBConnection

    try:
        c = SMBConnection(host, host, sess_port=port, timeout=timeout, preferredDialect="NT LM 0.12")
        c.login("", "")
        c.close()
        return True
    except Exception:
        return False


def _probe_reject_unknown(host: str, port: int, timeout: float, domain: str) -> bool | None:
    """Does the host reject an unknown account (vs. mapping any credential to guest)?

    Returns True (rejects unknown — hardened), False (accepted a bogus login — guest fallback),
    or None if inconclusive (some other status), in which case the caller fails closed.
    """
    from impacket.nt_errors import STATUS_LOGON_FAILURE
    from impacket.smbconnection import SMBConnection, SessionError

    try:
        c = SMBConnection(host, host, sess_port=port, timeout=timeout)
        c.login(_PROBE_USER, _PROBE_PASS, domain)
        c.close()
        return False  # a non-existent account "authenticated" -> unknown users are guest-mapped
    except SessionError as exc:
        return True if exc.getErrorCode() == STATUS_LOGON_FAILURE else None
    except Exception:
        return None


class _Budget:
    def __init__(self, limit: int):
        self.limit = limit
        self.used = 0

    def take(self) -> bool:
        if self.used >= self.limit:
            return False
        self.used += 1
        return True

    def exhausted(self) -> bool:
        return self.used >= self.limit


class _Pair:
    """Consume from a per-share and an overall budget together; both must have room."""

    def __init__(self, per_share: _Budget, overall: _Budget):
        self.per_share = per_share
        self.overall = overall

    def take(self) -> bool:
        if self.per_share.exhausted() or self.overall.exhausted():
            return False
        self.per_share.take()
        self.overall.take()
        return True

    def exhausted(self) -> bool:
        return self.per_share.exhausted() or self.overall.exhausted()


def _walk(conn, share, smb_dir, files, budget, max_size, scrubber, warnings) -> None:
    pattern = (smb_dir + "*") if smb_dir else "*"
    for f in conn.listPath(share, pattern):
        name = f.get_longname()
        if name in (".", ".."):
            continue
        smb_path = smb_dir + name
        rel = smb_path.replace("\\", "/")
        if f.is_directory():
            _walk(conn, share, smb_path + "\\", files, budget, max_size, scrubber, warnings)
            if budget.exhausted():
                return
            continue

        if not budget.take():
            return
        size = f.get_filesize()
        if size > max_size:
            files[rel] = f"<file omitted: {size} bytes exceeds capture limit>\n"
            continue
        data = _read(conn, share, smb_path)
        files[rel] = _content(data, scrubber)


def _read(conn, share, smb_path) -> bytes:
    buf = io.BytesIO()
    conn.getFile(share, smb_path, buf.write)
    return buf.getvalue()


def _content(data: bytes, scrubber: Scrubber | None) -> str:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return f"<binary file, {len(data)} bytes; content not captured>\n"
    return scrubber.text(text) if scrubber is not None else text


def _cstr(value: str) -> str:
    # impacket returns null-terminated strings for share fields.
    return value[:-1] if value.endswith("\x00") else value


def probe_credential(host: str, port: int, username: str, password: str, *,
                     domain: str = "", timeout: float = 5.0) -> "bool | None":
    """Does the SMB host accept a logon as (domain\\username, password)?

    True on a successful session, False if the server rejects the credential (SessionError),
    None if inconclusive (unreachable / backend error). Fail-closed: inconclusive never reports
    success, so `verify estate` can't score an unmeasured credential edge as real.
    """
    from impacket.smbconnection import SMBConnection, SessionError

    try:
        conn = SMBConnection(host, host, sess_port=port, timeout=timeout)
    except Exception:
        return None
    try:
        conn.login(username, password, domain)
        # A guest-mapping host accepts *any* credential and drops it into a guest session, so a
        # login that didn't raise doesn't prove the password is right. Treat a guest session as a
        # rejection (fail closed) — never score a guest-mapped bad password as authenticated.
        try:
            if conn.isGuestSession():
                return False
        except Exception:
            pass
        try:
            conn.logoff()
        except Exception:
            pass
        return True
    except SessionError:
        return False
    except Exception:
        return None
