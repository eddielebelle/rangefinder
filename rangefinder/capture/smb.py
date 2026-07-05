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

from rangefinder.capture.scrub import Scrubber

# Shares that are administrative / non-file — skip (a null session can't read them anyway).
_SKIP_SHARES = {"IPC$", "ADMIN$", "PRINT$"}


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
) -> tuple[dict, list[str]]:
    """Enumerate shares/files and return (smb_service_config, warnings).

    The file budget is **per share** (``max_files_per_share``) so one large share (a media
    library, say) can't starve the rest; ``max_files`` is an overall safety ceiling. ``shares``
    restricts the capture to named shares (case-insensitive) — target the ones that matter and
    skip media/photo shares that are all placeholders anyway.
    """
    from impacket.smbconnection import SMBConnection, SessionError
    from impacket.nt_errors import STATUS_ACCESS_DENIED

    warnings: list[str] = []
    scrubber = Scrubber() if scrub else None
    want = {s.strip().lower() for s in shares} if shares else None
    anonymous = not username  # null session: denials become restrict_anonymous, not empty shares
    conn = SMBConnection(host, host, sess_port=port, timeout=timeout)
    try:
        conn.login(username, password, domain)
        server_os = conn.getServerOS() or "Windows"
        try:
            signing_required = bool(conn.isSigningRequired())
        except Exception:
            signing_required = False
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
                     "signing_required": signing_required, "shares": shares_cfg}
    total = sum(len(s.get("files", {})) for s in shares_cfg)
    warnings.append(f"captured {len(shares_cfg)} share(s), {total} file(s) from {host}")
    return service, warnings


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
