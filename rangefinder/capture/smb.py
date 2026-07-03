"""Capture a live SMB server's readable shares into a faithful ``smb`` facade.

Record-replay at the given access level (null session by default): list shares, walk the
file tree each one exposes, and record the files actually readable. The smb facade replays
them as real backing files — so if a share is null-session readable on the real server, it
is on the replica, with the same tree. No misconfig detection: the exposure is whatever the
capture could reach.

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
    max_files: int = 500,
    max_file_size: int = 65_536,
    scrub: bool = False,
) -> tuple[dict, list[str]]:
    """Enumerate shares/files and return (smb_service_config, warnings)."""
    from impacket.smbconnection import SMBConnection

    warnings: list[str] = []
    scrubber = Scrubber() if scrub else None
    conn = SMBConnection(host, host, sess_port=port, timeout=timeout)
    try:
        conn.login(username, password, domain)
        server_os = conn.getServerOS() or "Windows"
        shares_cfg: list[dict] = []
        budget = _Budget(max_files)

        for share in conn.listShares():
            name = _cstr(share["shi1_netname"])
            comment = _cstr(share["shi1_remark"])
            if name.upper() in _SKIP_SHARES or name.endswith("$"):
                continue

            files: dict[str, str] = {}
            try:
                _walk(conn, name, "", files, budget, max_file_size, scrubber, warnings)
            except Exception as exc:  # access denied / not a disk share
                warnings.append(f"share {name!r}: not fully readable at this access level ({exc})")

            entry: dict = {"name": name, "comment": comment, "readonly": True}
            if files:
                entry["files"] = files
            shares_cfg.append(entry)
            if budget.exhausted():
                warnings.append(f"file cap {max_files} reached; capture truncated")
                break
    finally:
        try:
            conn.close()
        except Exception:
            pass

    service: dict = {"type": "smb", "port": port, "server_os": server_os, "shares": shares_cfg}
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
