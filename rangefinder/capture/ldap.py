"""Capture a live LDAP directory's contents into a faithful ``ldap`` facade.

Record-replay, at the attacker's access level: bind (anonymous by default), read the
RootDSE, then subtree-search each naming context and record the entries actually returned.
The facade replays those entries verbatim — so if anonymous bind exposes the directory on
the real server, it does on the replica too; if it is locked down, the replica returns the
same little. No misconfig detection: the exposure is whatever the capture saw.

Reuses the project's pyasn1 + rfc2251 machinery (the same wire format the facade speaks),
so there is no extra dependency. Binary attribute values (objectSid, GUIDs) that are not
UTF-8 are dropped — text attributes (cn, sAMAccountName, description, memberOf, …) are what
enumeration cares about.
"""

from __future__ import annotations

import socket
import ssl

from pyasn1.codec.ber import decoder, encoder
from pyasn1.error import PyAsn1Error
from pyasn1_modules import rfc2251 as L

from rangefinder.capture.scrub import Scrubber

_ROOTDSE_ATTRS = [
    "*", "+", "namingContexts", "defaultNamingContext", "rootDomainNamingContext",
    "supportedLDAPVersion", "dnsHostName",
]
_SENSITIVE_ATTRS = {"userpassword", "unicodepwd", "ntpwdhistory", "lmpwdhistory"}


def capture_ldap(
    host: str,
    port: int = 389,
    *,
    tls: bool = False,
    bind_dn: str = "",
    password: str = "",
    timeout: float = 5.0,
    max_entries: int = 5000,
    scrub: bool = False,
) -> tuple[dict, list[str]]:
    """Bind, enumerate, and return (ldap_service_config, warnings)."""
    warnings: list[str] = []
    scrubber = Scrubber() if scrub else None
    sock = socket.create_connection((host, port), timeout)
    try:
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock)

        counter = _Counter()
        rc = _bind(sock, counter.next(), bind_dn, password)
        if rc != 0:
            raise ValueError(f"LDAP bind failed (resultCode {rc})")

        root = _search(sock, counter.next(), "", 0, _ROOTDSE_ATTRS, max_entries)
        root_attrs = root[0][1] if root else {}
        ncs = root_attrs.get("namingContexts") or root_attrs.get("defaultNamingContext") or []
        if not ncs:
            warnings.append("server advertised no namingContexts; captured RootDSE only")

        captured: list[tuple[str, dict]] = []
        for nc in ncs:
            if len(captured) >= max_entries:
                break
            captured.extend(_search(sock, counter.next(), nc, 2, ["*"], max_entries - len(captured)))
        _unbind(sock, counter.next())
    finally:
        try:
            sock.close()
        except OSError:
            pass

    if len(captured) >= max_entries:
        warnings.append(f"entry cap {max_entries} reached; directory may be truncated")

    base_dn = None
    default_nc = root_attrs.get("defaultNamingContext")
    if default_nc:
        base_dn = default_nc[0]
    elif ncs:
        base_dn = ncs[0]

    entries: list[dict] = [{"dn": "", "attributes": _clean(root_attrs, scrubber)}]
    seen = {""}
    dropped = 0
    for dn, attrs in captured:
        if dn in seen:
            continue
        seen.add(dn)
        cleaned = _clean(attrs, scrubber)
        if not cleaned and not attrs:
            dropped += 1
        entries.append({"dn": dn, "attributes": cleaned})

    service: dict = {"type": "ldap", "port": port}
    if tls:
        service["tls"] = True
    if base_dn:
        service["base_dn"] = base_dn
    # Reproduce the exposure we exercised: if anonymous bind returned data, the replica
    # should allow anonymous bind too.
    service["allow_anonymous_bind"] = bind_dn == ""
    service["entries"] = entries

    warnings.append(f"captured {len(entries) - 1} entries under {base_dn or '(unknown base)'}")
    return service, warnings


# ------------------------------------------------------------------------ ldap client


class _Counter:
    def __init__(self):
        self._n = 0

    def next(self) -> int:
        self._n += 1
        return self._n


def _bind(sock, mid: int, dn: str, password: str) -> int:
    msg = L.LDAPMessage()
    msg["messageID"] = mid
    br = L.BindRequest()
    br["version"] = 3
    br["name"] = dn
    br["authentication"]["simple"] = password.encode("utf-8")
    msg["protocolOp"]["bindRequest"] = br
    sock.sendall(encoder.encode(msg))
    resp = _recv_message(sock)
    return int(resp["protocolOp"]["bindResponse"]["resultCode"])


def _search(sock, mid: int, base: str, scope: int, attributes, limit: int) -> list[tuple[str, dict]]:
    msg = L.LDAPMessage()
    msg["messageID"] = mid
    sr = L.SearchRequest()
    sr["baseObject"] = base
    sr["scope"] = scope
    sr["derefAliases"] = 0
    sr["sizeLimit"] = 0
    sr["timeLimit"] = 0
    sr["typesOnly"] = 0
    filt = L.Filter()
    filt["present"] = "objectClass"
    sr["filter"] = filt
    attr_list = sr.getComponentByName("attributes")
    for i, a in enumerate(attributes):
        attr_list.setComponentByPosition(i, a)
    msg["protocolOp"]["searchRequest"] = sr
    sock.sendall(encoder.encode(msg))

    out: list[tuple[str, dict]] = []
    while True:
        resp = _recv_message(sock)
        kind = resp["protocolOp"].getName()
        if kind == "searchResEntry":
            entry = resp["protocolOp"]["searchResEntry"]
            dn = str(entry["objectName"])
            attrs: dict[str, list[str]] = {}
            for a in entry["attributes"]:
                name = str(a["type"])
                vals = [_val(v) for v in a["vals"]]
                vals = [v for v in vals if v is not None]
                if vals:
                    attrs[name] = vals
            out.append((dn, attrs))
            if len(out) >= limit:
                # Drain until done so the stream stays aligned for the next query.
                _drain_until_done(sock)
                break
        elif kind == "searchResDone":
            break
        elif kind == "searchResRef":
            continue
        else:
            break
    return out


def _drain_until_done(sock) -> None:
    try:
        while _recv_message(sock)["protocolOp"].getName() != "searchResDone":
            continue
    except (EOFError, PyAsn1Error):
        pass


def _unbind(sock, mid: int) -> None:
    msg = L.LDAPMessage()
    msg["messageID"] = mid
    msg["protocolOp"]["unbindRequest"] = L.UnbindRequest("")
    try:
        sock.sendall(encoder.encode(msg))
    except OSError:
        pass


def _recv_message(sock):
    tag = _recv_exact(sock, 1)
    first = _recv_exact(sock, 1)
    if first[0] < 0x80:
        length = first[0]
        header = tag + first
    else:
        n = first[0] & 0x7F
        more = _recv_exact(sock, n)
        length = int.from_bytes(more, "big")
        header = tag + first + more
    body = _recv_exact(sock, length)
    msg, _ = decoder.decode(header + body, asn1Spec=L.LDAPMessage())
    return msg


def _recv_exact(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError("connection closed mid-message")
        buf += chunk
    return buf


def _val(value) -> str | None:
    try:
        return bytes(value).decode("utf-8")
    except UnicodeDecodeError:
        return None  # binary attribute value (objectSid, GUID, cert) — skip


# --------------------------------------------------------------------------- scrubbing


def _clean(attrs: dict, scrubber: Scrubber | None) -> dict:
    if scrubber is None:
        return {k: list(v) for k, v in attrs.items()}
    out: dict[str, list[str]] = {}
    for name, vals in attrs.items():
        if name.lower() in _SENSITIVE_ATTRS:
            continue  # drop password-ish attributes entirely
        out[name] = [scrubber.text(v) for v in vals]
    return out
