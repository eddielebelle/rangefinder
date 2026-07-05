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

# LDAP resultCodes that mean "this bind is refused" (anon disabled / bad creds), as opposed to a
# transient or protocol condition (confidentialityRequired, busy, unavailable, …). Only a refusal
# of the *anonymous* bind is a hardened posture; anything else is a genuine capture error.
_BIND_REFUSED = frozenset({48, 49, 53})  # inappropriateAuthentication / invalidCredentials / unwilling


def _wrap_tls(sock):
    """Wrap a socket for LDAPS. Verification is intentionally disabled — capture points at hosts
    with self-signed / internal-CA certs, and we are recording exposure, not trusting the peer."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx.wrap_socket(sock)


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
) -> tuple[dict, list[str], "CaptureReport"]:
    """Bind, enumerate, and return (ldap_service_config, warnings, capture_report)."""
    from rangefinder.capture.posture import CaptureReport

    warnings: list[str] = []
    scrubber = Scrubber() if scrub else None
    sock = socket.create_connection((host, port), timeout)
    try:
        if tls:
            sock = _wrap_tls(sock)

        counter = _Counter()
        anonymous = bind_dn == ""
        rc = _bind(sock, counter.next(), bind_dn, password)
        # A non-zero bind is a hardened posture ONLY when it is the *anonymous* bind being refused
        # (inappropriateAuthentication / unwilling / invalidCredentials). A credentialed failure, or
        # any other condition (confidentialityRequired, busy, unavailable, …), is a genuine capture
        # error — raising is more honest than silently emitting an empty "hardened" twin.
        anon_denied = anonymous and rc in _BIND_REFUSED
        if rc != 0 and not anon_denied:
            raise ValueError(f"LDAP bind failed (resultCode {rc})")
        if anon_denied:
            # Record the hardening and build a twin that also refuses anon. The RootDSE stays
            # anonymously readable (RFC 4513), so still read it for a believable twin, but don't
            # enumerate the directory — anon can't, and neither should the replica.
            warnings.append(
                f"anonymous bind rejected (resultCode {rc}); recording hardened posture "
                "(directory not anonymously enumerable)")

        captured: list[tuple[str, dict]] = []
        if anon_denied:
            try:
                root = _search(sock, counter.next(), "", 0, _ROOTDSE_ATTRS, max_entries)
            except (EOFError, PyAsn1Error, OSError):
                root = []  # a fully hardened server may refuse even the RootDSE read
        else:
            # On the success path a RootDSE read failure is a real error — let it propagate rather
            # than silently produce an empty twin for a directory that is in fact exposed.
            root = _search(sock, counter.next(), "", 0, _ROOTDSE_ATTRS, max_entries)
        root_attrs = root[0][1] if root else {}
        # namingContexts is anonymously readable from the RootDSE even on a hardened DC, so it
        # still gives us the base DN; only the subtree *enumeration* is gated on anon access.
        ncs = root_attrs.get("namingContexts") or root_attrs.get("defaultNamingContext") or []
        if not anon_denied:
            if not ncs:
                warnings.append("server advertised no namingContexts; captured RootDSE only")
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

    entries: list[dict] = []
    seen: set = set()
    if root_attrs:
        entries.append({"dn": "", "attributes": _clean(root_attrs, scrubber)})
        seen.add("")
    for dn, attrs in captured:
        if dn in seen:
            continue
        seen.add(dn)
        entries.append({"dn": dn, "attributes": _clean(attrs, scrubber)})
    n_entries = sum(1 for e in entries if e["dn"] != "")

    service: dict = {"type": "ldap", "port": port}
    if tls:
        service["tls"] = True
    if base_dn:
        service["base_dn"] = base_dn
    if anonymous:
        # Reproduce what we exercised: anonymous bind is allowed iff it succeeded on the target.
        service["allow_anonymous_bind"] = not anon_denied
    else:
        # Fail closed: the captured entries are the *authenticated* view. The twin must never
        # serve them to anonymous clients — that would fabricate an exposure the real host does
        # not have — regardless of the target's own anon-bind setting (measured below).
        service["allow_anonymous_bind"] = False
    service["entries"] = entries

    warnings.append(f"captured {n_entries} entries under {base_dn or '(unknown base)'}")

    perspective = "anonymous bind" if anonymous else f"authenticated as {bind_dn!r}"
    report = CaptureReport(target=host, perspective=perspective, protocol="ldap")
    report.measured("tls", tls, "LDAPS" if tls else "plaintext ldap")
    report.measured("base_dn", base_dn or "(unknown)", "RootDSE namingContexts")
    report.measured("entries", n_entries, "readable at this bind")
    if anonymous:
        if anon_denied:
            report.measured("allow_anonymous_bind", False,
                            f"anonymous simple bind rejected (resultCode {rc}); anon bind disabled")
            report.unmeasurable("authenticated_directory", "unknown",
                                "anonymous bind is refused, so nothing beyond the RootDSE was "
                                "readable; the authenticated directory was not measured. "
                                "Re-capture with -D/-w.")
        else:
            # We bound anonymously and it returned data -> anonymous bind is genuinely allowed.
            report.measured("allow_anonymous_bind", True,
                            "anonymous simple bind accepted and returned directory data")
            report.unmeasurable("authenticated_directory", "unknown",
                                "captured anonymously; entries/attributes visible only to an "
                                "authenticated bind were not measured. Re-capture with -D/-w.")
    else:
        # Credentialed capture: the main bind was authenticated, so it can't itself observe the
        # anonymous posture. Probe it directly so the report is honest — but the twin still fails
        # closed (see allow_anonymous_bind above): measuring that the target *accepts* anon bind
        # does not license serving the privileged view to anon.
        anon_accepted = _probe_anonymous_bind(host, port, tls=tls, timeout=timeout)
        if anon_accepted is True:
            report.measured("anonymous_bind_accepted", True,
                            "bind-level probe: target accepts an anonymous bind")
            report.assumed(
                "allow_anonymous_bind", False,
                "target accepts anon bind, but its anonymously-readable subset was not enumerated "
                "(captured with credentials); the twin refuses anon rather than serve the "
                "privileged view — re-capture anonymously to measure the true anon exposure")
        elif anon_accepted is False:
            report.measured("allow_anonymous_bind", False,
                            "bind-level probe: target rejects an anonymous bind")
        else:
            report.assumed("allow_anonymous_bind", False,
                           "anonymous-bind posture not measured (probe inconclusive); "
                           "assumed denied (fail-closed)")
    return service, warnings, report


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


def probe_credential(host: str, port: int, dn: str, password: str, *,
                     tls: bool = False, timeout: float = 5.0) -> bool | None:
    """Does the directory accept a simple bind as (dn, password)?

    True if the bind succeeds, False if it is refused (invalid credentials / inappropriate auth),
    None if the probe was inconclusive (unreachable / protocol error). Fail-closed: an inconclusive
    probe never reports success, so `verify estate` can't score an unmeasured edge as real.
    """
    try:
        sock = socket.create_connection((host, port), timeout)
    except OSError:
        return None
    try:
        if tls:
            sock = _wrap_tls(sock)
        rc = _bind(sock, 1, dn, password)
        _unbind(sock, 2)
        if rc == 0:
            return True
        if rc == 49:
            return False   # invalidCredentials: the one code that unambiguously means "wrong password"
        return None        # confidentialityRequired / unwilling / busy / operationsError: inconclusive,
        #                    not a credential rejection — don't falsely disprove a possibly-valid edge
    except (OSError, EOFError, PyAsn1Error, ValueError):
        return None
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _probe_anonymous_bind(host: str, port: int, *, tls: bool = False,
                          timeout: float = 5.0) -> bool | None:
    """Does the target accept an anonymous simple bind? True / False, or None if inconclusive.

    Opens a fresh connection and sends an empty-DN, empty-password simple bind. A hardened
    directory (anonymous bind disabled) answers inappropriateAuthentication -> False; a server
    that accepts it -> True. Used by the credentialed capture path, whose main bind is
    authenticated and so cannot itself observe the anonymous posture.
    """
    try:
        sock = socket.create_connection((host, port), timeout)
    except OSError:
        return None
    try:
        if tls:
            sock = _wrap_tls(sock)
        rc = _bind(sock, 1, "", "")
        _unbind(sock, 2)
        return rc == 0
    except (OSError, EOFError, PyAsn1Error, ValueError):
        return None
    finally:
        try:
            sock.close()
        except OSError:
            pass


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
