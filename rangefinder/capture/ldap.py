"""Capture a live LDAP directory's contents into a faithful ``ldap`` facade.

Record-replay, at the attacker's access level: bind (anonymous by default), read the
RootDSE, then subtree-search each naming context and record the entries actually returned.
The facade replays those entries verbatim — so if anonymous bind exposes the directory on
the real server, it does on the replica too; if it is locked down, the replica returns the
same little. No misconfig detection: the exposure is whatever the capture saw.

Reuses the project's pyasn1 + rfc2251 machinery (the same wire format the facade speaks),
so there is no extra dependency. Text attributes (cn, sAMAccountName, description, memberOf, …)
are recorded as UTF-8; binary-syntax attributes (objectSid, objectGUID, userCertificate,
ntSecurityDescriptor) are recorded base64 in ``binary_attributes`` and replayed as raw octets —
so SID/GUID/ACL identifiers that SID-based enumeration and BloodHound-style tooling read survive
the capture instead of being dropped.
"""

from __future__ import annotations

import base64
import socket
import ssl

from pyasn1.codec.ber import decoder, encoder
from pyasn1.error import PyAsn1Error
from pyasn1.type import namedtype, univ
from pyasn1_modules import rfc2251 as L

from rangefinder.capture.scrub import Scrubber

_ROOTDSE_ATTRS = [
    "*", "+", "namingContexts", "defaultNamingContext", "rootDomainNamingContext",
    "supportedLDAPVersion", "dnsHostName",
]
_SENSITIVE_ATTRS = {"userpassword", "unicodepwd", "ntpwdhistory", "lmpwdhistory"}

# Attributes that are binary-syntax regardless of whether a given value happens to decode as UTF-8,
# so a coincidentally-textual objectSid is still carried (and served) as binary rather than routed
# to the text path and mangled by scrubbing. Also the allow-list of binary attrs kept under --scrub:
# an *unknown* binary attribute (a text attr rerouted by a stray non-UTF-8 byte) may hide a secret,
# so scrubbing drops it fail-closed; these known identifiers are not secrets and are kept.
_BINARY_ATTRS = {
    "objectsid", "objectguid", "usercertificate", "usercertificate;binary",
    "cacertificate", "cacertificate;binary", "ntsecuritydescriptor",
    "msds-allowedtoactonbehalfofotheridentity",
}

# LDAP resultCodes that mean "this bind is refused" (anon disabled / bad creds), as opposed to a
# transient or protocol condition (confidentialityRequired, busy, unavailable, …). Only a refusal
# of the *anonymous* bind is a hardened posture; anything else is a genuine capture error.
_BIND_REFUSED = frozenset({48, 49, 53})  # inappropriateAuthentication / invalidCredentials / unwilling

# nTSecurityDescriptor holds the object's ACL — owner, group, and the DACL that defines who can do
# what to it. Those ACEs are exactly the edges BloodHound-style tooling walks to find attack paths
# (GenericAll, WriteDacl, …), so an ACL-blind twin can't surface identity-plane privilege paths.
# AD does NOT return nTSecurityDescriptor for a bare ``*`` — it must be requested by name, and the
# request is scoped by the LDAP_SERVER_SD_FLAGS control below.
_SD_ATTR = "nTSecurityDescriptor"

# LDAP_SERVER_SD_FLAGS_OID: scopes which components of the security descriptor the server returns.
# OWNER (1) | GROUP (2) | DACL (4) — deliberately NOT SACL (8). Reading the SACL (the audit ACL)
# needs SeSecurityPrivilege, which an ordinary bind lacks; requesting it can make the server refuse
# the whole attribute. An attacker at this access level can't read the SACL either, so omitting it
# is faithful to what this bind can see, not a capture gap.
_SD_FLAGS_OID = "1.2.840.113556.1.4.801"
_SD_FLAGS_OWNER_GROUP_DACL = 0x07


class _SDFlagsRequestValue(univ.Sequence):
    """The controlValue payload for LDAP_SERVER_SD_FLAGS: ``SEQUENCE { flags INTEGER }``."""

    componentType = namedtype.NamedTypes(namedtype.NamedType("flags", univ.Integer()))


def _sd_flags_control(flags: int) -> tuple[str, bool, bytes]:
    """Build the LDAP_SERVER_SD_FLAGS control as (oid, criticality, controlValue).

    Criticality is FALSE so a directory that does not implement the control (OpenLDAP, a hardened
    non-AD server) ignores it and the search still succeeds — it simply returns no security
    descriptor rather than erroring. Against AD the control is honored regardless of criticality
    and scopes nTSecurityDescriptor to the requested SD components.
    """
    value = _SDFlagsRequestValue()
    value["flags"] = flags
    return _SD_FLAGS_OID, False, encoder.encode(value)


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

        captured: list[tuple[str, dict, dict]] = []
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
        root_battrs = root[0][2] if root else {}
        # namingContexts is anonymously readable from the RootDSE even on a hardened DC, so it
        # still gives us the base DN; only the subtree *enumeration* is gated on anon access.
        ncs = root_attrs.get("namingContexts") or root_attrs.get("defaultNamingContext") or []
        if not anon_denied:
            if not ncs:
                warnings.append("server advertised no namingContexts; captured RootDSE only")
            # Request the ACL (nTSecurityDescriptor) alongside "*": it is not returned by the
            # wildcard, so it must be named, and the SD_FLAGS control scopes it to owner/group/DACL
            # (the parts this bind can read). Whatever the server actually returns is captured; a
            # server that withholds it just yields no SD — fail-closed, never fabricated.
            sd_control = _sd_flags_control(_SD_FLAGS_OWNER_GROUP_DACL)
            for nc in ncs:
                if len(captured) >= max_entries:
                    break
                captured.extend(_search(sock, counter.next(), nc, 2, ["*", _SD_ATTR],
                                        max_entries - len(captured), controls=[sd_control]))
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

    def _entry(dn, text, binary):
        clean_text, clean_binary = _clean_entry(text, binary, scrubber)
        e = {"dn": dn, "attributes": clean_text}
        if clean_binary:
            e["binary_attributes"] = clean_binary
        return e

    entries: list[dict] = []
    seen: set = set()
    if root_attrs or root_battrs:
        entries.append(_entry("", root_attrs, root_battrs))
        seen.add("")
    for dn, attrs, battrs in captured:
        if dn in seen:
            continue
        seen.add(dn)
        entries.append(_entry(dn, attrs, battrs))
    n_entries = sum(1 for e in entries if e["dn"] != "")
    n_binary = sum(len(e.get("binary_attributes", {})) for e in entries)
    n_acl = sum(1 for e in entries for k in e.get("binary_attributes", {})
                if k.lower() == "ntsecuritydescriptor")

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

    warnings.append(f"captured {n_entries} entries under {base_dn or '(unknown base)'}"
                    + (f" ({n_binary} binary attribute(s) preserved)" if n_binary else ""))

    perspective = "anonymous bind" if anonymous else f"authenticated as {bind_dn!r}"
    report = CaptureReport(target=host, perspective=perspective, protocol="ldap")
    report.measured("tls", tls, "LDAPS" if tls else "plaintext ldap")
    report.measured("base_dn", base_dn or "(unknown)", "RootDSE namingContexts")
    report.measured("entries", n_entries, "readable at this bind")
    if n_binary:
        report.measured("binary_attributes", n_binary,
                        "objectSid/GUID/cert/ACL values carried base64 and replayed as raw octets")
    # ACLs (nTSecurityDescriptor) are the identity-plane attack-path edges. Surface them as their
    # own provenance fact, distinct from the raw binary count, and be explicit about the SACL gap.
    if not anon_denied:
        if n_acl:
            report.measured("security_descriptors", n_acl,
                            "nTSecurityDescriptor (owner/group/DACL) captured via "
                            "LDAP_SERVER_SD_FLAGS and replayed as raw octets for ACL analysis")
            report.unmeasurable("sacl", "unknown",
                                "system ACL (SACL/auditing) not requested — reading it needs "
                                "SeSecurityPrivilege, which this bind lacks; an attacker at this "
                                "access level cannot see it either")
        else:
            report.unmeasurable("security_descriptors", 0,
                                "no nTSecurityDescriptor was readable at this bind; ACL-based "
                                "attack paths were not captured — re-capture with a credential "
                                "that can read object security to measure them")
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


def _search(sock, mid: int, base: str, scope: int, attributes, limit: int,
            controls: list[tuple[str, bool, bytes]] | None = None) -> list[tuple[str, dict, dict]]:
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
    if controls:
        # LDAPMessage.controls is context-tagged [0]; instantiate it from the message's own schema
        # so the tag matches, then fill each Control (controlType / criticality / controlValue).
        ctrls = msg.componentType.getTypeByPosition(2).clone()
        for i, (oid, criticality, value) in enumerate(controls):
            c = ctrls.componentType.clone()
            c["controlType"] = oid
            c["criticality"] = criticality
            if value is not None:
                c["controlValue"] = value
            ctrls.setComponentByPosition(i, c)
        msg["controls"] = ctrls
    sock.sendall(encoder.encode(msg))

    out: list[tuple[str, dict]] = []
    while True:
        resp = _recv_message(sock)
        kind = resp["protocolOp"].getName()
        if kind == "searchResEntry":
            entry = resp["protocolOp"]["searchResEntry"]
            dn = str(entry["objectName"])
            attrs: dict[str, list[str]] = {}
            battrs: dict[str, list[str]] = {}
            for a in entry["attributes"]:
                name = str(a["type"])
                raw = [bytes(v) for v in a["vals"]]
                if not raw:
                    continue  # a valueless attribute — omit rather than record an empty set
                # Known-binary attrs go binary by name (even if a value is coincidentally UTF-8);
                # otherwise decide by content.
                text = None if name.lower() in _BINARY_ATTRS else _decode_text(raw)
                if text is not None:
                    attrs[name] = text
                else:
                    battrs[name] = [base64.b64encode(b).decode("ascii") for b in raw]
            out.append((dn, attrs, battrs))
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


def _decode_text(raw: list[bytes]) -> list[str] | None:
    """Decode an attribute's values as UTF-8, or None if any value is binary (so the whole
    single-syntax attribute is carried as base64 instead)."""
    out: list[str] = []
    for b in raw:
        try:
            out.append(b.decode("utf-8"))
        except UnicodeDecodeError:
            return None
    return out


# --------------------------------------------------------------------------- scrubbing


def _clean_entry(text: dict, binary: dict, scrubber: Scrubber | None) -> tuple[dict, dict]:
    """Scrub text attribute values; drop password-ish attributes from both text and binary.

    Binary identifiers (objectSid/GUID/cert/ACL) are carried verbatim — they are not secrets, and
    corrupting them would defeat the point of capturing them. Sensitive binary (unicodePwd,
    ntPwdHistory) is still dropped by the same sensitive-attr set.
    """
    clean_text: dict[str, list[str]] = {}
    for name, vals in text.items():
        if name.lower() in _SENSITIVE_ATTRS:
            continue
        clean_text[name] = [scrubber.text(v) for v in vals] if scrubber else list(vals)
    clean_binary: dict[str, list[str]] = {}
    for name, vals in binary.items():
        if name.lower() in _SENSITIVE_ATTRS:
            continue
        if scrubber is not None and name.lower() not in _BINARY_ATTRS:
            # Under --scrub an unknown binary attribute may be a text attr rerouted by a stray
            # non-UTF-8 byte, hiding a secret we can't redact in base64 — drop it fail-closed.
            continue
        clean_binary[name] = list(vals)
    return clean_text, clean_binary
