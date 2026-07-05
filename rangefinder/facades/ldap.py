"""Enumeration-grade LDAP facade.

Answers anonymous BIND + SEARCH from ldapsearch / enum4linux / windapsearch against a
directory built from the range's ``identities`` (domain, users, groups). It speaks real
LDAPv3 over the wire (BER via pyasn1 + the rfc2251 schema), supports the RootDSE query
and the filter operators enumeration tools actually send (and/or/not/equality/present/
substrings), and logs every bind and search.

It also validates NTLM binds: SASL GSS-SPNEGO (what GetUserSPNs / BloodHound use) and the
legacy MS Sicily mechanism both run the NTLM challenge/response against the ``identities``
NT hashes. Simple binds are validated against known identity passwords (a wrong password
for a known user returns invalidCredentials, like a real DC); a captured directory holds no
passwords, so simple binds there stay permissive to keep replay working. When
``allow_anonymous_bind`` is off the facade reproduces a hardened DC: the anonymous bind is
refused (inappropriateAuthentication) and an unbound client's directory search is refused
(operationsError), while the RootDSE stays anonymously readable — so a credentialed-captured
twin never leaks its privileged view to an anonymous client. Deliberate limits:
no NTLM signing/sealing on the post-bind session, no writes, no StartTLS, no paged-results
control. It renders a directory for enumeration.
"""

from __future__ import annotations

import asyncio
import datetime
from dataclasses import dataclass, field

from pyasn1.codec.ber import decoder, encoder
from pyasn1.error import PyAsn1Error
from pyasn1_modules import rfc2251 as L

from rangefinder.config.services import LdapConfig
from rangefinder.facades.base import ConnScope, Facade, FacadeContext
from rangefinder.facades.registry import register
from rangefinder.telemetry import event as ev

_SCOPE_NAMES = {0: "base", 1: "one", 2: "sub"}


# --------------------------------------------------------------------------- directory


@dataclass
class Entry:
    dn: str
    attrs: dict[str, list[str]]
    # lowercased attribute name -> values, for case-insensitive matching
    _lc: dict[str, list[str]] = field(default_factory=dict)

    def __post_init__(self):
        self._lc = {k.lower(): v for k, v in self.attrs.items()}

    def get(self, name: str) -> list[str]:
        return self._lc.get(name.lower(), [])


def _base_dn(domain: str) -> str:
    return ",".join(f"DC={part}" for part in domain.split("."))


def _infer_base_dn(entries) -> str | None:
    """Pick the domain root from captured entries: the shortest all-DC= DN."""
    dc_dns = [
        e.dn for e in entries
        if e.dn and all(rdn.strip().lower().startswith("dc=") for rdn in e.dn.split(","))
    ]
    return min(dc_dns, key=lambda d: d.count(",")) if dc_dns else None


def build_directory(identities, hostname: str, base_dn: str | None) -> tuple[str, list[Entry]]:
    """Render identities into a flat list of directory entries + the base DN."""
    if identities is None:
        base = base_dn or "DC=example,DC=local"
        return base, [Entry(base, {"objectClass": ["top", "domain", "domainDNS"]})]

    base = base_dn or _base_dn(identities.domain)
    users_dn = f"CN=Users,{base}"
    entries: list[Entry] = [
        Entry(
            base,
            {
                "objectClass": ["top", "domain", "domainDNS"],
                "dc": [identities.domain.split(".")[0]],
                "distinguishedName": [base],
                "name": [identities.netbios or identities.domain.split(".")[0].upper()],
            },
        ),
        Entry(
            users_dn,
            {
                "objectClass": ["top", "container"],
                "cn": ["Users"],
                "distinguishedName": [users_dn],
            },
        ),
    ]

    user_dn = {u.sam.lower(): f"CN={u.display_name or u.sam},{users_dn}" for u in identities.users}
    group_dn = {g.name.lower(): f"CN={g.name},{users_dn}" for g in identities.groups}

    for u in identities.users:
        dn = user_dn[u.sam.lower()]
        attrs = {
            "objectClass": ["top", "person", "organizationalPerson", "user"],
            "cn": [u.display_name or u.sam],
            "name": [u.display_name or u.sam],
            "sAMAccountName": [u.sam],
            "distinguishedName": [dn],
            "userAccountControl": ["512" if u.enabled else "514"],
        }
        if u.upn:
            attrs["userPrincipalName"] = [u.upn]
        if u.spn:
            attrs["servicePrincipalName"] = [u.spn]
        if u.description:
            attrs["description"] = [u.description]
        memberof = [group_dn[g.lower()] for g in u.groups if g.lower() in group_dn]
        if memberof:
            attrs["memberOf"] = memberof
        entries.append(Entry(dn, attrs))

    for g in identities.groups:
        dn = group_dn[g.name.lower()]
        attrs = {
            "objectClass": ["top", "group"],
            "cn": [g.name],
            "name": [g.name],
            "sAMAccountName": [g.name],
            "distinguishedName": [dn],
            "groupType": ["-2147483646"],
        }
        if g.description:
            attrs["description"] = [g.description]
        members = [user_dn[m.lower()] for m in g.members if m.lower() in user_dn]
        if members:
            attrs["member"] = members
        entries.append(Entry(dn, attrs))

    existing_sams = {u.sam.lower() for u in identities.users}
    existing_groups = {g.name.lower() for g in identities.groups}
    entries += _baseline_entries(base, existing_sams, existing_groups)
    return base, entries


# Well-known objects every real domain ships — their absence (no krbtgt, no Guest, no
# CN=Builtin) is a giveaway that a directory is hand-built. Rendered alongside the
# configured identities so an AD range enumerates like a genuine domain.
_BUILTIN_GROUPS = [
    ("Administrators", "Administrators have complete and unrestricted access to the computer/domain"),
    ("Users", "Users are prevented from making accidental or intentional system-wide changes"),
    ("Guests", "Guests have the same access as members of the Users group by default"),
    ("Backup Operators", "Backup Operators can override security restrictions to back up or restore files"),
    ("Remote Desktop Users", "Members are granted the right to log on remotely"),
    ("Account Operators", "Members can administer domain user and group accounts"),
    ("Server Operators", "Members can administer domain servers"),
    ("Print Operators", "Members can administer printers installed on domain controllers"),
    ("Replicator", "Supports file replication in a domain"),
    ("Pre-Windows 2000 Compatible Access", "A backward compatibility group allowing read access on all users and groups"),
]
_DOMAIN_GROUPS = [
    ("Domain Users", "All domain users"),
    ("Domain Computers", "All workstations and servers joined to the domain"),
    ("Domain Guests", "All domain guests"),
    ("Domain Controllers", "All domain controllers in the domain"),
    ("Cert Publishers", "Members are permitted to publish certificates to the directory"),
    ("Group Policy Creator Owners", "Members can modify group policy for the domain"),
    ("DnsAdmins", "DNS Administrators Group"),
]
_WELL_KNOWN_ACCOUNTS = [
    ("krbtgt", 514, "Key Distribution Center Service Account"),
    ("Guest", 66082, "Built-in account for guest access to the computer/domain"),
    ("Administrator", 66048, "Built-in account for administering the computer/domain"),
]


def _baseline_entries(base: str, existing_sams: set, existing_groups: set) -> list[Entry]:
    users_dn = f"CN=Users,{base}"
    builtin_dn = f"CN=Builtin,{base}"
    out: list[Entry] = []

    for cn, oc in [("Builtin", "builtinDomain"), ("Computers", "container"),
                   ("System", "container"), ("ForeignSecurityPrincipals", "container"),
                   ("Managed Service Accounts", "container"), ("Program Data", "container")]:
        dn = f"CN={cn},{base}"
        out.append(Entry(dn, {"objectClass": ["top", oc], "cn": [cn],
                              "distinguishedName": [dn], "isCriticalSystemObject": ["TRUE"]}))

    for sam, uac, desc in _WELL_KNOWN_ACCOUNTS:
        if sam.lower() in existing_sams:
            continue
        dn = f"CN={sam},{users_dn}"
        out.append(Entry(dn, {
            "objectClass": ["top", "person", "organizationalPerson", "user"],
            "cn": [sam], "name": [sam], "sAMAccountName": [sam], "distinguishedName": [dn],
            "userAccountControl": [str(uac)], "description": [desc],
            "isCriticalSystemObject": ["TRUE"]}))

    for name, desc in _BUILTIN_GROUPS:
        dn = f"CN={name},{builtin_dn}"
        out.append(Entry(dn, {"objectClass": ["top", "group"], "cn": [name], "name": [name],
            "sAMAccountName": [name], "distinguishedName": [dn], "groupType": ["-2147483643"],
            "description": [desc], "isCriticalSystemObject": ["TRUE"]}))

    for name, desc in _DOMAIN_GROUPS:
        if name.lower() in existing_groups:
            continue
        dn = f"CN={name},{users_dn}"
        out.append(Entry(dn, {"objectClass": ["top", "group"], "cn": [name], "name": [name],
            "sAMAccountName": [name], "distinguishedName": [dn], "groupType": ["-2147483646"],
            "description": [desc], "isCriticalSystemObject": ["TRUE"]}))
    return out


_OS_STRINGS = {
    "windows_server_2019": "Windows Server 2019 Standard",
    "windows_server_2022": "Windows Server 2022 Standard",
    "windows_10": "Windows 10 Pro",
    "windows_11": "Windows 11 Pro",
}


def build_computers(hosts, base: str, domain: str) -> list[Entry]:
    """Render Windows range hosts as AD computer objects (DCs under an OU)."""
    win = [h for h in hosts if h.os.value.startswith("windows")]
    if not win:
        return []

    computers_dn = f"CN=Computers,{base}"
    dc_ou = f"OU=Domain Controllers,{base}"
    entries = [
        Entry(computers_dn, {"objectClass": ["top", "container"], "cn": ["Computers"],
                             "distinguishedName": [computers_dn]}),
    ]
    if any("domain-controller" in h.tags for h in win):
        entries.append(Entry(dc_ou, {"objectClass": ["top", "organizationalUnit"],
                                     "ou": ["Domain Controllers"], "distinguishedName": [dc_ou]}))

    for h in win:
        is_dc = "domain-controller" in h.tags
        parent = dc_ou if is_dc else computers_dn
        name = h.hostname.upper()
        dn = f"CN={name},{parent}"
        fqdn = f"{h.hostname.lower()}.{domain}" if domain else h.hostname.lower()
        entries.append(Entry(dn, {
            "objectClass": ["top", "person", "organizationalPerson", "user", "computer"],
            "cn": [name],
            "name": [name],
            "sAMAccountName": [f"{name}$"],
            "dNSHostName": [fqdn],
            "operatingSystem": [_OS_STRINGS.get(h.os.value, "Windows")],
            "distinguishedName": [dn],
            # DCs: server trust account; members: workstation/server trust account.
            "userAccountControl": ["532480" if is_dc else "4096"],
        }))
    return entries


# Control / capability OIDs a real AD DC advertises in its RootDSE. A RootDSE that answers
# only a handful of naming-context attributes is a tell; these are what tooling expects.
_SUPPORTED_CONTROLS = [
    "1.2.840.113556.1.4.319", "1.2.840.113556.1.4.801", "1.2.840.113556.1.4.473",
    "1.2.840.113556.1.4.528", "1.2.840.113556.1.4.417", "1.2.840.113556.1.4.1338",
    "1.2.840.113556.1.4.474", "1.2.840.113556.1.4.1339", "1.2.840.113556.1.4.1413",
    "2.16.840.1.113730.3.4.9", "1.2.840.113556.1.4.1504", "1.2.840.113556.1.4.1852",
    "1.2.840.113556.1.4.802", "1.2.840.113556.1.4.1907", "1.2.840.113556.1.4.1948",
]
_SUPPORTED_CAPABILITIES = [
    "1.2.840.113556.1.4.800", "1.2.840.113556.1.4.1670", "1.2.840.113556.1.4.1791",
    "1.2.840.113556.1.4.1935", "1.2.840.113556.1.4.2080", "1.2.840.113556.1.4.2237",
]


def _ldap_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d%H%M%S.0Z")


def _root_dse(base: str, hostname: str, domain: str) -> Entry:
    fqdn = f"{hostname.lower()}.{domain}" if domain else hostname.lower()
    server = hostname.upper()
    cfg = f"CN=Configuration,{base}"
    sites = f"CN=Default-First-Site-Name,CN=Sites,{cfg}"
    return Entry(
        "",
        {
            "objectClass": ["top"],
            "namingContexts": [base, cfg, f"CN=Schema,{cfg}",
                               f"DC=DomainDnsZones,{base}", f"DC=ForestDnsZones,{base}"],
            "defaultNamingContext": [base],
            "rootDomainNamingContext": [base],
            "configurationNamingContext": [cfg],
            "schemaNamingContext": [f"CN=Schema,{cfg}"],
            "subschemaSubentry": [f"CN=Aggregate,CN=Schema,{cfg}"],
            "supportedLDAPVersion": ["3", "2"],
            "supportedControl": _SUPPORTED_CONTROLS,
            "supportedSASLMechanisms": ["GSSAPI", "GSS-SPNEGO", "EXTERNAL", "DIGEST-MD5"],
            "supportedCapabilities": _SUPPORTED_CAPABILITIES,
            "dnsHostName": [fqdn],
            "serverName": [f"CN={server},CN=Servers,{sites}"],
            "dsServiceName": [f"CN=NTDS Settings,CN={server},CN=Servers,{sites}"],
            "ldapServiceName": [f"{domain}:{server}$@{domain.upper()}" if domain else server],
            "isSynchronized": ["TRUE"],
            "isGlobalCatalogReady": ["TRUE"],
            "highestCommittedUSN": ["163994"],
            "domainFunctionality": ["7"],
            "forestFunctionality": ["7"],
            "domainControllerFunctionality": ["7"],
        },
    )


# --------------------------------------------------------------------------- DN helpers


def _norm(dn: str) -> str:
    return ",".join(p.strip() for p in dn.lower().split(","))


def _parent(dn: str) -> str:
    return _norm(dn).split(",", 1)[1] if "," in dn else ""


def in_scope(entry_dn: str, base: str, scope: int) -> bool:
    e, b = _norm(entry_dn), _norm(base)
    if scope == 0:  # base
        return e == b
    if scope == 1:  # one level
        return _parent(entry_dn) == b
    return e == b or e.endswith("," + b)  # subtree


# ------------------------------------------------------------------------ filter eval


def eval_filter(f, entry: Entry) -> bool:
    try:
        name = f.getName()
        if name == "and":
            return all(eval_filter(sub, entry) for sub in f["and"])
        if name == "or":
            return any(eval_filter(sub, entry) for sub in f["or"])
        if name == "not":
            return not eval_filter(f["not"], entry)
        if name == "present":
            return bool(entry.get(str(f["present"])))
        if name == "equalityMatch":
            ava = f["equalityMatch"]
            attr = str(ava["attributeDesc"])
            want = _octets(ava["assertionValue"]).lower()
            return any(v.lower() == want for v in entry.get(attr))
        if name == "substrings":
            sub = f["substrings"]
            return _match_substrings(entry.get(str(sub["type"])), sub["substrings"])
        # greaterOrEqual / lessOrEqual / approxMatch / extensibleMatch: treat approx as
        # equality; others are unsupported and do not match.
        if name == "approxMatch":
            ava = f["approxMatch"]
            want = _octets(ava["assertionValue"]).lower()
            return any(v.lower() == want for v in entry.get(str(ava["attributeDesc"])))
        return False
    except (PyAsn1Error, KeyError, AttributeError):
        # Be permissive on anything we cannot parse so enumeration still returns data.
        return True


def _match_substrings(values: list[str], substrings) -> bool:
    if not values:
        return False
    initial, anys, final = None, [], None
    for item in substrings:
        which = item.getName()
        val = _octets(item[which]).lower()
        if which == "initial":
            initial = val
        elif which == "final":
            final = val
        else:
            anys.append(val)
    for v in values:
        lv = v.lower()
        if initial and not lv.startswith(initial):
            continue
        if final and not lv.endswith(final):
            continue
        pos, ok = 0, True
        for a in anys:
            idx = lv.find(a, pos)
            if idx < 0:
                ok = False
                break
            pos = idx + len(a)
        if ok:
            return True
    return False


def _octets(value) -> str:
    try:
        return bytes(value).decode("utf-8", "replace")
    except Exception:
        return str(value)


def _bind_user(bind_dn: str) -> str:
    """Extract the sAMAccountName from a bind DN — UPN (user@dom), DOMAIN\\user, or a DN
    whose leftmost RDN is the account (cn=user,...). Lowercased to match the password map."""
    s = bind_dn.strip()
    if "@" in s:
        return s.split("@", 1)[0].lower()
    if "\\" in s:
        return s.split("\\", 1)[1].lower()
    if "=" in s:
        return s.split(",", 1)[0].split("=", 1)[1].strip().lower()
    return s.lower()


def filter_to_str(f) -> str:
    try:
        name = f.getName()
        if name == "and":
            return "(&" + "".join(filter_to_str(s) for s in f["and"]) + ")"
        if name == "or":
            return "(|" + "".join(filter_to_str(s) for s in f["or"]) + ")"
        if name == "not":
            return "(!" + filter_to_str(f["not"]) + ")"
        if name == "present":
            return f"({str(f['present'])}=*)"
        if name in ("equalityMatch", "approxMatch"):
            ava = f[name]
            op = "~=" if name == "approxMatch" else "="
            return f"({str(ava['attributeDesc'])}{op}{_octets(ava['assertionValue'])})"
        if name == "substrings":
            sub = f["substrings"]
            parts = [_octets(i[i.getName()]) for i in sub["substrings"]]
            return f"({str(sub['type'])}=*{'*'.join(parts)}*)"
        return "(?)"
    except (PyAsn1Error, KeyError, AttributeError):
        return "(?)"


# ------------------------------------------------------------------------- the facade


@register("ldap")
class LdapFacade(Facade):
    def __init__(self, *, cfg: LdapConfig, ctx: FacadeContext, service_id: str):
        super().__init__(
            bind_host=cfg.bind, port=cfg.port, ctx=ctx, service_id=service_id, protocol="ldap"
        )
        self.cfg = cfg
        identities = ctx.identities
        domain = identities.domain if identities else ""

        if identities is not None:
            self.base_dn, entries = build_directory(identities, ctx.host_name, cfg.base_dn)
            entries += build_computers(ctx.hosts, self.base_dn, domain)
        else:
            self.base_dn = cfg.base_dn or _infer_base_dn(cfg.entries) or "DC=example,DC=local"
            entries = []

        # Replay raw captured entries verbatim (dn="" overrides the RootDSE).
        root_override = None
        for e in cfg.entries:
            if e.dn == "":
                root_override = e
            else:
                entries.append(Entry(e.dn, {k: list(v) for k, v in e.attributes.items()}))

        # Dedup by DN (build_directory and build_computers can both emit CN=Computers, etc.),
        # keeping the first — the richer baseline container over the bare one.
        seen: set = set()
        self.entries = []
        for e in entries:
            key = _norm(e.dn)
            if key in seen:
                continue
            seen.add(key)
            self.entries.append(e)
        if root_override is not None:
            self.root_dse = Entry("", {k: list(v) for k, v in root_override.attributes.items()})
        else:
            self.root_dse = _root_dse(self.base_dn, ctx.host_name, domain)

        # For NTLM (Sicily) bind validation.
        self._passwords = {
            u.sam.lower(): u.password
            for u in (identities.users if identities else [])
            if u.password
        }
        self._netbios = (
            (identities.netbios or identities.domain.split(".")[0].upper())
            if identities else "WORKGROUP"
        )

    @classmethod
    def from_config(cls, cfg: LdapConfig, ctx: FacadeContext) -> "LdapFacade":
        self = cls(cfg=cfg, ctx=ctx, service_id=f"{'ldaps' if cfg.tls else 'ldap'}-{cfg.port}")
        if cfg.tls:
            from rangefinder.tls import server_context

            self.protocol = "ldaps"
            self.ssl_context = server_context(ctx.host_name, self.tls_sans())
        return self

    async def handle(self, scope, reader, writer):
        ntlm_state: dict = {}  # per-connection NTLM (Sicily) bind state
        session: dict = {"authenticated": False}  # flips on any successful bind
        while True:
            substrate = await _read_message(reader)
            if substrate is None:
                return
            try:
                msg, _ = decoder.decode(substrate, asn1Spec=L.LDAPMessage())
            except PyAsn1Error:
                # rfc2251 can't decode an MS Sicily (NTLM) bind; handle it out of band.
                if await self._handle_sicily(scope, writer, substrate, ntlm_state, session):
                    continue
                return  # genuinely malformed
            mid = int(msg["messageID"])
            op = msg["protocolOp"]
            kind = op.getName()

            if kind == "bindRequest":
                req = op["bindRequest"]
                auth = req["authentication"]
                if auth.getName() == "sasl" and str(auth["sasl"]["mechanism"]) == "GSS-SPNEGO":
                    await self._handle_spnego(scope, writer, mid, bytes(auth["sasl"]["credentials"]), ntlm_state, session)
                else:
                    await self._handle_bind(scope, writer, mid, req, session)
            elif kind == "searchRequest":
                await self._handle_search(scope, writer, mid, op["searchRequest"], session)
            elif kind == "unbindRequest":
                return
            elif kind == "extendedReq":
                # e.g. StartTLS / whoami — decline uniformly.
                er = L.ExtendedResponse()
                er["resultCode"] = "protocolError"
                er["matchedDN"] = ""
                er["errorMessage"] = "extended operation not supported"
                writer.write(_encode(mid, "extendedResp", er))
                await writer.drain()
            # abandonRequest and unhandled ops: silently ignore (no response expected)

    async def _handle_spnego(self, scope, writer, mid: int, creds: bytes, state: dict, session: dict) -> None:
        """NTLM over LDAP via SASL GSS-SPNEGO (what GetUserSPNs / BloodHound use)."""
        import struct

        from impacket.spnego import SPNEGO_NegTokenResp, TypesMech

        from rangefinder.ntlm import build_challenge, nt_hash, validate

        token = _extract_ntlm_token(creds)
        if token is None or len(token) < 12:
            writer.write(_bind_response(mid, 49))
            await writer.drain()
            return
        msg_type = struct.unpack("<I", token[8:12])[0]

        if msg_type == 1:  # NTLM Type1 -> challenge, returned in serverSaslCreds
            type2, challenge8, neg, chal = build_challenge(token, self.ctx.host_name.upper(), self._netbios)
            state.update(challenge8=challenge8, neg=neg, chal=chal)
            resp = SPNEGO_NegTokenResp()
            resp["NegState"] = b"\x01"  # accept-incomplete
            resp["SupportedMech"] = TypesMech["NTLMSSP - Microsoft NTLM Security Support Provider"]
            resp["ResponseToken"] = type2
            writer.write(_bind_response(mid, 14, server_sasl_creds=resp.getData()))  # saslBindInProgress
            await writer.drain()
            return

        if msg_type == 3:  # NTLM Type3 -> validate
            neg, chal, challenge8 = state.get("neg"), state.get("chal"), state.get("challenge8")
            if neg is None:
                writer.write(_bind_response(mid, 49))
                await writer.drain()
                return
            domain, user, _ws, _ = validate(token, None, challenge8, neg, chal)
            pw = self._passwords.get(user.lower())
            _, _, _, ok = validate(token, nt_hash(pw) if pw else None, challenge8, neg, chal)
            session["authenticated"] = ok  # RFC 4513: a failed bind drops to unauthenticated
            writer.write(_bind_response(mid, 0 if ok else 49))
            await writer.drain()
            scope.emit(ev.ldap_bind(
                scope, bind_dn=f"{domain}\\{user}" if domain else user,
                method="ntlm", result_code="success" if ok else "invalidCredentials", password=None,
            ))
            return
        writer.write(_bind_response(mid, 49))
        await writer.drain()

    async def _handle_sicily(self, scope, writer, substrate: bytes, state: dict, session: dict) -> bool:
        """Handle an MS-style NTLM (Sicily) LDAP bind. Returns True if it was one."""
        parsed = _parse_sicily_bind(substrate)
        if parsed is None:
            return False
        mid, tag, blob = parsed

        if tag == 0x89:  # sicilyPackageDiscovery — advertise NTLM
            writer.write(_bind_response(mid, 0, b"NTLM"))
            await writer.drain()
            return True

        if tag == 0x8A:  # sicilyNegotiate — client's NTLM Type1
            from rangefinder.ntlm import build_challenge

            type2, challenge8, neg, chal = build_challenge(blob, self.ctx.host_name.upper(), self._netbios)
            state.update(challenge8=challenge8, neg=neg, chal=chal)
            # The Type2 challenge is returned in matchedDN with resultCode success.
            writer.write(_bind_response(mid, 0, type2))
            await writer.drain()
            return True

        if tag == 0x8B:  # sicilyResponse — client's NTLM Type3
            from rangefinder.ntlm import nt_hash, validate

            neg, chal, challenge8 = state.get("neg"), state.get("chal"), state.get("challenge8")
            if neg is None:
                writer.write(_bind_response(mid, 49))  # no challenge issued
                await writer.drain()
                return True
            domain, user, workstation, _ = validate(blob, None, challenge8, neg, chal)
            pw = self._passwords.get(user.lower())
            _, _, _, ok = validate(blob, nt_hash(pw) if pw else None, challenge8, neg, chal)
            session["authenticated"] = ok  # RFC 4513: a failed bind drops to unauthenticated
            writer.write(_bind_response(mid, 0 if ok else 49))
            await writer.drain()
            scope.emit(ev.ldap_bind(
                scope, bind_dn=f"{domain}\\{user}" if domain else user,
                method="ntlm", result_code="success" if ok else "invalidCredentials",
                password=None,
            ))
            return True
        return False

    async def _handle_bind(self, scope: ConnScope, writer, mid: int, req, session: dict) -> None:
        bind_dn = str(req["name"])
        auth = req["authentication"]
        method = auth.getName()
        password = None
        if method == "simple":
            password = _octets(auth["simple"])

        anonymous = not bind_dn and not password
        if anonymous:
            result = "success" if self.cfg.allow_anonymous_bind else "inappropriateAuthentication"
        elif method == "simple":
            # Validate against a known credential when we have one (identities-rendered users):
            # a real DC returns invalidCredentials for a wrong password, and answering "success"
            # to any password is both wrong and an obvious decoy tell.
            known = self._passwords.get(_bind_user(bind_dn))
            if known is not None:
                result = "success" if password == known else "invalidCredentials"
            elif self.cfg.allow_anonymous_bind:
                # Open directory: we can't validate (no stored password) but anonymous can read
                # anyway, so a permissive success keeps captured-directory replay working without
                # widening exposure.
                result = "success"
            else:
                # Hardened directory + a credential we cannot validate: FAIL CLOSED. Answering
                # "success" here would let `ldapsearch -D cn=anything -w whatever` unlock the
                # gated directory — fabricating a credential-access finding a real DC (which
                # returns invalidCredentials for an unverifiable principal) would never allow.
                result = "invalidCredentials"
        else:
            result = "success"

        # RFC 4513: a bind attempt resets the connection's auth state — success authenticates,
        # any failure drops it back to unauthenticated (so a failed re-bind can't keep a gated
        # directory unlocked).
        session["authenticated"] = result == "success"

        br = L.BindResponse()
        br["resultCode"] = result
        br["matchedDN"] = ""
        br["errorMessage"] = ""
        writer.write(_encode(mid, "bindResponse", br))
        await writer.drain()

        scope.emit(
            ev.ldap_bind(
                scope,
                bind_dn=bind_dn,
                method="anonymous" if anonymous else method,
                result_code=result,
                password=password or None,
            )
        )

    async def _handle_search(self, scope: ConnScope, writer, mid: int, req, session: dict) -> None:
        base = str(req["baseObject"])
        scope_i = int(req["scope"])
        size_limit = int(req["sizeLimit"])
        types_only = bool(req["typesOnly"])
        requested = [str(a) for a in req["attributes"]]
        filt = req["filter"]

        is_rootdse = base == "" and scope_i == 0
        # Anonymous operations disabled + no successful bind: a real DC refuses the search with
        # operationsError ("a successful bind must be completed"). The RootDSE stays exempt
        # (RFC 4513 permits an anonymous RootDSE read even when anon bind is disabled). This is
        # what keeps a credentialed-captured twin from serving its privileged view to an unbound
        # client — the fail-open the capture is careful never to configure.
        if not self.cfg.allow_anonymous_bind and not session["authenticated"] and not is_rootdse:
            done = L.SearchResultDone()
            done["resultCode"] = "operationsError"
            done["matchedDN"] = ""
            done["errorMessage"] = ("000004DC: LdapErr: DSID-0C090A5C, comment: In order to "
                                    "perform this operation a successful bind must be completed")
            writer.write(_encode(mid, "searchResDone", done))
            await writer.drain()
            scope.emit(ev.ldap_search(
                scope, base=base or "(RootDSE)",
                search_scope=_SCOPE_NAMES.get(scope_i, str(scope_i)),
                filter_str=filter_to_str(filt), entries=0))
            return

        # RootDSE: empty base + base scope is the client's first question. currentTime is an
        # operational attribute that must be live, so inject it fresh per query.
        if is_rootdse:
            candidates = [Entry("", {**self.root_dse.attrs, "currentTime": [_ldap_now()]})]
        else:
            candidates = [
                e
                for e in self.entries
                if in_scope(e.dn, base, scope_i) and eval_filter(filt, e)
            ]

        truncated = False
        if size_limit and len(candidates) > size_limit:
            candidates = candidates[:size_limit]
            truncated = True

        for entry in candidates:
            writer.write(_encode(mid, "searchResEntry", _entry_msg(entry, requested, types_only)))
        await writer.drain()

        done = L.SearchResultDone()
        done["resultCode"] = "sizeLimitExceeded" if truncated else "success"
        done["matchedDN"] = ""
        done["errorMessage"] = ""
        writer.write(_encode(mid, "searchResDone", done))
        await writer.drain()

        scope.emit(
            ev.ldap_search(
                scope,
                base=base or "(RootDSE)",
                search_scope=_SCOPE_NAMES.get(scope_i, str(scope_i)),
                filter_str=filter_to_str(filt),
                entries=len(candidates),
            )
        )


# ------------------------------------------------------------------- wire + encoding


async def _read_message(reader: asyncio.StreamReader) -> bytes | None:
    """Read exactly one BER-framed LDAPMessage; None on EOF/short read."""
    try:
        tag = await reader.readexactly(1)
        first = await reader.readexactly(1)
        length_bytes = first
        if first[0] < 0x80:
            length = first[0]
        else:
            n = first[0] & 0x7F
            if n == 0:  # indefinite length not used by LDAP
                return None
            more = await reader.readexactly(n)
            length_bytes = first + more
            length = int.from_bytes(more, "big")
        body = await reader.readexactly(length)
    except (asyncio.IncompleteReadError, ConnectionError):
        return None
    return tag + length_bytes + body


def _read_tlv(data: bytes, off: int):
    tag = data[off]
    off += 1
    length = data[off]
    off += 1
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(data[off:off + n], "big")
        off += n
    return tag, data[off:off + length], off + length


def _parse_sicily_bind(substrate: bytes):
    """Extract (messageID, sicily-auth-tag, ntlm-blob) from a Sicily bind, else None.

    The rfc2251 decoder rejects the Sicily authentication tags ([9]/[10]/[11]), so we walk
    the BER by hand just far enough to pull out the NTLM token.
    """
    try:
        tag, seq, _ = _read_tlv(substrate, 0)
        if tag != 0x30:  # LDAPMessage SEQUENCE
            return None
        off = 0
        mtag, mval, off = _read_tlv(seq, off)  # messageID
        if mtag != 0x02:
            return None
        message_id = int.from_bytes(mval, "big")
        ptag, pval, off = _read_tlv(seq, off)  # protocolOp
        if ptag != 0x60:  # bindRequest [APPLICATION 0]
            return None
        boff = 0
        _, _, boff = _read_tlv(pval, boff)  # version
        _, _, boff = _read_tlv(pval, boff)  # name
        atag, aval, boff = _read_tlv(pval, boff)  # authentication
        if atag in (0x89, 0x8A, 0x8B):  # sicilyPackageDiscovery / Negotiate / Response
            return message_id, atag, aval
        return None
    except (IndexError, ValueError):
        return None


def _bind_response(message_id: int, result_code: int, matched_dn: bytes = b"",
                   server_sasl_creds: bytes | None = None) -> bytes:
    br = L.BindResponse()
    br["resultCode"] = result_code
    br["matchedDN"] = matched_dn  # carries the NTLM Type2 for a sicilyNegotiate reply
    br["errorMessage"] = b""
    if server_sasl_creds is not None:
        br["serverSaslCreds"] = server_sasl_creds  # carries the Type2 for GSS-SPNEGO
    return _encode(message_id, "bindResponse", br)


def _extract_ntlm_token(creds: bytes) -> bytes | None:
    """Pull the raw NTLM message out of a SASL GSS-SPNEGO credential blob."""
    if not creds:
        return None
    from impacket.spnego import SPNEGO_NegTokenInit, SPNEGO_NegTokenResp

    try:
        if creds[0] == 0x60:  # NegTokenInit (first message)
            return bytes(SPNEGO_NegTokenInit(creds)["MechToken"])
        if creds[0] == 0xA1:  # NegTokenResp (subsequent)
            return bytes(SPNEGO_NegTokenResp(creds)["ResponseToken"])
        if creds[:7] == b"NTLMSSP":  # raw NTLM (no SPNEGO wrapper)
            return creds
    except Exception:
        return None
    return None


def _encode(message_id: int, op_name: str, op) -> bytes:
    m = L.LDAPMessage()
    m["messageID"] = message_id
    m["protocolOp"][op_name] = op
    return encoder.encode(m)


def _entry_msg(entry: Entry, requested: list[str], types_only: bool):
    sre = L.SearchResultEntry()
    sre["objectName"] = entry.dn
    attrs = _select_attrs(entry.attrs, requested)
    pal = sre["attributes"]
    for i, (name, values) in enumerate(attrs.items()):
        pa = pal.componentType.clone()
        pa["type"] = name
        if not types_only:
            vals = pa["vals"]
            for j, v in enumerate(values):
                vals.setComponentByPosition(j, v)
        pal.setComponentByPosition(i, pa)
    return sre


def _select_attrs(attrs: dict[str, list[str]], requested: list[str]) -> dict[str, list[str]]:
    if not requested or "*" in requested:
        return attrs
    if requested == ["1.1"]:  # RFC 4511: return no attributes
        return {}
    want = {r.lower() for r in requested}
    return {k: v for k, v in attrs.items() if k.lower() in want}
