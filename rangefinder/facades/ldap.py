"""Enumeration-grade LDAP facade.

Answers anonymous BIND + SEARCH from ldapsearch / enum4linux / windapsearch against a
directory built from the range's ``identities`` (domain, users, groups). It speaks real
LDAPv3 over the wire (BER via pyasn1 + the rfc2251 schema), supports the RootDSE query
and the filter operators enumeration tools actually send (and/or/not/equality/present/
substrings), and logs every bind and search.

Deliberate limits: no password validation (any simple bind succeeds — attempted
credentials are captured as telemetry), no writes, no SASL/StartTLS, no paged-results
control. It renders a directory for enumeration; it is not a domain controller.
"""

from __future__ import annotations

import asyncio
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

    return base, entries


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


def _root_dse(base: str, hostname: str, domain: str) -> Entry:
    fqdn = f"{hostname.lower()}.{domain}" if domain else hostname.lower()
    return Entry(
        "",
        {
            "objectClass": ["top"],
            "namingContexts": [base, f"CN=Configuration,{base}"],
            "defaultNamingContext": [base],
            "rootDomainNamingContext": [base],
            "configurationNamingContext": [f"CN=Configuration,{base}"],
            "schemaNamingContext": [f"CN=Schema,CN=Configuration,{base}"],
            "supportedLDAPVersion": ["3"],
            "dnsHostName": [fqdn],
            "serverName": [f"CN={hostname.upper()},CN=Servers,{base}"],
            "dsServiceName": [f"CN=NTDS Settings,CN={hostname.upper()},{base}"],
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
        self.base_dn, entries = build_directory(identities, ctx.host_name, cfg.base_dn)
        entries += build_computers(ctx.hosts, self.base_dn, domain)
        self.entries = entries
        self.root_dse = _root_dse(self.base_dn, ctx.host_name, domain)

    @classmethod
    def from_config(cls, cfg: LdapConfig, ctx: FacadeContext) -> "LdapFacade":
        self = cls(cfg=cfg, ctx=ctx, service_id=f"{'ldaps' if cfg.tls else 'ldap'}-{cfg.port}")
        if cfg.tls:
            from rangefinder.tls import server_context

            self.protocol = "ldaps"
            self.ssl_context = server_context(ctx.host_name, self.tls_sans())
        return self

    async def handle(self, scope, reader, writer):
        while True:
            substrate = await _read_message(reader)
            if substrate is None:
                return
            try:
                msg, _ = decoder.decode(substrate, asn1Spec=L.LDAPMessage())
            except PyAsn1Error:
                return  # malformed; drop the connection
            mid = int(msg["messageID"])
            op = msg["protocolOp"]
            kind = op.getName()

            if kind == "bindRequest":
                await self._handle_bind(scope, writer, mid, op["bindRequest"])
            elif kind == "searchRequest":
                await self._handle_search(scope, writer, mid, op["searchRequest"])
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

    async def _handle_bind(self, scope: ConnScope, writer, mid: int, req) -> None:
        bind_dn = str(req["name"])
        auth = req["authentication"]
        method = auth.getName()
        password = None
        if method == "simple":
            password = _octets(auth["simple"])

        anonymous = not bind_dn and not password
        if anonymous and not self.cfg.allow_anonymous_bind:
            result = "inappropriateAuthentication"
        else:
            # Decoy: never validates credentials; any bind "succeeds".
            result = "success"

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

    async def _handle_search(self, scope: ConnScope, writer, mid: int, req) -> None:
        base = str(req["baseObject"])
        scope_i = int(req["scope"])
        size_limit = int(req["sizeLimit"])
        types_only = bool(req["typesOnly"])
        requested = [str(a) for a in req["attributes"]]
        filt = req["filter"]

        # RootDSE: empty base + base scope is the client's first question.
        if base == "" and scope_i == 0:
            candidates = [self.root_dse]
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
