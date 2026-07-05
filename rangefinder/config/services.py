"""Per-service configuration models and the built-in service discriminated union.

Every service variant carries a ``type`` literal that acts as the discriminator and
as the key into the facade registry. Variants use ``extra="forbid"`` so config typos
become hard errors at ``rangefinder validate`` time rather than silent no-ops.

v1 ships runtime facades for ``http`` and ``banner`` only. ``ldap``/``smb``/``dns``
config models are defined here so configs are forward-shaped and appear in the exported
JSON Schema, but their protocol facades land in v2 — ``build_facade`` raises a clear
"not yet implemented" error if a range actually uses them. The shipped example range
represents a domain controller's 389/445/53 as ``banner`` decoys so it runs fully today.
"""

from __future__ import annotations

from typing import Annotated, Literal, Union

from pydantic import BaseModel, ConfigDict, Field


class ServiceBase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # No default: every service must declare a port unless a variant overrides this.
    port: int = Field(ge=1, le=65535)
    # Bind address inside the container. 0.0.0.0 is correct for the one-container-per-host
    # model; tests override to 127.0.0.1.
    bind: str = "0.0.0.0"


# --------------------------------------------------------------------------- HTTP


class HttpPath(BaseModel):
    """A single canned route. Matched by exact path (see HttpConfig.paths keys)."""

    model_config = ConfigDict(extra="forbid")

    methods: list[str] = Field(default_factory=lambda: ["GET"])
    status: int = 200
    body: str | None = None
    body_file: str | None = None  # resolved relative to the config file's directory
    content_type: str = "text/html; charset=utf-8"
    headers: dict[str, str] = Field(default_factory=dict)
    # Tagging a route with vuln_id turns its hits into ECS "alert" telemetry events —
    # the hook a SIEM detection rule fires on.
    vuln_id: str | None = None
    # HTTP Basic auth gating. When auth_realm is set the route returns 401 until valid
    # credentials arrive; auth_users maps accepted username -> password (empty = reject
    # all, but still capture every attempt as telemetry).
    auth_realm: str | None = None
    auth_users: dict[str, str] = Field(default_factory=dict)
    # NTLM (Windows integrated) auth: the route challenges with WWW-Authenticate: NTLM and
    # validates the Type3 against the identities NT hashes (IIS/Exchange-style).
    auth_ntlm: bool = False


class HttpConfig(ServiceBase):
    type: Literal["http"] = "http"
    port: int = Field(default=80, ge=1, le=65535)
    tls: bool = False  # serve HTTPS with a self-signed cert
    server_header: str = "Apache/2.4.52 (Ubuntu)"
    extra_headers: dict[str, str] = Field(default_factory=dict)
    paths: dict[str, HttpPath] = Field(default_factory=dict)
    default_status: int = 404
    default_body: str | None = None
    default_content_type: str = "text/html; charset=utf-8"
    keepalive: bool = True


# ------------------------------------------------------------------------- Banner


class BannerRule(BaseModel):
    """A request/response rule applied after the banner is sent.

    Text mode matches ``match`` (regex) against each received line and replies with
    ``respond``. Binary mode (see ``BannerConfig.binary``) matches ``match_hex`` (hex
    bytes, substring) against the raw bytes read and replies with ``respond_hex``.
    """

    model_config = ConfigDict(extra="forbid")

    match: str = ""  # regex tested against each received line (text mode)
    respond: str = ""
    match_hex: str | None = None  # hex bytes to look for in the raw read (binary mode)
    respond_hex: str | None = None  # hex bytes to send in reply (binary mode)
    raw: bool = False  # text mode: if False, the terminator is appended to the response
    close_after: bool = False


class KerberosConfig(ServiceBase):
    """Minimal KDC facade for AS-REP roasting (Kerberoasting to follow).

    Users come from top-level ``identities`` (their ``password`` derives the account key,
    ``no_preauth`` makes them AS-REP roastable). ``krbtgt_password`` keys the TGT the
    attacker never cracks.
    """

    type: Literal["kerberos"] = "kerberos"
    port: int = Field(default=88, ge=1, le=65535)
    realm: str | None = None  # default: identities.domain uppercased
    krbtgt_password: str = "Krbtgt-Rand0m-Passw0rd!"


class SshConfig(ServiceBase):
    """Real SSH server (asyncssh): performs KEX, captures + rejects auth attempts."""

    type: Literal["ssh"] = "ssh"
    port: int = Field(default=22, ge=1, le=65535)
    server_version: str = "OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
    # username -> password that are accepted (dropped into the decoy shell). Empty =
    # reject everything (capture only).
    accept_creds: dict[str, str] = Field(default_factory=dict)
    motd: str = ""


class BannerConfig(ServiceBase):
    """Generic server-speaks-first TCP facade (SSH/FTP/SMTP-style version detection).

    Set ``banner_hex`` to send a raw binary greeting (e.g. a MySQL server handshake) and
    ``binary: true`` to switch the read loop to raw bytes + hex rules (e.g. answering an
    RDP X.224 Connection Request), so nmap ``-sV`` can fingerprint protocols a text banner
    cannot represent.
    """

    type: Literal["banner"] = "banner"
    banner: str = ""
    banner_hex: str | None = None  # raw binary greeting sent on connect (overrides banner)
    binary: bool = False  # read raw bytes and match hex rules instead of lines
    terminator: str = "\r\n"
    banner_delay_ms: int = Field(default=0, ge=0)
    rules: list[BannerRule] = Field(default_factory=list)
    idle_timeout_s: float = Field(default=30.0, gt=0)
    close_after_banner: bool = False
    # Application-layer label recorded in telemetry (network.protocol), e.g. "ssh".
    protocol: str = "tcp"


# --------------------------------------------------- v2 forward models (no facade yet)


class LdapEntry(BaseModel):
    """A raw directory entry (a captured DN + its attributes) replayed verbatim.

    dn="" is the RootDSE. This is how `rangefinder capture ldap` records a real directory:
    exactly the entries an anonymous (or credentialed) search returned.
    """

    model_config = ConfigDict(extra="forbid")

    dn: str
    attributes: dict[str, list[str]] = Field(default_factory=dict)


class LdapConfig(ServiceBase):
    type: Literal["ldap"] = "ldap"
    port: int = Field(default=389, ge=1, le=65535)
    tls: bool = False  # serve LDAPS (implicit TLS, typically port 636)
    base_dn: str | None = None  # default derived from identities.domain / entries
    allow_anonymous_bind: bool = True
    # Raw captured entries served verbatim (in addition to any rendered from identities).
    entries: list[LdapEntry] = Field(default_factory=list)


class SmbShare(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    comment: str = ""
    readonly: bool = True
    # Faithful access model. A real server enumerates its share names to a null session but may
    # deny that session read access to the share's contents. When True, the share is listed by
    # ``smbclient -L`` / NetrShareEnum (enumeration transfers) but a null/anonymous tree connect
    # is refused with STATUS_ACCESS_DENIED — so the twin reproduces the captured access decision
    # instead of serving the (empty, because unreadable at capture time) share wide open.
    restrict_anonymous: bool = False
    files: dict[str, str] = Field(default_factory=dict)


class SmbConfig(ServiceBase):
    type: Literal["smb"] = "smb"
    port: int = Field(default=445, ge=1, le=65535)
    signing_required: bool = True
    server_os: str = "Windows Server 2022 Standard 20348"
    # Highest SMB2 dialect the negotiate response will advertise. The facade adds proper
    # 3.1.1 negotiate contexts (preauth-integrity + encryption/signing capabilities) so recon
    # tooling sees a modern Windows service; anonymous enumeration works at every dialect.
    # (A signed/credentialed 3.1.1 session needs AES-CMAC the impacket backend can't do, so
    # signing stays advertised-not-required at 3.1.1 — see the facade's signing note.)
    max_dialect: Literal["2.0.2", "2.1", "3.0", "3.1.1"] = "3.1.1"
    # Security posture. Defaults are FAIL-CLOSED (restrictive): a field the capture could not
    # measure must never make the twin *more* exposed than the real host, since a fail-open
    # default fabricates findings. Capture overwrites these with measured values and records the
    # provenance (measured / assumed) in the capture report.
    #   smb1_enabled: answer the legacy SMB1 (NT LM 0.12) negotiate. Modern hosts disable it; a
    #     disabled twin refuses the SMB1 negotiate (no common dialect), as the real host does.
    #   reject_unknown_users: reject a non-anonymous logon whose account isn't known (real
    #     hardened behaviour), instead of impacket's default of mapping any credential to guest.
    #     Null-session (anonymous) enumeration is unaffected either way.
    smb1_enabled: bool = False
    reject_unknown_users: bool = True
    shares: list[SmbShare] = Field(default_factory=list)


class DnsRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    type: Literal["A", "AAAA", "CNAME", "TXT", "SRV", "MX", "SOA", "NS"] = "A"
    value: str
    ttl: int = 300


class DnsConfig(ServiceBase):
    type: Literal["dns"] = "dns"
    port: int = Field(default=53, ge=1, le=65535)
    zone: str | None = None  # default from identities.domain
    records: list[DnsRecord] = Field(default_factory=list)
    autofill_hosts: bool = True
    # Security posture (FAIL-CLOSED). A zone transfer (AXFR) leaking the whole zone is a classic
    # anonymous exposure; the twin reproduces it only when the capture measured the real server
    # permitting it. Default False = refuse AXFR, so an unmeasured host can never fabricate a
    # "zone transfer allowed" finding. Capture overwrites this with the measured value.
    axfr_allowed: bool = False


class RdpConfig(ServiceBase):
    type: Literal["rdp"] = "rdp"
    port: int = Field(default=3389, ge=1, le=65535)
    # A modern hardened Windows host requires CredSSP/NLA: it answers the X.224 negotiation,
    # upgrades to TLS, and challenges over CredSSP (which leaks its name/domain/OS). When
    # False the host also accepts plain TLS (PROTOCOL_SSL) without NLA.
    nla_required: bool = True
    # Leaked to rdp-ntlm-info via the NTLM Version field in the CredSSP challenge, so it must
    # match the host: Server 2022=10.0.20348, Server 2019=10.0.17763, Win11=10.0.22631,
    # Win10=10.0.19045.
    os_version: str = "10.0.20348"


# The discriminated union authored in host.services[]. The discriminator lets pydantic
# route each object to the right model by its "type" key, and produces a JSON Schema
# oneOf that editors use for per-variant autocomplete.
BuiltinService = Annotated[
    Union[HttpConfig, BannerConfig, SshConfig, KerberosConfig, LdapConfig, SmbConfig, DnsConfig, RdpConfig],
    Field(discriminator="type"),
]

# Service types that have a working runtime facade in this release.
IMPLEMENTED_TYPES = frozenset({"http", "banner", "ssh", "kerberos", "ldap", "smb", "dns", "rdp"})
