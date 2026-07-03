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


class HttpConfig(ServiceBase):
    type: Literal["http"] = "http"
    port: int = Field(default=80, ge=1, le=65535)
    server_header: str = "Apache/2.4.52 (Ubuntu)"
    extra_headers: dict[str, str] = Field(default_factory=dict)
    paths: dict[str, HttpPath] = Field(default_factory=dict)
    default_status: int = 404
    default_body: str | None = None
    default_content_type: str = "text/html; charset=utf-8"
    keepalive: bool = True


# ------------------------------------------------------------------------- Banner


class BannerRule(BaseModel):
    """A line-oriented request/response rule applied after the banner is sent."""

    model_config = ConfigDict(extra="forbid")

    match: str  # regex tested against each received line
    respond: str
    raw: bool = False  # if False, the terminator is appended to the response
    close_after: bool = False


class BannerConfig(ServiceBase):
    """Generic server-speaks-first TCP facade (SSH/FTP/SMTP-style version detection)."""

    type: Literal["banner"] = "banner"
    banner: str
    terminator: str = "\r\n"
    banner_delay_ms: int = Field(default=0, ge=0)
    rules: list[BannerRule] = Field(default_factory=list)
    idle_timeout_s: float = Field(default=30.0, gt=0)
    close_after_banner: bool = False
    # Application-layer label recorded in telemetry (network.protocol), e.g. "ssh".
    protocol: str = "tcp"


# --------------------------------------------------- v2 forward models (no facade yet)


class LdapConfig(ServiceBase):
    type: Literal["ldap"] = "ldap"
    port: int = Field(default=389, ge=1, le=65535)
    base_dn: str | None = None  # default derived from identities.domain
    allow_anonymous_bind: bool = True


class SmbShare(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    comment: str = ""
    readonly: bool = True
    files: dict[str, str] = Field(default_factory=dict)


class SmbConfig(ServiceBase):
    type: Literal["smb"] = "smb"
    port: int = Field(default=445, ge=1, le=65535)
    signing_required: bool = True
    server_os: str = "Windows Server 2022 Standard 20348"
    shares: list[SmbShare] = Field(default_factory=list)


class DnsRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    type: Literal["A", "AAAA", "CNAME", "TXT", "SRV", "MX"] = "A"
    value: str
    ttl: int = 300


class DnsConfig(ServiceBase):
    type: Literal["dns"] = "dns"
    port: int = Field(default=53, ge=1, le=65535)
    zone: str | None = None  # default from identities.domain
    records: list[DnsRecord] = Field(default_factory=list)
    autofill_hosts: bool = True


# The discriminated union authored in host.services[]. The discriminator lets pydantic
# route each object to the right model by its "type" key, and produces a JSON Schema
# oneOf that editors use for per-variant autocomplete.
BuiltinService = Annotated[
    Union[HttpConfig, BannerConfig, LdapConfig, SmbConfig, DnsConfig],
    Field(discriminator="type"),
]

# Service types that have a working runtime facade in this release.
IMPLEMENTED_TYPES = frozenset({"http", "banner", "ldap", "smb"})
