"""Top-level range configuration model and cross-field validation."""

from __future__ import annotations

from enum import Enum

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    IPvAnyAddress,
    IPvAnyNetwork,
    model_validator,
)

from rangefinder.config.services import BuiltinService


# Config-schema compatibility version. Bump this whenever the config schema changes in a
# way an older runtime can't parse (a new facade type, a new service field, etc.).
# Machine-generated configs (capture/import) stamp it; the loader refuses a config stamped
# newer than the runtime supports, turning "stale image" into a clear, actionable error
# instead of a cryptic field-rejection deep inside a container.
# v2: added Objective.sequence (kill-chain scoring).
SCHEMA_VERSION = 2


class OS(str, Enum):
    windows_server_2019 = "windows_server_2019"
    windows_server_2022 = "windows_server_2022"
    windows_10 = "windows_10"
    windows_11 = "windows_11"
    ubuntu_22_04 = "ubuntu_22_04"
    debian_12 = "debian_12"
    generic_linux = "generic_linux"


class Host(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # id doubles as the docker-compose service name and a DNS label, so it is
    # constrained to lowercase alphanumerics + hyphens.
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9\-]{0,62}$")
    hostname: str
    ip: IPvAnyAddress
    os: OS = OS.generic_linux
    tags: list[str] = Field(default_factory=list)
    services: list[BuiltinService] = Field(min_length=1)

    @model_validator(mode="after")
    def _unique_ports(self) -> "Host":
        ports = [s.port for s in self.services]
        dupes = sorted({p for p in ports if ports.count(p) > 1})
        if dupes:
            raise ValueError(f"host {self.id!r}: duplicate service ports {dupes}")
        return self


class ADUser(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sam: str  # sAMAccountName
    display_name: str | None = None
    upn: str | None = None
    groups: list[str] = Field(default_factory=list)
    description: str | None = None  # a classic place to plant a leaked secret
    enabled: bool = True


class ADGroup(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    members: list[str] = Field(default_factory=list)
    description: str | None = None


class Identities(BaseModel):
    model_config = ConfigDict(extra="forbid")

    domain: str
    netbios: str | None = None
    users: list[ADUser] = Field(default_factory=list)
    groups: list[ADGroup] = Field(default_factory=list)

    @property
    def base_dn(self) -> str:
        return ",".join(f"DC={part}" for part in self.domain.split("."))


class Condition(BaseModel):
    """A single field predicate over a telemetry event.

    ``field`` is a dotted path into the event (ECS names), e.g. ``event.action``,
    ``url.path``, ``rangefinder.smb.path``, ``source.ip``. Exactly one matcher applies.
    """

    model_config = ConfigDict(extra="forbid")

    field: str
    equals: str | None = None
    contains: str | None = None  # case-insensitive substring
    regex: str | None = None

    @model_validator(mode="after")
    def _needs_matcher(self) -> "Condition":
        if self.equals is None and self.contains is None and self.regex is None:
            raise ValueError(f"condition on {self.field!r} needs one of equals/contains/regex")
        return self


class Signal(BaseModel):
    """One way an objective can be satisfied: all conditions hold on a single event."""

    model_config = ConfigDict(extra="forbid")

    label: str | None = None
    all: list[Condition] = Field(min_length=1)


class Sequence(BaseModel):
    """An ordered multi-event kill chain: steps that must occur in order.

    Each step is a Signal (conditions on one event). By default all steps must be by the
    same source (``same_source``); ``within`` optionally bounds the elapsed time from the
    first step to the last (e.g. "10m", "1h").
    """

    model_config = ConfigDict(extra="forbid")

    steps: list[Signal] = Field(min_length=1)
    same_source: bool = True
    within: str | None = None


class Objective(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    title: str
    description: str
    hints: list[str] = Field(default_factory=list)
    # MET when any signal matches any single event (single-event detection).
    detect: list[Signal] = Field(default_factory=list)
    # MET when an ordered kill chain occurs (cross-event detection). An objective may use
    # detect, sequence, or both (met if either fires). Neither = descriptive (UNSCORED).
    sequence: Sequence | None = None


class Network(BaseModel):
    model_config = ConfigDict(extra="forbid")

    subnet: IPvAnyNetwork
    gateway: IPvAnyAddress | None = None


class RangeConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # name is usable as a docker-compose project name.
    name: str = Field(pattern=r"^[a-z0-9][a-z0-9_\-]{0,61}$")
    # Config-schema version this config was generated for (see SCHEMA_VERSION). Optional:
    # hand-authored configs may omit it. The loader checks it before validation.
    schema_version: int | None = None
    network: Network
    hosts: list[Host] = Field(min_length=1)
    identities: Identities | None = None
    objectives: list[Objective] = Field(default_factory=list)

    def get_host(self, host_id: str) -> Host:
        for host in self.hosts:
            if host.id == host_id:
                return host
        known = ", ".join(h.id for h in self.hosts)
        raise KeyError(f"no host with id {host_id!r}; known hosts: {known}")

    @model_validator(mode="after")
    def _cross_checks(self) -> "RangeConfig":
        net = self.network.subnet
        gateway = self.network.gateway
        if gateway is not None and gateway not in net:
            raise ValueError(f"gateway {gateway} is not within subnet {net}")

        seen_ip: set = set()
        seen_id: set = set()
        seen_name: set = set()
        for host in self.hosts:
            if host.id in seen_id:
                raise ValueError(f"duplicate host id {host.id!r}")
            seen_id.add(host.id)
            if host.hostname in seen_name:
                raise ValueError(f"duplicate hostname {host.hostname!r}")
            seen_name.add(host.hostname)
            if host.ip in seen_ip:
                raise ValueError(f"duplicate host ip {host.ip}")
            seen_ip.add(host.ip)

            if host.ip not in net:
                raise ValueError(
                    f"host {host.id!r}: ip {host.ip} is not within subnet {net}"
                )
            if host.ip == net.network_address:
                raise ValueError(
                    f"host {host.id!r}: ip {host.ip} is the network address"
                )
            if gateway is not None and host.ip == gateway:
                raise ValueError(
                    f"host {host.id!r}: ip {host.ip} collides with the gateway"
                )

            # The ldap facade renders identities when present and/or replays captured
            # entries; it also works with neither (an empty directory), so nothing is
            # required here.
        return self
