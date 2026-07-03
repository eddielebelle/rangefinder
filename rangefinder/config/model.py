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


class Objective(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    title: str
    description: str
    hints: list[str] = Field(default_factory=list)


class Network(BaseModel):
    model_config = ConfigDict(extra="forbid")

    subnet: IPvAnyNetwork
    gateway: IPvAnyAddress | None = None


class RangeConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # name is usable as a docker-compose project name.
    name: str = Field(pattern=r"^[a-z0-9][a-z0-9_\-]{0,61}$")
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

            # ldap/smb facades render AD identities; require them to be present.
            for svc in host.services:
                if svc.type in ("ldap", "smb") and self.identities is None:
                    raise ValueError(
                        f"host {host.id!r}: {svc.type!r} service requires top-level "
                        f"'identities' to be defined"
                    )
        return self
