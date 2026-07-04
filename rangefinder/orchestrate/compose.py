"""Compile a range config into a docker-compose stack.

The compose file is emitted as JSON (which is valid YAML 1.2 and read fine by
``docker compose``) so the tool needs no YAML dependency and sidesteps YAML's
implicit-typing quoting traps. One container per host, each pinned to its config IP on a
user-defined bridge network. An opt-in ``attacker`` container attaches to the same
network for running tools against the range.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from rangefinder.config.model import RangeConfig

IMAGE = "rangefinder:latest"
ATTACKER_IMAGE = "rangefinder-attacker:latest"
CONFIG_IN_CONTAINER = "/range/config.json"


def _dns_host_ip(cfg: RangeConfig) -> str | None:
    """IP of the host running the DNS facade (range clients resolve against it, like a DC)."""
    for host in cfg.hosts:
        if any(getattr(s, "type", None) == "dns" for s in host.services):
            return str(host.ip)
    return None


def _vmware_mac(seed: str) -> str:
    """A stable MAC in VMware's OUI (00:50:56, manual range) derived from *seed*.

    Docker hands out random locally-administered MACs; a whole estate of those is a tell,
    whereas a virtualized enterprise shows a hypervisor vendor's OUI. Deterministic per host.
    """
    h = hashlib.sha256(seed.encode()).digest()
    return "00:50:56:%02x:%02x:%02x" % (h[0] & 0x3F, h[1], h[2])


def build_compose(cfg: RangeConfig, *, include_attacker: bool = True) -> dict:
    net = cfg.network
    ipam_entry: dict = {"subnet": str(net.subnet)}
    if net.gateway is not None:
        ipam_entry["gateway"] = str(net.gateway)

    # Point every container's resolver at the range's own DNS host (as domain members
    # resolve against a DC) and set the search domain to the AD domain — otherwise docker's
    # embedded DNS answers reverse lookups with "<container>.<network>" names and the search
    # suffix leaks the compose network name, both obvious tells.
    dns_ip = _dns_host_ip(cfg)
    domain = cfg.identities.domain if cfg.identities else None

    def _resolver(svc: dict) -> None:
        if dns_ip:
            svc["dns"] = [dns_ip]
        if domain:
            svc["dns_search"] = [domain]

    services: dict = {}
    for host in cfg.hosts:
        svc = {
            "image": IMAGE,
            "container_name": f"{cfg.name}-{host.id}",
            "hostname": host.hostname,
            "mac_address": _vmware_mac(f"{cfg.name}:{host.id}"),
            "command": ["run", "--host", host.id, "--config", CONFIG_IN_CONTAINER],
            "volumes": [f"./config.json:{CONFIG_IN_CONTAINER}:ro"],
            "networks": {"range": {"ipv4_address": str(host.ip)}},
            "restart": "unless-stopped",
            # Namespaced sysctl lets the non-root user bind 22/53/80/389/445 without
            # --privileged and without touching the host.
            "sysctls": ["net.ipv4.ip_unprivileged_port_start=0"],
        }
        _resolver(svc)
        services[host.id] = svc

    if include_attacker:
        attacker = {
            "image": ATTACKER_IMAGE,
            "container_name": f"{cfg.name}-attacker",
            "profiles": ["attacker"],  # opt-in; does not start with `up`
            "networks": {"range": {}},  # dynamic IP on the same subnet
            "command": ["sleep", "infinity"],
            "cap_add": ["NET_RAW", "NET_ADMIN"],  # SYN/ping scans, ARP
        }
        _resolver(attacker)
        services["attacker"] = attacker

    return {
        "name": cfg.name,
        "networks": {
            "range": {
                "driver": "bridge",
                "ipam": {"config": [ipam_entry]},
            }
        },
        "services": services,
    }


def write_outputs(
    cfg: RangeConfig,
    outdir: str | Path,
    config_src: str | Path,
    *,
    include_attacker: bool = True,
) -> Path:
    """Write docker-compose.yml + a copy of the validated config into *outdir*.

    Returns the path to the generated compose file. The config is copied next to the
    compose file because the bind mount uses ``./config.json`` (resolved relative to the
    compose file's directory), which keeps the emitted stack self-contained and portable.
    """
    out = Path(outdir)
    out.mkdir(parents=True, exist_ok=True)

    compose = build_compose(cfg, include_attacker=include_attacker)
    compose_path = out / "docker-compose.yml"
    compose_path.write_text(json.dumps(compose, indent=2) + "\n", encoding="utf-8")

    (out / "config.json").write_text(
        Path(config_src).read_text(encoding="utf-8"), encoding="utf-8"
    )
    return compose_path
