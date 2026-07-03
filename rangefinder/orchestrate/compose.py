"""Compile a range config into a docker-compose stack.

The compose file is emitted as JSON (which is valid YAML 1.2 and read fine by
``docker compose``) so the tool needs no YAML dependency and sidesteps YAML's
implicit-typing quoting traps. One container per host, each pinned to its config IP on a
user-defined bridge network. An opt-in ``attacker`` container attaches to the same
network for running tools against the range.
"""

from __future__ import annotations

import json
from pathlib import Path

from rangefinder.config.model import RangeConfig

IMAGE = "rangefinder:latest"
ATTACKER_IMAGE = "rangefinder-attacker:latest"
CONFIG_IN_CONTAINER = "/range/config.json"


def build_compose(cfg: RangeConfig, *, include_attacker: bool = True) -> dict:
    net = cfg.network
    ipam_entry: dict = {"subnet": str(net.subnet)}
    if net.gateway is not None:
        ipam_entry["gateway"] = str(net.gateway)

    services: dict = {}
    for host in cfg.hosts:
        services[host.id] = {
            "image": IMAGE,
            "container_name": f"{cfg.name}-{host.id}",
            "hostname": host.hostname,
            "command": ["run", "--host", host.id, "--config", CONFIG_IN_CONTAINER],
            "volumes": [f"./config.json:{CONFIG_IN_CONTAINER}:ro"],
            "networks": {"range": {"ipv4_address": str(host.ip)}},
            "restart": "unless-stopped",
            # Namespaced sysctl lets the non-root user bind 22/53/80/389/445 without
            # --privileged and without touching the host.
            "sysctls": ["net.ipv4.ip_unprivileged_port_start=0"],
        }

    if include_attacker:
        services["attacker"] = {
            "image": ATTACKER_IMAGE,
            "container_name": f"{cfg.name}-attacker",
            "profiles": ["attacker"],  # opt-in; does not start with `up`
            "networks": {"range": {}},  # dynamic IP on the same subnet
            "command": ["sleep", "infinity"],
            "cap_add": ["NET_RAW", "NET_ADMIN"],  # SYN/ping scans, ARP
        }

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
