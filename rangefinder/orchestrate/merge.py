"""Merge several single-service captures into one multi-host estate twin.

Each ``rangefinder capture`` emits a complete but *tiny* range: one host holding one measured
service. A real estate is many services per host and many hosts. This module composes those
fragments into one ``RangeConfig`` — the step that turns "we can capture faithful services" into
"we can capture a faithful estate".

Two axes of merge, both keyed on ``host.id`` (which the capturers derive from the hostname, and
``--host-id`` overrides):

- **same id** -> the services union onto one host (fail *closed* on a real port conflict rather
  than silently dropping a measured service);
- **different id** -> separate hosts in one range, with IP collisions between placeholder captures
  reallocated deterministically so the topology is valid.

Pure and I/O-free: it takes raw config dicts and returns ``(merged_dict, warnings)``. The CLI owns
reading/validating the inputs and stitching the provenance sidecars.
"""

from __future__ import annotations

import ipaddress
import itertools
from collections import Counter

from rangefinder.importers.nmap import _subnet

# The sentinel IP `capture` assigns when the target is a hostname (no measured address). Two
# captures of different hosts by name both land here, so it's the signal of an *unmeasured* IP —
# a measured address always wins over it.
_PLACEHOLDER_IP = "10.99.0.10"


def merge_configs(
    configs: list[dict], *, name: str | None = None, subnet: str | None = None
) -> tuple[dict, list[str]]:
    """Combine range config dicts into one. Returns (merged_config, warnings).

    Raises ValueError on an irreconcilable conflict (a genuine port clash on one host, or a
    subnet too small to hold the hosts) — the fail-closed cases where silently guessing would
    fabricate or discard measured facts.
    """
    if not configs:
        raise ValueError("merge needs at least one config")

    warnings: list[str] = []
    names: list[str] = []
    schema_versions: list[int] = []
    all_hosts: list[dict] = []
    identities_list: list[dict] = []
    objectives: list[dict] = []
    gateway: str | None = None

    for cfg in configs:
        if cfg.get("name"):
            names.append(cfg["name"])
        if isinstance(cfg.get("schema_version"), int):
            schema_versions.append(cfg["schema_version"])
        for host in cfg.get("hosts", []):
            all_hosts.append(_copy_host(host))
        if cfg.get("identities"):
            identities_list.append(cfg["identities"])
        for obj in cfg.get("objectives", []):
            objectives.append(obj)
        g = (cfg.get("network") or {}).get("gateway")
        if g and gateway is None:
            gateway = str(g)

    if not all_hosts:
        raise ValueError("merge needs at least one host across the inputs")

    # --- 1. union hosts by id ------------------------------------------------------------
    merged: dict[str, dict] = {}
    order: list[str] = []
    for host in all_hosts:
        hid = host["id"]
        if hid not in merged:
            merged[hid] = host
            order.append(hid)
        else:
            _merge_host(merged[hid], host, warnings)
    hosts = [merged[hid] for hid in order]

    # --- 2. subnet + IP/hostname reallocation --------------------------------------------
    net = _resolve_subnet(subnet, hosts, warnings)
    gw = _clamp_gateway(gateway, net, warnings)
    _assign_ips(hosts, net, gw, warnings)
    _dedup_hostnames(hosts, warnings)

    # --- 3. identities + objectives ------------------------------------------------------
    identities = _merge_identities(identities_list, warnings)
    merged_objectives = _merge_objectives(objectives, warnings)

    # --- 4. assemble ---------------------------------------------------------------------
    network: dict = {"subnet": str(net)}
    if gw is not None:
        network["gateway"] = str(gw)

    out: dict = {
        "name": name or (names[0] if names else "merged"),
        "network": network,
        "hosts": hosts,
    }
    if schema_versions:
        out["schema_version"] = max(schema_versions)
    if identities is not None:
        out["identities"] = identities
    if merged_objectives:
        out["objectives"] = merged_objectives
    return out, warnings


def _copy_host(host: dict) -> dict:
    """Shallow-plus copy so merging never mutates a caller's input dict."""
    out = dict(host)
    out["services"] = [dict(s) for s in host.get("services", [])]
    out["tags"] = list(host.get("tags", []))
    return out


def _merge_host(dst: dict, src: dict, warnings: list[str]) -> None:
    """Fold *src*'s services/metadata into *dst* (same host id)."""
    hid = dst["id"]
    existing = {s["port"]: s for s in dst["services"]}
    for svc in src.get("services", []):
        port = svc["port"]
        if port not in existing:
            dst["services"].append(svc)
            existing[port] = svc
        elif existing[port] == svc:
            warnings.append(f"host {hid!r}: identical {svc.get('type', '?')} service on port "
                            f"{port} captured twice; kept one")
        else:
            # Same host:port measured twice with different results — a real conflict we must not
            # paper over (dropping one would lose a measured facade; guessing which wins could
            # fabricate the estate). Fail closed, with advice matched to the case.
            old_type, new_type = existing[port].get("type", "?"), svc.get("type", "?")
            if old_type == new_type:
                raise ValueError(
                    f"host {hid!r}: two {old_type!r} captures on port {port} disagree "
                    f"(posture drift); re-capture the service once and merge a single copy"
                )
            raise ValueError(
                f"host {hid!r}: different services on port {port} ({old_type} vs {new_type}); "
                f"give one a distinct --host-id or drop one input"
            )

    # Prefer a measured address over the hostname-capture placeholder; otherwise keep the first
    # and surface the divergence (never silently drop a measured IP).
    if src.get("ip") and src["ip"] != dst.get("ip"):
        if dst.get("ip") == _PLACEHOLDER_IP and src["ip"] != _PLACEHOLDER_IP:
            warnings.append(f"host {hid!r}: adopted measured ip {src['ip']} over "
                            f"placeholder {dst['ip']}")
            dst["ip"] = src["ip"]
        else:
            warnings.append(f"host {hid!r}: ip {src['ip']} differs from {dst.get('ip')!r}; "
                            f"kept the first")

    if src.get("hostname") and src["hostname"] != dst.get("hostname"):
        warnings.append(f"host {hid!r}: hostname {src['hostname']!r} differs from "
                        f"{dst.get('hostname')!r}; kept the first")
    # Prefer a specific OS over the generic default when one input measured it.
    if src.get("os") and src["os"] != dst.get("os"):
        if dst.get("os", "generic_linux") == "generic_linux":
            dst["os"] = src["os"]
        else:
            warnings.append(f"host {hid!r}: os {src['os']!r} differs from {dst.get('os')!r}; "
                            f"kept the first")
    for tag in src.get("tags", []):
        if tag not in dst["tags"]:
            dst["tags"].append(tag)


def _resolve_subnet(subnet, hosts, warnings) -> ipaddress._BaseNetwork:
    """Use --subnet if given, else derive one covering the hosts' distinct IPs."""
    ips = sorted({h["ip"] for h in hosts})
    if subnet:
        return ipaddress.ip_network(subnet, strict=False)
    return _subnet(None, ips, warnings)


def _clamp_gateway(gateway, net, warnings):
    if gateway is None:
        return None
    gw = ipaddress.ip_address(gateway)
    if gw not in net:
        warnings.append(f"gateway {gw} is outside subnet {net}; dropped")
        return None
    return gw


def _assign_ips(hosts, net, gw, warnings) -> None:
    """Keep each host's measured IP where it's unique and in-subnet; reallocate the rest.

    A collision means two hosts claim the same address — the signature of placeholder captures
    (hostname targets all get the same sentinel IP). Reassigning them deterministically from the
    subnet is a synthetic-topology choice, not a posture change, so every move is surfaced.
    """
    counts = Counter(h["ip"] for h in hosts)
    pinned: dict[str, ipaddress._BaseAddress] = {}
    for h in hosts:
        ip = ipaddress.ip_address(h["ip"])
        if (counts[h["ip"]] == 1 and ip in net and ip != net.network_address
                and (gw is None or ip != gw)):
            pinned[h["id"]] = ip

    used = set(pinned.values())
    # Hosts start at .10 by convention (leaving .1-.9 for gateways/infrastructure), but fall back
    # to the low addresses so a deliberately tight subnet (/29 etc.) isn't wrongly rejected.
    base = int(net.network_address)
    preferred = (ip for ip in net.hosts() if int(ip) - base >= 10 and ip != gw)
    fallback = (ip for ip in net.hosts() if int(ip) - base < 10 and ip != gw)
    pool = itertools.chain(preferred, fallback)

    def next_free():
        for ip in pool:
            if ip not in used:
                used.add(ip)
                return ip
        raise ValueError(f"subnet {net} is too small for {len(hosts)} hosts; pass a larger --subnet")

    for h in hosts:
        if h["id"] in pinned:
            continue
        old = h["ip"]
        new = next_free()
        h["ip"] = str(new)
        if old != h["ip"]:
            warnings.append(f"host {h['id']!r}: reassigned ip {old} -> {new} "
                            f"(collision or outside {net})")


def _dedup_hostnames(hosts, warnings) -> None:
    """Disambiguate colliding hostnames so the merged config validates.

    Distinct hosts can share a hostname (both reverse-resolved to the same name, or one target
    given two ``--host-id``s). Reallocating IPs but crashing on the equivalent hostname clash was
    an opaque failure; instead we suffix the later one and surface it, mirroring IP handling.
    """
    seen: set = set()
    for h in hosts:
        name = h.get("hostname")
        if name not in seen:
            seen.add(name)
            continue
        for n in itertools.count(2):
            candidate = f"{name}-{n}"
            if candidate not in seen:
                break
        warnings.append(f"host {h['id']!r}: hostname {name!r} already used; "
                        f"renamed to {candidate!r}")
        h["hostname"] = candidate
        seen.add(candidate)


def _merge_identities(identities_list, warnings):
    """Merge AD identity blocks that share a domain; keep the first on a domain clash."""
    if not identities_list:
        return None
    base = {**identities_list[0]}
    base["users"] = list(base.get("users", []))
    base["groups"] = list(base.get("groups", []))
    users_by_sam = {u.get("sam"): u for u in base["users"]}
    seen_groups = {g.get("name") for g in base["groups"]}
    for extra in identities_list[1:]:
        if extra.get("domain") != base.get("domain"):
            # A range twin holds one AD domain (the schema's single Identities block, which every
            # ldap/kerberos facade reads). Silently dropping the second domain's accounts would
            # under-represent the estate; serving them under the first domain would fabricate it.
            # Fail closed and tell the operator to split the domains into separate ranges.
            raise ValueError(
                f"cannot merge identities for domains {base.get('domain')!r} and "
                f"{extra.get('domain')!r} into one range (a range twin holds a single AD domain); "
                f"merge same-domain captures, keeping each domain in its own range"
            )
        for u in extra.get("users", []):
            sam = u.get("sam")
            if sam not in users_by_sam:
                base["users"].append(u)
                users_by_sam[sam] = u
            elif u != users_by_sam[sam]:
                warnings.append(f"identity {sam!r} defined differently across inputs; "
                                f"kept the first definition and dropped the other")
        for g in extra.get("groups", []):
            if g.get("name") not in seen_groups:
                base["groups"].append(g)
                seen_groups.add(g.get("name"))
    return base


def _merge_objectives(objectives, warnings):
    """Concatenate objectives, dropping duplicate ids (keeping the first).

    An identical redefinition is a harmless artifact of merging overlapping inputs; a *differing*
    body under the same id is a real conflict where the second (dropped) definition would have
    scored differently — that one is worth a warning.
    """
    out: list[dict] = []
    by_id: dict = {}
    for obj in objectives:
        oid = obj.get("id")
        if oid in by_id:
            if obj != by_id[oid]:
                warnings.append(f"objective id {oid!r} redefined with different content; "
                                f"kept the first")
            continue
        by_id[oid] = obj
        out.append(obj)
    return out
