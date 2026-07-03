"""Discover topology from an nmap ``-oX`` scan → a range config skeleton.

nmap is a fingerprinter: it tells you *what is listening where*, which is exactly the
discovery layer. Each up host becomes a range host and each open TCP port a facade
(http/https → ``http``, ssh → ``ssh``, else a labelled ``banner`` decoy carrying the
detected version). Subnet is derived from the host IPs (``--subnet`` to override).

Fidelity — reproducing a service's actual responses so its misconfigurations carry through
— is NOT nmap's job and is deliberately not done here. That comes from ``rangefinder
capture`` (e.g. ``capture http``), which speaks each protocol to the live target and
records what it really returns. Import gives the skeleton; capture fills in the flesh.
"""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from xml.etree import ElementTree as ET

from rangefinder.config.model import RangeConfig

_HTTP_PORTS = {80, 8080, 8000, 8888}
_TLS_HTTP_PORTS = {443, 8443}


def import_nmap(
    scan_path: str | Path, *, name: str = "imported", subnet: str | None = None
) -> tuple[dict, dict, list[str]]:
    """Parse an nmap XML file and return (config_dict, summary, warnings).

    Raises ValueError on unparseable input or if the built config fails validation.
    """
    try:
        root = ET.parse(scan_path).getroot()
    except (ET.ParseError, OSError) as exc:
        raise ValueError(f"could not parse nmap XML {scan_path}: {exc}") from exc
    if root.tag != "nmaprun":
        raise ValueError(f"{scan_path}: not an nmap XML file (root tag {root.tag!r})")

    warnings: list[str] = []
    hosts: list[dict] = []
    used_ids: set[str] = set()
    facade_counts: dict[str, int] = {}
    skipped = 0

    for host_el in root.findall("host"):
        status = host_el.find("status")
        if status is not None and status.get("state") != "up":
            continue
        ip = _ipv4(host_el)
        if ip is None:
            skipped += 1
            warnings.append("skipped a host with no IPv4 address (IPv6-only not supported)")
            continue

        hostname = _hostname(host_el)
        host_id = _make_id(hostname, ip, used_ids)
        services = _services(host_el, hostname or ip, facade_counts)
        if not services:
            skipped += 1
            used_ids.discard(host_id)
            continue

        hosts.append({
            "id": host_id,
            "hostname": hostname or ip,
            "ip": ip,
            "os": _map_os(host_el),
            "services": services,
        })

    if not hosts:
        raise ValueError("no usable hosts with open ports found in the scan")

    net = _subnet(subnet, [h["ip"] for h in hosts], warnings)
    config = {
        "name": _sanitize_name(name),
        "network": {"subnet": str(net)},
        "hosts": hosts,
    }
    try:
        RangeConfig.model_validate(config)
    except Exception as exc:  # pydantic ValidationError
        raise ValueError(f"generated config is invalid: {exc}") from exc

    summary = {
        "hosts": len(hosts),
        "services": sum(len(h["services"]) for h in hosts),
        "facades": dict(sorted(facade_counts.items())),
        "skipped_hosts": skipped,
        "subnet": str(net),
    }
    return config, summary, warnings


def _ipv4(host_el) -> str | None:
    for addr in host_el.findall("address"):
        if addr.get("addrtype") == "ipv4":
            return addr.get("addr")
    return None


def _hostname(host_el) -> str | None:
    hn = host_el.find("hostnames/hostname")
    return hn.get("name") if hn is not None else None


def _map_os(host_el) -> str:
    osmatch = host_el.find("os/osmatch")
    name = (osmatch.get("name", "") if osmatch is not None else "").lower()
    osclass = host_el.find("os/osmatch/osclass")
    family = (osclass.get("osfamily", "") if osclass is not None else "").lower()
    blob = f"{family} {name}"
    if "windows" in blob:
        if "server" in blob:
            return "windows_server_2019" if "2019" in blob else "windows_server_2022"
        if "11" in blob:
            return "windows_11"
        if "10" in blob:
            return "windows_10"
        return "windows_server_2022"
    if "linux" in blob:
        if "ubuntu" in blob:
            return "ubuntu_22_04"
        if "debian" in blob:
            return "debian_12"
        return "generic_linux"
    return "generic_linux"


def _services(host_el, host_label, counts) -> list[dict]:
    services: list[dict] = []
    seen_ports: set[int] = set()
    for port_el in host_el.findall("ports/port"):
        if port_el.get("protocol") != "tcp":
            continue
        state = port_el.find("state")
        if state is None or state.get("state") != "open":
            continue
        portid = int(port_el.get("portid"))
        if portid in seen_ports:
            continue
        seen_ports.add(portid)

        cfg = _facade_for(portid, port_el.find("service"), host_label)
        counts[cfg["type"]] = counts.get(cfg["type"], 0) + 1
        services.append(cfg)
    return services


def _facade_for(portid: int, svc, host_label: str) -> dict:
    name = (svc.get("name", "") if svc is not None else "").lower()
    product = svc.get("product", "") if svc is not None else ""
    version = svc.get("version", "") if svc is not None else ""
    tunnel = svc.get("tunnel", "") if svc is not None else ""
    server_header = " ".join(p for p in (product, version) if p).strip()

    is_tls = tunnel == "ssl" or name == "https"
    if name == "https" or (is_tls and name.startswith("http")) or portid in _TLS_HTTP_PORTS:
        cfg = {"type": "http", "port": portid, "tls": True}
        if server_header:
            cfg["server_header"] = server_header
        return cfg
    if name in ("http", "http-proxy") or portid in _HTTP_PORTS:
        cfg = {"type": "http", "port": portid}
        if server_header:
            cfg["server_header"] = server_header
        return cfg
    if name == "ssh" or portid == 22:
        cfg = {"type": "ssh", "port": portid}
        sv = f"{product}_{version}".strip("_") if product else ""
        if sv:
            cfg["server_version"] = sv
        return cfg

    cfg = {"type": "banner", "port": portid, "protocol": name or "tcp"}
    banner = _text_banner(name, product, version, host_label)
    if banner is not None:
        cfg["banner"] = banner
    else:
        cfg["banner"] = ""
        cfg["close_after_banner"] = True
    return cfg


def _text_banner(name: str, product: str, version: str, host_label: str) -> str | None:
    pv = " ".join(p for p in (product, version) if p).strip()
    if name == "ftp":
        return f"220 {pv or 'FTP server ready'}"
    if name == "smtp":
        return f"220 {host_label} ESMTP {product or 'ready'}".rstrip()
    if name == "imap":
        return f"* OK [CAPABILITY IMAP4rev1] {product or 'server'} ready."
    if name == "pop3":
        return f"+OK {product or 'POP3'} ready"
    return None


def _make_id(hostname: str | None, ip: str, used: set[str]) -> str:
    base = ""
    if hostname:
        base = re.sub(r"[^a-z0-9-]", "-", hostname.split(".")[0].lower()).strip("-")
    if not base:
        base = "h-" + ip.replace(".", "-")
    base = base[:63] or "host"
    candidate, n = base, 2
    while candidate in used:
        candidate = f"{base}-{n}"[:63]
        n += 1
    used.add(candidate)
    return candidate


def _sanitize_name(name: str) -> str:
    clean = re.sub(r"[^a-z0-9_-]", "-", name.lower()).strip("-_")
    return (clean or "imported")[:62]


def _subnet(explicit, ips, warnings) -> ipaddress.IPv4Network:
    if explicit is not None:
        net = ipaddress.ip_network(explicit, strict=False)
        outside = [ip for ip in ips if ipaddress.ip_address(ip) not in net]
        if outside:
            raise ValueError(f"--subnet {explicit} does not contain host(s): {', '.join(outside)}")
        return net

    ints = [int(ipaddress.ip_address(ip)) for ip in ips]
    xored = 0
    for value in ints[1:]:
        xored |= ints[0] ^ value
    prefix = min(32 - xored.bit_length(), 24)
    net = ipaddress.ip_network(f"{ips[0]}/{prefix}", strict=False)
    if net.overlaps(ipaddress.ip_network("172.16.0.0/12")):
        warnings.append(
            f"subnet {net} overlaps Docker's default 172.16/12 range; pass --subnet to "
            f"remap if `docker compose up` fails to create the network"
        )
    return net
