"""Generate a rangefinder config from an nmap ``-oX`` scan of real infrastructure.

Two layers:

1. **Topology + versions** — each up host becomes a range host and each open TCP port a
   facade (http/https -> ``http``, ssh -> ``ssh``, else a labelled ``banner`` decoy).
2. **Security posture** — nmap NSE ``<script>`` output is translated into faithful config
   that reproduces the *misconfigurations* found (exposed web paths -> planted routes;
   null-session SMB shares -> a real ``smb`` facade), and into auto-generated
   ``objectives`` so the imported range ships with a scorecard of the real weaknesses.

Posture vs. data: this captures the *property* of a weakness (a path is exposed, a share
is null-session readable, LDAP answers anonymously) and structural names/paths, but never
bulk data or secret values — share contents are placeholdered. Run nmap with NSE scripts
(``-sV -sC`` or targeted ``--script http-enum,http-git,smb-enum-shares,...``) to populate
the posture layer; a bare ``-sV`` yields only the topology layer.
"""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from xml.etree import ElementTree as ET

from rangefinder.config.model import RangeConfig

_HTTP_PORTS = {80, 8080, 8000, 8888}
_TLS_HTTP_PORTS = {443, 8443}

# Web paths whose exposure is security-relevant (tagged as vulns + scored).
_SENSITIVE_PATH = re.compile(
    r"(/\.git|/\.svn|/\.env|/\.aws|backup|/admin|phpmyadmin|phpmyadmin|/config|"
    r"\.sql|\.bak|/wp-login|/wp-admin|/server-status|/actuator|/\.ht)",
    re.IGNORECASE,
)
_PATH_RE = re.compile(r"(/[A-Za-z0-9_./~-]+)")
_MAX_ROUTES_PER_HOST = 40


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
    objectives: list[dict] = []
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
        hostscript = host_el.find("hostscript")
        host_scripts = _scripts(hostscript) if hostscript is not None else {}
        services = _services(
            host_el, host_id, hostname or ip, facade_counts, objectives, host_scripts
        )
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

    # Deduplicate objectives by id (host scripts can be evaluated against multiple ports).
    seen: set[str] = set()
    objectives = [o for o in objectives if not (o["id"] in seen or seen.add(o["id"]))]

    net = _subnet(subnet, [h["ip"] for h in hosts], warnings)
    config: dict = {
        "name": _sanitize_name(name),
        "network": {"subnet": str(net)},
        "hosts": hosts,
    }
    if objectives:
        config["objectives"] = objectives

    try:
        RangeConfig.model_validate(config)
    except Exception as exc:  # pydantic ValidationError
        raise ValueError(f"generated config is invalid: {exc}") from exc

    scoreable = sum(1 for o in objectives if o.get("detect"))
    summary = {
        "hosts": len(hosts),
        "services": sum(len(h["services"]) for h in hosts),
        "facades": dict(sorted(facade_counts.items())),
        "skipped_hosts": skipped,
        "subnet": str(net),
        "misconfigs": len(objectives),
        "scoreable_objectives": scoreable,
    }
    return config, summary, warnings


# ------------------------------------------------------------------- host/port basics


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


def _scripts(el) -> dict[str, str]:
    """Collect {script-id: output} from <script> children of a port or host."""
    out: dict[str, str] = {}
    for scr in el.findall("script"):
        out[scr.get("id", "")] = scr.get("output", "") or ""
    return out


def _services(host_el, host_id, host_label, counts, objectives, host_scripts) -> list[dict]:
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

        svc = port_el.find("service")
        # Host scripts (e.g. smb-enum-shares) apply to the relevant port too.
        scripts = {**host_scripts, **_scripts(port_el)}
        cfg = _facade_for(portid, svc, host_label)
        cfg = _apply_posture(cfg, portid, scripts, host_id, host_label, objectives)
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


# ----------------------------------------------------------------- posture / misconfig


def _apply_posture(cfg, portid, scripts, host_id, host_label, objectives) -> dict:
    """Enrich a facade with misconfigs found by NSE scripts; append scored objectives."""
    if not scripts:
        return cfg

    if cfg["type"] == "http":
        routes = _http_exposed_routes(scripts, host_id, objectives)
        if routes:
            cfg.setdefault("paths", {}).update(routes)

    # Promote a null-session SMB port to a real smb facade reproducing the shares.
    if portid == 445 or cfg.get("protocol") in ("microsoft-ds", "netbios-ssn"):
        smb = _smb_from_scripts(scripts, host_id, objectives)
        if smb is not None:
            smb["port"] = portid
            cfg = smb

    # Record misconfigs we flag but do not fully reproduce behaviorally.
    if _has(scripts, "ldap-rootdse") or _has(scripts, "ldap-search"):
        objectives.append(_objective(
            f"{host_id}-ldap-anon", f"Anonymous LDAP on {host_id}",
            "LDAP answered unauthenticated (anonymous bind) queries.",
        ))
    if _output(scripts, "ftp-anon", "anonymous ftp login allowed"):
        objectives.append(_objective(
            f"{host_id}-ftp-anon", f"Anonymous FTP on {host_id}",
            "The FTP service permits anonymous login.",
        ))
    if _output(scripts, "ssl-cert", "self-signed") or _output(scripts, "ssl-cert", "expired"):
        objectives.append(_objective(
            f"{host_id}-weak-tls", f"Weak TLS certificate on {host_id}",
            "The service presents a self-signed or expired certificate.",
        ))
    for svc_name in ("redis-info", "mongodb-info", "elasticsearch"):
        if _has(scripts, svc_name):
            objectives.append(_objective(
                f"{host_id}-{svc_name}-unauth", f"Unauthenticated {svc_name.split('-')[0]} on {host_id}",
                f"The {svc_name.split('-')[0]} service responded without authentication.",
            ))
    return cfg


def _http_exposed_routes(scripts, host_id, objectives) -> dict:
    routes: dict[str, dict] = {}
    for sid, out in scripts.items():
        low = out.lower()
        if "git" in sid and ".git" in low:
            routes["/.git/HEAD"] = {
                "content_type": "text/plain; charset=utf-8",
                "body": "ref: refs/heads/main\n",
                "vuln_id": "exposed-git-repo",
            }
            objectives.append(_objective(
                f"{host_id}-exposed-git", f"Exposed .git repository on {host_id}",
                "An unauthenticated .git directory is reachable over HTTP.",
                _detect_http("/.git"),
            ))
        if sid in ("http-enum", "http-robots.txt") or sid.startswith("http-"):
            for path in _extract_paths(out):
                if path in routes or len(routes) >= _MAX_ROUTES_PER_HOST:
                    continue
                route = {"body": "<!-- endpoint observed during discovery -->\n"}
                if _SENSITIVE_PATH.search(path):
                    slug = _slug(path)
                    route["vuln_id"] = f"exposed-{slug}"
                    objectives.append(_objective(
                        f"{host_id}-exposed-{slug}", f"Exposed {path} on {host_id}",
                        f"nmap enumeration found the sensitive path {path}.",
                        _detect_http(path),
                    ))
                routes[path] = route
    return routes


def _extract_paths(output: str) -> list[str]:
    paths: list[str] = []
    for m in _PATH_RE.finditer(output):
        p = m.group(1).rstrip("/") or "/"
        if p in paths:
            continue
        if p.endswith((".js", ".css", ".png", ".jpg", ".gif", ".ico", ".woff")):
            continue
        if " " in p or len(p) > 120:
            continue
        # Require a letter after the leading slash so version numbers / counts
        # ("/6", "/1.18.0") extracted from script prose are not treated as endpoints.
        if not re.search(r"[A-Za-z]", p[1:]):
            continue
        paths.append(p)
    return paths


def _smb_from_scripts(scripts, host_id, objectives) -> dict | None:
    enum = next((out for sid, out in scripts.items() if "enum-shares" in sid), None)
    if not enum:
        return None
    names = _parse_share_names(enum)
    if not names:
        return None
    shares = [
        {"name": n, "comment": "imported (contents not captured)", "readonly": True,
         "files": {"README.txt": "Placeholder — share contents are not imported.\n"}}
        for n in names
    ]
    cfg: dict = {"type": "smb", "server_os": "Windows Server", "shares": shares}
    weak_signing = any(
        "security-mode" in sid and ("not required" in out.lower() or "disabled" in out.lower())
        for sid, out in scripts.items()
    )
    if weak_signing:
        cfg["signing_required"] = False
    objectives.append(_objective(
        f"{host_id}-smb-null-session", f"Null-session SMB shares on {host_id}",
        "SMB shares are enumerable/readable without authentication.",
        _detect_smb(),
    ))
    return cfg


def _parse_share_names(output: str) -> list[str]:
    names: list[str] = []
    for m in re.finditer(r"\\\\[^\\\s]+\\([A-Za-z0-9$_.-]+)", output):
        share = m.group(1)
        if share.upper() == "IPC$":  # our smb facade adds IPC$ itself
            continue
        if share not in names:
            names.append(share)
    return names


# --------------------------------------------------------------------- small builders


def _objective(oid: str, title: str, description: str, detect: list | None = None) -> dict:
    obj = {"id": oid, "title": title, "description": description}
    if detect:
        obj["detect"] = detect
    return obj


def _detect_http(path: str) -> list:
    return [{"label": f"HTTP request to {path}",
             "all": [{"field": "event.action", "equals": "http_request"},
                     {"field": "url.path", "contains": path}]}]


def _detect_smb() -> list:
    return [{"label": "SMB file access",
             "all": [{"field": "event.action", "equals": "smb_file_access"}]}]


def _has(scripts: dict, script_id: str) -> bool:
    return any(script_id in sid for sid in scripts)


def _output(scripts: dict, script_id: str, needle: str) -> bool:
    return any(script_id in sid and needle.lower() in out.lower() for sid, out in scripts.items())


def _slug(path: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", path.lower()).strip("-") or "root"


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
