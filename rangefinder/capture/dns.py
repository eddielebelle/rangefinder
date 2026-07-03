"""Capture a live DNS zone into a faithful ``dns`` facade.

Record-replay: ask the server for the zone's records. If the server allows a zone transfer
(AXFR) we take the whole zone — the transfer being allowed is itself an exposure that carries
through to the replica. Otherwise we query a probe set of the names/types tooling actually
asks for (the apex, common hostnames, and the AD service SRV records domain-joined clients
use to find a DC). The facade replays the answers, so ``dig`` against the replica returns
what the real server returned.

Uses dnspython (a light client dep) instead of hand-rolling the wire format. Records the
record types the dns facade can serve (A/AAAA/CNAME/MX/TXT/SRV); NS/SOA are not replayed.
"""

from __future__ import annotations

import socket

from rangefinder.capture.scrub import Scrubber

_TYPES = ("A", "AAAA", "CNAME", "MX", "TXT", "SRV")

# Hostnames and AD service records worth asking for when a zone transfer is refused.
_COMMON = ["", "www", "mail", "ns", "ns1", "ns2", "dc", "dc01", "dc02", "gc", "ldap",
           "kerberos", "autodiscover", "vpn", "remote", "smtp", "imap", "api", "app",
           "intranet", "fileserver", "fs01", "web", "web01"]
_SRV = ["_ldap._tcp", "_kerberos._tcp", "_kerberos._udp", "_gc._tcp", "_kpasswd._tcp",
        "_ldap._tcp.dc._msdcs", "_kerberos._tcp.dc._msdcs", "_autodiscover._tcp"]


def capture_dns(host: str, port: int = 53, *, zone: str, timeout: float = 5.0,
                names: list[str] | None = None, scrub: bool = False) -> tuple[dict, list[str]]:
    """Enumerate a zone and return (dns_service_config, warnings)."""
    import dns.exception
    import dns.flags
    import dns.message
    import dns.name
    import dns.query
    import dns.rdatatype
    import dns.zone

    warnings: list[str] = []
    scrubber = Scrubber() if scrub else None
    zone = zone.lower().rstrip(".")
    server = _server_ip(host)

    seen: set = set()
    records: list[dict] = []

    def add(name: str, rtype: str, value: str, ttl: int) -> None:
        name = name.lower().rstrip(".")
        value = scrubber.text(value) if scrubber is not None else value
        key = (name, rtype, value)
        if key in seen:
            return
        seen.add(key)
        records.append({"name": name, "type": rtype, "value": value, "ttl": int(ttl)})

    axfr = False
    try:
        # relativize=False so names *inside* rdata (SRV/MX/CNAME targets) come back as FQDNs,
        # not relative to the origin — else the replica would serve "dc01" for "dc01.acme.corp".
        z = dns.zone.from_xfr(dns.query.xfr(server, zone, port=port, timeout=timeout),
                              relativize=False)
        axfr = True
        for node_name, node in z.nodes.items():
            fqdn = str(node_name)
            for rds in node.rdatasets:
                _collect(fqdn, rds, add)
        warnings.append("AXFR (zone transfer) allowed — full zone captured; the transfer "
                        "being permitted is itself an exposure that carries through")
    except Exception:
        pass  # AXFR refused (the normal case) -> fall back to probing

    if not axfr:
        for fqdn in (names or _probe_names(zone)):
            for rtype in _TYPES:
                try:
                    q = dns.message.make_query(fqdn, rtype)
                    resp = dns.query.udp(q, server, port=port, timeout=timeout)
                    if resp.flags & dns.flags.TC:  # truncated -> retry over TCP
                        resp = dns.query.tcp(q, server, port=port, timeout=timeout)
                except dns.exception.DNSException:
                    continue
                for rrset in resp.answer:
                    _collect(str(rrset.name), rrset, add)

    service: dict = {"type": "dns", "port": port, "zone": zone,
                     "autofill_hosts": False, "records": records}
    warnings.append(f"captured {len(records)} record(s) for {zone}"
                    + (" via AXFR" if axfr else " via probing"))
    return service, warnings


def _collect(fqdn: str, rds, add) -> None:
    import dns.rdatatype

    rtype = dns.rdatatype.to_text(rds.rdtype)
    if rtype not in _TYPES:
        return
    ttl = getattr(rds, "ttl", 300)
    for rdata in rds:
        value = _value(rtype, rdata)
        if value is not None:
            add(fqdn, rtype, value, ttl)


def _value(rtype: str, rdata) -> str | None:
    if rtype in ("A", "AAAA"):
        return rdata.address
    if rtype == "CNAME":
        return str(rdata.target).rstrip(".")
    if rtype == "MX":
        return f"{rdata.preference} {str(rdata.exchange).rstrip('.')}"
    if rtype == "SRV":
        return f"{rdata.priority} {rdata.weight} {rdata.port} {str(rdata.target).rstrip('.')}"
    if rtype == "TXT":
        return b"".join(rdata.strings).decode("utf-8", "replace")
    return None


def _probe_names(zone: str) -> list[str]:
    names = [zone if not s else f"{s}.{zone}" for s in _COMMON]
    names += [f"{s}.{zone}" for s in _SRV]
    return names


def _server_ip(host: str) -> str:
    try:
        socket.inet_aton(host)
        return host
    except OSError:
        return socket.gethostbyname(host)
