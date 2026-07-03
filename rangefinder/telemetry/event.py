"""ECS-aligned telemetry event construction.

Events are plain dicts (fast, no per-event model overhead) whose keys follow Elastic
Common Schema names so the JSON lines drop into Elastic/OpenSearch/Splunk with minimal
mapping. Range-specific fields live under a ``rangefinder`` namespace. ``None`` values
and empty maps are pruned before emission.

These are pure functions that read attributes off a facade-like object and a connection
scope; they import nothing from the facade layer to keep the dependency arrow one-way.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

SCHEMA_VERSION = "1.0"


def _now_iso() -> str:
    # RFC3339 UTC with millisecond precision.
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _prune(value: Any) -> Any:
    """Recursively drop None values and empty dicts."""
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            pv = _prune(v)
            if pv is None or pv == {}:
                continue
            out[k] = pv
        return out
    return value


def _envelope(
    facade: Any,
    *,
    action: str,
    category: list[str],
    etype: list[str],
    kind: str = "event",
    outcome: str = "unknown",
    src_ip: str | None = None,
    src_port: int | None = None,
    conn_id: str | None = None,
) -> dict:
    return {
        "@timestamp": _now_iso(),
        "event": {
            "kind": kind,
            "category": category,
            "type": etype,
            "action": action,
            "outcome": outcome,
            "dataset": facade.dataset,
        },
        "source": {"ip": src_ip, "port": src_port},
        "destination": {"ip": facade.host_ip, "port": facade.port},
        "network": {"transport": "tcp", "protocol": facade.protocol},
        "host": {"id": facade.host_id, "name": facade.host_name},
        "service": {"type": facade.type_name, "id": facade.service_id},
        "rangefinder": {"conn_id": conn_id, "schema_version": SCHEMA_VERSION},
    }


# ------------------------------------------------------------------ service lifecycle


def service_listen(facade: Any) -> dict:
    ev = _envelope(
        facade,
        action="service_listen",
        category=["network"],
        etype=["info"],
        outcome="success",
    )
    return _prune(ev)


def host_event(facade_like: Any, action: str, extra: dict | None = None) -> dict:
    """Host-level lifecycle event (ready/stopping). facade_like carries host fields."""
    ev = {
        "@timestamp": _now_iso(),
        "event": {
            "kind": "event",
            "category": ["host"],
            "type": ["info"],
            "action": action,
            "outcome": "success",
            "dataset": "rangefinder.host",
        },
        "host": {"id": facade_like.host_id, "name": facade_like.host_name},
        "rangefinder": {"schema_version": SCHEMA_VERSION, **(extra or {})},
    }
    return _prune(ev)


# ------------------------------------------------------------------ connection events


def connection_open(scope: Any) -> dict:
    ev = _envelope(
        scope.facade,
        action="connection_open",
        category=["network"],
        etype=["connection", "start"],
        outcome="success",
        src_ip=scope.src_ip,
        src_port=scope.src_port,
        conn_id=scope.conn_id,
    )
    return _prune(ev)


def connection_close(scope: Any, duration_ns: int) -> dict:
    ev = _envelope(
        scope.facade,
        action="connection_close",
        category=["network"],
        etype=["connection", "end"],
        outcome="success",
        src_ip=scope.src_ip,
        src_port=scope.src_port,
        conn_id=scope.conn_id,
    )
    ev["event"]["duration"] = duration_ns
    return _prune(ev)


def connection_error(scope: Any, exc: BaseException) -> dict:
    ev = _envelope(
        scope.facade,
        action="connection_error",
        category=["network"],
        etype=["connection", "error"],
        outcome="failure",
        src_ip=scope.src_ip,
        src_port=scope.src_port,
        conn_id=scope.conn_id,
    )
    ev["error"] = {"type": type(exc).__name__, "message": str(exc)}
    return _prune(ev)


# --------------------------------------------------------------------- HTTP events


def http_request(
    scope: Any,
    *,
    method: str,
    path: str,
    query: str | None,
    original: str,
    version: str,
    user_agent: str | None,
    referrer: str | None,
    status_code: int,
    request_bytes: int,
    response_bytes: int,
    matched_route: str | None,
    vuln_id: str | None,
) -> dict:
    kind = "alert" if vuln_id else "event"
    ev = _envelope(
        scope.facade,
        action="http_request",
        category=["web"],
        etype=["access"],
        kind=kind,
        outcome="success",
        src_ip=scope.src_ip,
        src_port=scope.src_port,
        conn_id=scope.conn_id,
    )
    ev["url"] = {"path": path, "query": query, "original": original}
    ev["http"] = {
        "version": version,
        "request": {"method": method, "bytes": request_bytes, "referrer": referrer},
        "response": {"status_code": status_code, "bytes": response_bytes},
    }
    ev["user_agent"] = {"original": user_agent}
    ev["rangefinder"]["matched_route"] = matched_route
    ev["rangefinder"]["vuln_id"] = vuln_id
    return _prune(ev)


# ------------------------------------------------------------------- banner events


def banner_sent(scope: Any, banner: str) -> dict:
    ev = _envelope(
        scope.facade,
        action="banner_sent",
        category=["network"],
        etype=["info"],
        outcome="success",
        src_ip=scope.src_ip,
        src_port=scope.src_port,
        conn_id=scope.conn_id,
    )
    ev["rangefinder"]["banner"] = banner
    return _prune(ev)


def ldap_bind(
    scope: Any,
    *,
    bind_dn: str,
    method: str,
    result_code: str,
    password: str | None = None,
) -> dict:
    outcome = "success" if result_code == "success" else "failure"
    ev = _envelope(
        scope.facade,
        action="ldap_bind",
        category=["authentication"],
        etype=["start"],
        outcome=outcome,
        src_ip=scope.src_ip,
        src_port=scope.src_port,
        conn_id=scope.conn_id,
    )
    ev["rangefinder"]["auth"] = {
        "dn": bind_dn or "(anonymous)",
        "method": method,
        "result": result_code,
        # Captured attempted credential — this is a decoy range, so recording what an
        # attacker tried is intended telemetry.
        "password": password,
    }
    return _prune(ev)


def ldap_search(
    scope: Any,
    *,
    base: str,
    search_scope: str,
    filter_str: str,
    entries: int,
) -> dict:
    ev = _envelope(
        scope.facade,
        action="ldap_search",
        category=["network"],
        etype=["access"],
        outcome="success",
        src_ip=scope.src_ip,
        src_port=scope.src_port,
        conn_id=scope.conn_id,
    )
    ev["rangefinder"]["ldap"] = {
        "base": base,
        "scope": search_scope,
        "filter": filter_str,
        "entries": entries,
    }
    return _prune(ev)


def http_auth(
    scope: Any,
    *,
    scheme: str,
    username: str,
    password: str,
    path: str,
    outcome: str,
) -> dict:
    """Captured HTTP auth attempt (attacker-supplied credentials)."""
    ev = _envelope(
        scope.facade,
        action="http_auth",
        category=["authentication"],
        etype=["start"],
        outcome=outcome,
        src_ip=scope.src_ip,
        src_port=scope.src_port,
        conn_id=scope.conn_id,
    )
    ev["url"] = {"path": path}
    ev["rangefinder"]["auth"] = {
        "scheme": scheme,
        "user": username,
        "password": password,
    }
    return _prune(ev)


def dns_query(
    facade: Any,
    *,
    src_ip: str | None,
    src_port: int | None,
    transport: str,
    qname: str,
    qtype: str,
    rcode: str,
    answers: int,
) -> dict:
    ev = _envelope(
        facade,
        action="dns_query",
        category=["network"],
        etype=["access"],
        outcome="success" if rcode == "NOERROR" else "unknown",
        src_ip=src_ip,
        src_port=src_port,
    )
    ev["network"]["transport"] = transport
    ev["dns"] = {
        "question": {"name": qname, "type": qtype},
        "response_code": rcode,
        "answers_count": answers,
    }
    return _prune(ev)


def ssh_connection(facade: Any, action: str, *, src_ip, src_port, conn_id) -> dict:
    start = action == "connection_open"
    ev = _envelope(
        facade,
        action=action,
        category=["network"],
        etype=["connection", "start" if start else "end"],
        outcome="success",
        src_ip=src_ip,
        src_port=src_port,
        conn_id=conn_id,
    )
    return _prune(ev)


def ssh_auth(
    facade: Any,
    *,
    src_ip,
    src_port,
    conn_id,
    username: str,
    method: str,
    credential: str | None,
    outcome: str,
) -> dict:
    """Captured SSH auth attempt (attacker-supplied username + password/key)."""
    ev = _envelope(
        facade,
        action="ssh_auth",
        category=["authentication"],
        etype=["start"],
        outcome=outcome,
        src_ip=src_ip,
        src_port=src_port,
        conn_id=conn_id,
    )
    ev["rangefinder"]["auth"] = {"user": username, "method": method, "credential": credential}
    return _prune(ev)


def ssh_command(facade: Any, *, src_ip, src_port, conn_id, username: str, command: str) -> dict:
    ev = _envelope(
        facade,
        action="ssh_command",
        category=["process"],
        etype=["info"],
        outcome="success",
        src_ip=src_ip,
        src_port=src_port,
        conn_id=conn_id,
    )
    ev["rangefinder"]["ssh"] = {"user": username, "command": command}
    return _prune(ev)


def smb_event(
    facade: Any,
    action: str,
    *,
    category: list[str],
    etype: list[str],
    kind: str = "event",
    outcome: str = "unknown",
    src_ip: str | None = None,
    src_port: int | None = None,
    conn_id: str | None = None,
    extra: dict | None = None,
) -> dict:
    """Build an SMB telemetry event from parsed impacket log records.

    Unlike the asyncio facades, the SMB facade has no ConnScope — it passes the facade
    plus fields parsed out of impacket's server log directly.
    """
    ev = _envelope(
        facade,
        action=action,
        category=category,
        etype=etype,
        kind=kind,
        outcome=outcome,
        src_ip=src_ip,
        src_port=src_port,
        conn_id=conn_id,
    )
    if extra:
        ev["rangefinder"].update(extra)
    return _prune(ev)


def line_received(
    scope: Any, preview: str, matched_rule: str | None, vuln_id: str | None = None
) -> dict:
    kind = "alert" if vuln_id else "event"
    ev = _envelope(
        scope.facade,
        action="line_received",
        category=["network"],
        etype=["access"],
        kind=kind,
        outcome="success",
        src_ip=scope.src_ip,
        src_port=scope.src_port,
        conn_id=scope.conn_id,
    )
    ev["rangefinder"]["recv_preview"] = preview
    ev["rangefinder"]["rule_id"] = matched_rule
    ev["rangefinder"]["vuln_id"] = vuln_id
    return _prune(ev)
