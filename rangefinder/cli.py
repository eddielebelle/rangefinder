"""rangefinder command-line interface."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from rangefinder import __version__
from rangefinder.config.loader import ConfigError, load_config
from rangefinder.config.model import RangeConfig
from rangefinder.facades import build_facade, registered_types
from rangefinder.facades.base import FacadeContext
from rangefinder.runtime import serve_host
from rangefinder.telemetry.emitter import Emitter, FileSink, StdoutSink

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_CONFIG = 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="rangefinder",
        description="Declarative cyber-range generator (protocol facades + telemetry).",
    )
    parser.add_argument("--version", action="version", version=f"rangefinder {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_validate = sub.add_parser("validate", help="validate a range config")
    p_validate.add_argument("config", type=Path)

    p_schema = sub.add_parser("schema", help="export the config JSON Schema")
    p_schema.add_argument("-o", "--out", type=Path, default=None)

    p_gen = sub.add_parser("gen", help="generate a docker-compose stack")
    p_gen.add_argument("config", type=Path)
    p_gen.add_argument("-o", "--out", type=Path, required=True, help="output directory")
    p_gen.add_argument(
        "--no-attacker", action="store_true", help="omit the attacker container"
    )

    p_import = sub.add_parser("import", help="generate a config from real-infra discovery output")
    import_sub = p_import.add_subparsers(dest="importer", required=True)
    p_imp_nmap = import_sub.add_parser("nmap", help="from an nmap -oX XML scan")
    p_imp_nmap.add_argument("scan", type=Path)
    p_imp_nmap.add_argument("-o", "--out", type=Path, default=None, help="output config (default stdout)")
    p_imp_nmap.add_argument("--name", default="imported", help="range name")
    p_imp_nmap.add_argument("--subnet", default=None, help="override the derived subnet CIDR")

    p_capture = sub.add_parser("capture", help="record a live service into a faithful facade")
    capture_sub = p_capture.add_subparsers(dest="captor", required=True)
    p_cap_http = capture_sub.add_parser("http", help="crawl a live web server -> http facade")
    p_cap_http.add_argument("url", help="base URL, e.g. https://10.0.0.5/")
    p_cap_http.add_argument("-o", "--out", type=Path, default=None)
    p_cap_http.add_argument("--name", default=None, help="range name")
    p_cap_http.add_argument("--host-id", default=None)
    p_cap_http.add_argument("--scrub", action="store_true", help="redact captured secrets")
    p_cap_http.add_argument("--max", type=int, default=200, help="max paths to probe")

    p_cap_ldap = capture_sub.add_parser("ldap", help="enumerate a live directory -> ldap facade")
    p_cap_ldap.add_argument("host", help="host, host:port, or ldap(s)://host:port")
    p_cap_ldap.add_argument("--port", type=int, default=None)
    p_cap_ldap.add_argument("--tls", action="store_true", help="use LDAPS")
    p_cap_ldap.add_argument("--bind-dn", default="", help="bind DN (default: anonymous)")
    p_cap_ldap.add_argument("--password", default="")
    p_cap_ldap.add_argument("-o", "--out", type=Path, default=None)
    p_cap_ldap.add_argument("--name", default=None, help="range name")
    p_cap_ldap.add_argument("--host-id", default=None)
    p_cap_ldap.add_argument("--scrub", action="store_true", help="redact secret attributes")

    p_cap_smb = capture_sub.add_parser("smb", help="enumerate live shares -> smb facade")
    p_cap_smb.add_argument("host", help="host or IP")
    p_cap_smb.add_argument("--port", type=int, default=445)
    p_cap_smb.add_argument("--username", default="", help="username (default: null session)")
    p_cap_smb.add_argument("--password", default="")
    p_cap_smb.add_argument("--domain", default="")
    p_cap_smb.add_argument("-o", "--out", type=Path, default=None)
    p_cap_smb.add_argument("--name", default=None, help="range name")
    p_cap_smb.add_argument("--host-id", default=None)
    p_cap_smb.add_argument("--scrub", action="store_true", help="redact captured secrets")

    p_cap_dns = capture_sub.add_parser("dns", help="capture a live DNS zone -> dns facade")
    p_cap_dns.add_argument("host", help="DNS server host or IP")
    p_cap_dns.add_argument("--zone", required=True, help="zone to capture, e.g. acme.corp")
    p_cap_dns.add_argument("--port", type=int, default=53)
    p_cap_dns.add_argument("-o", "--out", type=Path, default=None)
    p_cap_dns.add_argument("--name", default=None, help="range name")
    p_cap_dns.add_argument("--host-id", default=None)
    p_cap_dns.add_argument("--scrub", action="store_true", help="redact captured secrets")

    p_score = sub.add_parser("score", help="score objectives against a telemetry log")
    p_score.add_argument("config", type=Path)
    p_score.add_argument("log", help="telemetry JSONL file, or - for stdin")
    p_score.add_argument("--json", action="store_true", help="emit results as JSON")

    p_run = sub.add_parser("run", help="serve a host's facades (container entrypoint)")
    p_run.add_argument("--host", required=True)
    p_run.add_argument("--config", required=True, type=Path)
    p_run.add_argument("--log-file", type=Path, default=None)

    p_verify = sub.add_parser("verify", help="measure replica fidelity against a live target")
    verify_sub = p_verify.add_subparsers(dest="proto", required=True)
    p_v_http = verify_sub.add_parser("http", help="capture + diff a live web server")
    p_v_http.add_argument("url", help="base URL, e.g. http://10.0.0.5/")
    p_v_http.add_argument("--max", type=int, default=200, help="max paths to probe")
    p_v_ldap = verify_sub.add_parser("ldap", help="capture + diff a live directory")
    p_v_ldap.add_argument("host", help="host or ldap[s]://host")
    p_v_ldap.add_argument("--port", type=int, default=None)
    p_v_ldap.add_argument("--tls", action="store_true", help="use LDAPS")
    p_v_ldap.add_argument("--bind-dn", default="", help="bind DN (default: anonymous)")
    p_v_ldap.add_argument("--password", default="")
    p_v_ldap.add_argument("--json", action="store_true", help="emit the report as JSON")
    p_v_http.add_argument("--json", action="store_true", help="emit the report as JSON")
    p_v_smb = verify_sub.add_parser("smb", help="capture + diff live file shares")
    p_v_smb.add_argument("host")
    p_v_smb.add_argument("--port", type=int, default=445)
    p_v_smb.add_argument("--username", default="", help="user (default: null session)")
    p_v_smb.add_argument("--password", default="")
    p_v_smb.add_argument("--domain", default="")
    p_v_smb.add_argument("--json", action="store_true", help="emit the report as JSON")
    p_v_dns = verify_sub.add_parser("dns", help="capture + diff a live DNS zone")
    p_v_dns.add_argument("host")
    p_v_dns.add_argument("--zone", required=True, help="zone, e.g. acme.corp")
    p_v_dns.add_argument("--port", type=int, default=53)
    p_v_dns.add_argument("--json", action="store_true", help="emit the report as JSON")

    p_up = sub.add_parser("up", help="docker compose up -d in an output directory")
    p_up.add_argument("-o", "--out", type=Path, default=Path("."))

    p_down = sub.add_parser("down", help="docker compose down in an output directory")
    p_down.add_argument("-o", "--out", type=Path, default=Path("."))

    args = parser.parse_args(argv)
    handler = {
        "validate": cmd_validate,
        "schema": cmd_schema,
        "gen": cmd_gen,
        "import": cmd_import,
        "capture": cmd_capture,
        "score": cmd_score,
        "verify": cmd_verify,
        "run": cmd_run,
        "up": cmd_up,
        "down": cmd_down,
    }[args.cmd]
    return handler(args)


def cmd_validate(args) -> int:
    try:
        cfg = load_config(args.config)
    except ConfigError as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_CONFIG
    _print_summary(cfg)
    return EXIT_OK


def cmd_schema(args) -> int:
    schema = RangeConfig.model_json_schema(ref_template="#/$defs/{model}")
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["title"] = "Rangefinder range config"
    text = json.dumps(schema, indent=2)
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
        print(f"wrote JSON Schema to {args.out}")
    else:
        print(text)
    return EXIT_OK


def cmd_gen(args) -> int:
    from rangefinder.orchestrate import write_outputs

    try:
        cfg = load_config(args.config)
    except ConfigError as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_CONFIG

    compose_path = write_outputs(
        cfg, args.out, args.config, include_attacker=not args.no_attacker
    )
    print(f"wrote {compose_path}")
    print(f"wrote {args.out / 'config.json'}")
    print()
    print("Next steps:")
    print("  docker build -t rangefinder:latest .")
    print(f"  docker compose -f {compose_path} up -d")
    print(
        f"  docker compose -f {compose_path} --profile attacker run --rm attacker"
    )
    return EXIT_OK


def cmd_capture(args) -> int:
    from urllib.parse import urlparse

    if args.captor == "http":
        from rangefinder.capture import capture_http

        try:
            service, warnings = capture_http(args.url, max_paths=args.max, scrub=args.scrub)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_ERROR
        parsed = urlparse(args.url if "://" in args.url else "http://" + args.url)
        hostname = parsed.hostname or "target"
        default_id = "web"
    elif args.captor == "ldap":
        from rangefinder.capture import capture_ldap

        parsed = urlparse(args.host if "://" in args.host else "ldap://" + args.host)
        hostname = parsed.hostname or "target"
        tls = args.tls or parsed.scheme == "ldaps"
        port = args.port or parsed.port or (636 if tls else 389)
        try:
            service, warnings = capture_ldap(
                hostname, port, tls=tls, bind_dn=args.bind_dn,
                password=args.password, scrub=args.scrub,
            )
        except (ValueError, OSError) as exc:
            print(f"error: LDAP capture failed: {exc}", file=sys.stderr)
            return EXIT_ERROR
        default_id = "dc"
    elif args.captor == "smb":
        from rangefinder.capture import capture_smb

        hostname = args.host
        try:
            service, warnings = capture_smb(
                hostname, args.port, username=args.username,
                password=args.password, domain=args.domain, scrub=args.scrub,
            )
        except Exception as exc:  # impacket raises many exception types
            print(f"error: SMB capture failed: {exc}", file=sys.stderr)
            return EXIT_ERROR
        default_id = "fs"
    elif args.captor == "dns":
        from rangefinder.capture import capture_dns

        hostname = args.host
        try:
            service, warnings = capture_dns(hostname, args.port, zone=args.zone, scrub=args.scrub)
        except (ValueError, OSError) as exc:
            print(f"error: DNS capture failed: {exc}", file=sys.stderr)
            return EXIT_ERROR
        default_id = "ns"
    else:
        print(f"error: unknown captor {args.captor!r}", file=sys.stderr)
        return EXIT_ERROR

    config = _capture_config(service, hostname, args, warnings, default_id)
    try:
        RangeConfig.model_validate(config)
    except Exception as exc:
        print(f"error: captured config is invalid: {exc}", file=sys.stderr)
        return EXIT_ERROR

    text = json.dumps(config, indent=2) + "\n"
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"wrote {args.out}", file=sys.stderr)
    else:
        sys.stdout.write(text)
    for w in warnings:
        print(f"note: {w}", file=sys.stderr)
    return EXIT_OK


def _capture_config(service, hostname, args, warnings, default_id) -> dict:
    import ipaddress
    import re

    try:
        ip = str(ipaddress.ip_address(hostname))
        subnet = str(ipaddress.ip_network(ip + "/24", strict=False))
    except ValueError:
        ip = "10.99.0.10"
        subnet = "10.99.0.0/24"
        warnings.append(f"target is a hostname; assigned placeholder IP {ip} (edit as needed)")

    from rangefinder.config.model import SCHEMA_VERSION

    host_id = args.host_id or (re.sub(r"[^a-z0-9-]", "-", hostname.split(".")[0].lower()).strip("-") or default_id)
    name = re.sub(r"[^a-z0-9_-]", "-", (args.name or hostname).lower()).strip("-_") or "captured"
    return {
        "name": name[:62],
        "schema_version": SCHEMA_VERSION,
        "network": {"subnet": subnet},
        "hosts": [{"id": host_id[:63], "hostname": hostname, "ip": ip,
                   "os": "generic_linux", "services": [service]}],
    }


def cmd_import(args) -> int:
    if args.importer == "nmap":
        from rangefinder.importers import import_nmap

        try:
            config, summary, warnings = import_nmap(
                args.scan, name=args.name, subnet=args.subnet
            )
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_ERROR

        text = json.dumps(config, indent=2) + "\n"
        if args.out:
            Path(args.out).write_text(text, encoding="utf-8")
            print(f"wrote {args.out}", file=sys.stderr)
        else:
            sys.stdout.write(text)

        facades = ", ".join(f"{n}×{t}" for t, n in summary["facades"].items())
        print(
            f"imported {summary['hosts']} hosts, {summary['services']} services "
            f"({facades}) on {summary['subnet']}"
            + (f"; skipped {summary['skipped_hosts']}" if summary["skipped_hosts"] else ""),
            file=sys.stderr,
        )
        for w in warnings:
            print(f"warning: {w}", file=sys.stderr)
        return EXIT_OK
    print(f"error: unknown importer {args.importer!r}", file=sys.stderr)
    return EXIT_ERROR


def cmd_score(args) -> int:
    import dataclasses

    from rangefinder.scoring import parse_events, score

    try:
        cfg = load_config(args.config)
    except ConfigError as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_CONFIG

    if args.log == "-":
        events = parse_events(sys.stdin)
    else:
        try:
            with open(args.log, encoding="utf-8", errors="replace") as fh:
                events = parse_events(fh)
        except OSError as exc:
            print(f"error: cannot read log {args.log}: {exc}", file=sys.stderr)
            return EXIT_ERROR

    results = score(cfg, events)

    if args.json:
        print(json.dumps([dataclasses.asdict(r) for r in results], indent=2))
        return EXIT_OK

    scoreable = [r for r in results if r.scoreable]
    met = [r for r in scoreable if r.met]
    print(f"Scoring: {cfg.name}   ({len(events)} events, {len(scoreable)} scoreable objectives)")
    print()
    for r in results:
        tag = "UNSCORED" if not r.scoreable else ("MET" if r.met else "UNMET")
        print(f"  [{tag:8}] {r.id}  —  {r.title}")
        if r.met and r.kind == "sequence":
            print(f"             kill chain completed at {r.timestamp} by {r.source_ip}:")
            for i, step in enumerate(r.chain, 1):
                label = step.get("label") or step.get("action")
                print(f"               {i}. {label}  at {step['timestamp']} ({step['action']})")
        elif r.met:
            via = f' via "{r.signal}"' if r.signal else ""
            print(f"             first{via} at {r.timestamp} by {r.source_ip} ({r.action})")
            print(f"             {r.match_count} matching event(s) from {', '.join(r.source_ips) or 'n/a'}")
    print()
    print(f"Summary: {len(met)}/{len(scoreable)} objectives met")
    return EXIT_OK


def cmd_verify(args) -> int:
    import dataclasses

    from rangefinder.verify import verify_dns, verify_http, verify_ldap, verify_smb

    try:
        if args.proto == "http":
            report = verify_http(args.url, max_paths=args.max)
        elif args.proto == "smb":
            report = verify_smb(args.host, args.port, username=args.username,
                                password=args.password, domain=args.domain)
        elif args.proto == "dns":
            report = verify_dns(args.host, args.port, zone=args.zone)
        elif args.proto == "ldap":
            from urllib.parse import urlparse

            parsed = urlparse(args.host if "://" in args.host else "ldap://" + args.host)
            hostname = parsed.hostname or args.host
            tls = args.tls or parsed.scheme == "ldaps"
            port = args.port or parsed.port or (636 if tls else 389)
            report = verify_ldap(hostname, port, tls=tls, bind_dn=args.bind_dn,
                                 password=args.password)
        else:
            print(f"error: unknown proto {args.proto!r}", file=sys.stderr)
            return EXIT_ERROR
    except (ValueError, OSError, RuntimeError, EOFError) as exc:
        print(f"error: verify failed: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except Exception as exc:  # network I/O against arbitrary targets: never dump a traceback
        print(f"error: verify failed ({type(exc).__name__}): {exc}", file=sys.stderr)
        return EXIT_ERROR

    if args.json:
        print(json.dumps(dataclasses.asdict(report) | {"score": report.score, "ok": report.ok}, indent=2))
        return EXIT_OK if report.ok else EXIT_ERROR

    pct = report.score * 100
    print(f"Fidelity: {report.protocol}  {report.target}")
    print(f"  {report.matched}/{report.total} faithful ({pct:.1f}%) from the consumer's perspective")
    if report.divergences:
        print(f"  divergences ({len(report.divergences)}):")
        for d in report.divergences:
            print(f"    {d.kind:8} {d.key}  —  {d.detail}")
    if report.boundary:
        print("  fidelity boundary:")
        for b in report.boundary:
            print(f"    - {b}")
    # Detection perspective: did the tool actions produce SIEM telemetry?
    alert_note = f", {report.alerts} alert(s)" if report.alerts else ""
    print(f"  detection: {report.telemetry_events} telemetry event(s){alert_note} emitted while probed")
    if report.blind_spots:
        print(f"  detection blind spots ({len(report.blind_spots)}) — served but not logged:")
        for b in report.blind_spots:
            print(f"    {b}")
    for w in report.warnings:
        print(f"  note: {w}", file=sys.stderr)
    print()
    verdict = "FAITHFUL & OBSERVABLE" if report.ok else "ISSUES FOUND"
    print(f"  => {verdict}")
    return EXIT_OK if report.ok else EXIT_ERROR


def cmd_run(args) -> int:
    try:
        cfg = load_config(args.config)
    except ConfigError as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_CONFIG
    try:
        host = cfg.get_host(args.host)
    except KeyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_CONFIG

    sinks = [StdoutSink()]
    if args.log_file:
        sinks.append(FileSink(args.log_file))
    emitter = Emitter(sinks)

    ctx = FacadeContext(
        host_id=host.id,
        host_name=host.hostname,
        host_ip=str(host.ip),
        emitter=emitter,
        config_dir=str(Path(args.config).resolve().parent),
        identities=cfg.identities,
        hosts=tuple(cfg.hosts),
    )

    try:
        facades = [build_facade(svc, ctx) for svc in host.services]
    except (NotImplementedError, ValueError, OSError) as exc:
        print(f"error building facades for host {host.id!r}: {exc}", file=sys.stderr)
        return EXIT_CONFIG

    try:
        serve_host(facades, emitter, ctx)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    return EXIT_OK


def cmd_up(args) -> int:
    return _compose(args.out, ["up", "-d"])


def cmd_down(args) -> int:
    return _compose(args.out, ["down"])


def _compose(outdir: Path, extra: list[str]) -> int:
    compose_file = Path(outdir) / "docker-compose.yml"
    if not compose_file.exists():
        print(f"error: {compose_file} not found; run `rangefinder gen` first", file=sys.stderr)
        return EXIT_ERROR
    cmd = ["docker", "compose", "-f", str(compose_file), *extra]
    print("+ " + " ".join(cmd))
    try:
        return subprocess.run(cmd).returncode
    except FileNotFoundError:
        print("error: docker not found on PATH", file=sys.stderr)
        return EXIT_ERROR


def _print_summary(cfg: RangeConfig) -> None:
    print(f"range: {cfg.name}   subnet: {cfg.network.subnet}")
    print(f"hosts: {len(cfg.hosts)}")
    for host in cfg.hosts:
        svc = ", ".join(f"{s.type}/{s.port}" for s in host.services)
        tags = f"  [{', '.join(host.tags)}]" if host.tags else ""
        print(f"  - {host.id} ({host.hostname}) {host.ip}  {host.os.value}{tags}")
        print(f"      services: {svc}")
    if cfg.identities:
        ids = cfg.identities
        print(
            f"identities: domain={ids.domain} "
            f"users={len(ids.users)} groups={len(ids.groups)}"
        )
    if cfg.objectives:
        print(f"objectives: {len(cfg.objectives)}")
    print(f"registered facade types: {', '.join(registered_types())}")


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
