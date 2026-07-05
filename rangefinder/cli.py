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
    p_cap_smb.add_argument("--shares", default=None,
                           help="comma-separated share names to capture (default: all readable)")
    p_cap_smb.add_argument("--max-files-per-share", type=int, default=200,
                           help="file budget per share so a big share can't starve the rest")
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

    p_cap_ssh = capture_sub.add_parser("ssh", help="capture a live SSH server's posture -> ssh facade")
    p_cap_ssh.add_argument("host", help="SSH server host or IP")
    p_cap_ssh.add_argument("--port", type=int, default=22)
    p_cap_ssh.add_argument("-o", "--out", type=Path, default=None)
    p_cap_ssh.add_argument("--name", default=None, help="range name")
    p_cap_ssh.add_argument("--host-id", default=None)
    p_cap_ssh.add_argument("--scrub", action="store_true", help="(no-op for ssh; posture holds no secrets)")

    p_score = sub.add_parser("score", help="score objectives against a telemetry log")
    p_score.add_argument("config", type=Path)
    p_score.add_argument("log", help="telemetry JSONL file, or - for stdin")
    p_score.add_argument("--json", action="store_true", help="emit results as JSON")

    p_detect = sub.add_parser(
        "detect", help="generate + validate SIEM (Sigma) detections from telemetry")
    p_detect.add_argument("--attack", required=True,
                          help="attack telemetry JSONL (labelled malicious), or - for stdin")
    p_detect.add_argument("--benign", default=None,
                          help="benign baseline telemetry JSONL (for false-positive scoring)")
    p_detect.add_argument("--rule", type=Path, default=None,
                          help="validate this Sigma rule file instead of generating templates")
    p_detect.add_argument("-o", "--out", type=Path, default=None,
                          help="write validated rules as .yml into this directory")

    p_run = sub.add_parser("run", help="serve a host's facades (container entrypoint)")
    p_run.add_argument("--host", required=True)
    p_run.add_argument("--config", required=True, type=Path)
    p_run.add_argument("--log-file", type=Path, default=None)

    p_verify = sub.add_parser("verify", help="measure replica fidelity against a live target")
    verify_sub = p_verify.add_subparsers(dest="proto", required=True)
    p_v_http = verify_sub.add_parser("http", help="capture + diff a live web server")
    p_v_http.add_argument("url", help="base URL, e.g. http://10.0.0.5/")
    p_v_http.add_argument("--max", type=int, default=200, help="max paths to probe")
    p_v_http.add_argument("--nmap", action="store_true",
                          help="also compare the nmap -sV service fingerprint (needs nmap)")
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

    p_v_ssh = verify_sub.add_parser("ssh", help="capture + diff a live SSH server's posture")
    p_v_ssh.add_argument("host", help="SSH server host or IP")
    p_v_ssh.add_argument("--port", type=int, default=22)
    p_v_ssh.add_argument("--json", action="store_true", help="emit the report as JSON")

    p_merge = sub.add_parser(
        "merge", help="merge captured single-service configs into one estate twin")
    p_merge.add_argument("configs", nargs="+", type=Path,
                         help="range config JSONs to merge (e.g. per-service captures)")
    p_merge.add_argument("-o", "--out", type=Path, default=None)
    p_merge.add_argument("--name", default=None, help="range name for the merged config")
    p_merge.add_argument("--subnet", default=None,
                         help="subnet for the merged range (default: derived from host IPs)")

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
        "merge": cmd_merge,
        "score": cmd_score,
        "detect": cmd_detect,
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

    capture_report = None  # every captor returns a provenance report; written as a sidecar below

    if args.captor == "http":
        from rangefinder.capture import capture_http

        try:
            service, warnings, capture_report = capture_http(
                args.url, max_paths=args.max, scrub=args.scrub)
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
            service, warnings, capture_report = capture_ldap(
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
            share_filter = [s for s in (args.shares or "").split(",") if s.strip()] or None
            service, warnings, capture_report = capture_smb(
                hostname, args.port, username=args.username,
                password=args.password, domain=args.domain, scrub=args.scrub,
                max_files_per_share=args.max_files_per_share, shares=share_filter,
            )
        except Exception as exc:  # impacket raises many exception types
            print(f"error: SMB capture failed: {exc}", file=sys.stderr)
            return EXIT_ERROR
        default_id = "fs"
    elif args.captor == "dns":
        from rangefinder.capture import capture_dns

        hostname = args.host
        try:
            service, warnings, capture_report = capture_dns(
                hostname, args.port, zone=args.zone, scrub=args.scrub)
        except (ValueError, OSError) as exc:
            print(f"error: DNS capture failed: {exc}", file=sys.stderr)
            return EXIT_ERROR
        default_id = "ns"
    elif args.captor == "ssh":
        from rangefinder.capture.ssh import capture_ssh

        hostname = args.host
        try:
            service, warnings, capture_report = capture_ssh(hostname, args.port)
        except (ValueError, OSError) as exc:
            print(f"error: SSH capture failed: {exc}", file=sys.stderr)
            return EXIT_ERROR
        default_id = "ssh"
    else:
        print(f"error: unknown captor {args.captor!r}", file=sys.stderr)
        return EXIT_ERROR

    config = _capture_config(service, hostname, args, warnings, default_id)
    try:
        RangeConfig.model_validate(config)
    except Exception as exc:
        print(f"error: captured config is invalid: {exc}", file=sys.stderr)
        return EXIT_ERROR

    _emit_config(json.dumps(config, indent=2) + "\n", args.out)
    for w in warnings:
        print(f"note: {w}", file=sys.stderr)

    # Provenance sidecar: what the twin reproduces from measurement vs. fail-closed assumption
    # vs. what can't be measured at this access level. Kept out of the config so the config stays
    # clean and editable; written next to it (and always printed) so assumptions can't hide.
    if capture_report is not None:
        _print_capture_report(capture_report)
        if args.out:
            sidecar = Path(args.out).with_suffix(".capture-report.md")
            sidecar.write_text(capture_report.to_markdown(), encoding="utf-8")
            print(f"wrote {sidecar}", file=sys.stderr)
    return EXIT_OK


def _emit_config(text: str, out) -> None:
    """Write a generated config to *out* (announcing it on stderr) or to stdout."""
    if out:
        Path(out).write_text(text, encoding="utf-8")
        print(f"wrote {out}", file=sys.stderr)
    else:
        sys.stdout.write(text)


def _print_capture_report(report) -> None:
    """Print a compact posture summary to stderr: the ⚠ assumed and ✗ unmeasurable lines are the
    ones a reviewer must act on, so surface counts and list those two tiers explicitly."""
    tiers = {t: [i for i in report.items if i.status == t]
             for t in ("measured", "assumed", "unmeasurable")}
    print(f"posture ({report.perspective}): "
          f"{len(tiers['measured'])} measured, {len(tiers['assumed'])} assumed, "
          f"{len(tiers['unmeasurable'])} unmeasurable", file=sys.stderr)
    for tier, mark in (("assumed", "⚠ assumed"), ("unmeasurable", "✗ unmeasurable")):
        for i in tiers[tier]:
            note = f" — {i.note}" if i.note else ""
            print(f"  {mark}: {i.field} = {i.value}{note}", file=sys.stderr)


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


def cmd_merge(args) -> int:
    from rangefinder.orchestrate.merge import merge_configs

    # Load each input through the normal loader so a bad fragment reports a friendly, located
    # error; dump back to a plain dict (IPs -> str, defaults filled) for the pure merger.
    dumped: list[dict] = []
    for path in args.configs:
        try:
            cfg = load_config(path)
        except ConfigError as exc:
            print(str(exc), file=sys.stderr)
            return EXIT_CONFIG
        dumped.append(cfg.model_dump(mode="json", exclude_none=True))

    try:
        merged, warnings = merge_configs(dumped, name=args.name, subnet=args.subnet)
    except ValueError as exc:
        print(f"error: merge failed: {exc}", file=sys.stderr)
        return EXIT_ERROR

    try:
        RangeConfig.model_validate(merged)
    except Exception as exc:
        print(f"error: merged config is invalid: {exc}", file=sys.stderr)
        return EXIT_ERROR

    _emit_config(json.dumps(merged, indent=2) + "\n", args.out)
    for w in warnings:
        print(f"note: {w}", file=sys.stderr)

    # Stitch the inputs' provenance sidecars into one, so the merged twin keeps the
    # measured/assumed/unmeasurable tiering rather than losing it in the join. Write it beside the
    # config when there is one; otherwise surface it on stderr so stdout mode doesn't drop it.
    combined = _combined_capture_report(args.configs)
    if combined:
        if args.out:
            sidecar = Path(args.out).with_suffix(".capture-report.md")
            sidecar.write_text(combined, encoding="utf-8")
            print(f"wrote {sidecar}", file=sys.stderr)
        else:
            print(combined, file=sys.stderr)
    return EXIT_OK


def _combined_capture_report(config_paths) -> str:
    """Concatenate each input's sibling ``*.capture-report.md`` under a per-source heading.

    A source without a sidecar (hand-authored config, or the sidecar wasn't co-located) gets an
    explicit "provenance unknown" section rather than being silently omitted — the merged report
    must not imply it covers the whole estate when a source's tiering is missing.
    """
    sections: list[str] = []
    for path in config_paths:
        sidecar = Path(path).with_suffix(".capture-report.md")
        if sidecar.exists():
            sections.append(f"# from {path.name}\n\n{sidecar.read_text(encoding='utf-8').strip()}")
        else:
            sections.append(f"# from {path.name}\n\n_No capture-report sidecar found — provenance "
                            f"unknown for this source (hand-authored, or sidecar not co-located)._")
    if not sections:
        return ""
    header = ("# Merged capture provenance\n\n"
              "This estate twin was assembled from the sources below; each captured source keeps "
              "its original measured / assumed / unmeasurable tiering.\n\n---\n\n")
    return header + "\n\n---\n\n".join(sections) + "\n"


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

        _emit_config(json.dumps(config, indent=2) + "\n", args.out)

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


def cmd_detect(args) -> int:
    import re

    import yaml

    from rangefinder import detect as det

    def load(path: str | None) -> list[dict]:
        if not path:
            return []
        text = sys.stdin.read() if path == "-" else Path(path).read_text(encoding="utf-8")
        return det.parse_events(text.splitlines())

    attack = load(args.attack)
    benign = load(args.benign)
    if not attack:
        print("no attack telemetry events found", file=sys.stderr)
        return EXIT_CONFIG

    if args.rule:
        rules = [yaml.safe_load(args.rule.read_text(encoding="utf-8"))]
    else:
        rules = det.generate(attack)
        if not rules:
            print("no known techniques found in the attack telemetry", file=sys.stderr)
            return EXIT_ERROR

    print(f"Detections vs telemetry  (attack: {len(attack)} events, benign: {len(benign)} events)\n")
    validated: list[dict] = []
    for rule in rules:
        v = det.validate(rule, attack, benign)
        print(f"  [{'PASS' if v.ok else 'FAIL'}] {v.title}")
        print(f"         TP {v.true_positives}/{v.attack_total}   "
              f"FP {v.false_positives}/{v.benign_total}   -> {v.verdict}")
        if v.ok:
            validated.append(rule)
    print(f"\n{len(validated)}/{len(rules)} rule(s) validated against ground truth.")

    if args.out and validated:
        args.out.mkdir(parents=True, exist_ok=True)
        for rule in validated:
            slug = re.sub(r"[^a-z0-9]+", "-", str(rule.get("title", "rule")).lower()).strip("-")
            (args.out / f"{slug}.yml").write_text(
                yaml.safe_dump(rule, sort_keys=False, allow_unicode=True))
        print(f"wrote {len(validated)} rule(s) to {args.out}/")
    return EXIT_OK if validated else EXIT_ERROR


def cmd_verify(args) -> int:
    import dataclasses

    from rangefinder.verify import verify_dns, verify_http, verify_ldap, verify_smb, verify_ssh

    try:
        if args.proto == "http":
            report = verify_http(args.url, max_paths=args.max, nmap=args.nmap)
        elif args.proto == "smb":
            report = verify_smb(args.host, args.port, username=args.username,
                                password=args.password, domain=args.domain)
        elif args.proto == "dns":
            report = verify_dns(args.host, args.port, zone=args.zone)
        elif args.proto == "ssh":
            report = verify_ssh(args.host, args.port)
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
