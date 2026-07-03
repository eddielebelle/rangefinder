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

    p_run = sub.add_parser("run", help="serve a host's facades (container entrypoint)")
    p_run.add_argument("--host", required=True)
    p_run.add_argument("--config", required=True, type=Path)
    p_run.add_argument("--log-file", type=Path, default=None)

    p_up = sub.add_parser("up", help="docker compose up -d in an output directory")
    p_up.add_argument("-o", "--out", type=Path, default=Path("."))

    p_down = sub.add_parser("down", help="docker compose down in an output directory")
    p_down.add_argument("-o", "--out", type=Path, default=Path("."))

    args = parser.parse_args(argv)
    handler = {
        "validate": cmd_validate,
        "schema": cmd_schema,
        "gen": cmd_gen,
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
        hosts=tuple((h.hostname, str(h.ip)) for h in cfg.hosts),
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
