# Rangefinder — declarative cyber-range generator (v1 plan)

## Context

The user wants a tool that turns JSON configs into realistic, disposable **cyber ranges** for
authorized security testing. Instead of hosting real software (a real AD domain, real web apps),
the tool renders **facades** — lightweight protocol servers that answer real recon/enumeration
tooling accurately enough to test against, and emit SIEM-ready telemetry as they do. The intended
outcome: author a range as one JSON file, `docker compose up` a fake network, point tools at it,
and collect structured logs of everything that touched it.

Scoping decisions confirmed with the user:
- **Fidelity target:** detection/SOC evals + recon/enum tooling (nmap, ldapsearch, enum4linux,
  dirb/gobuster, curl) + human red-teamers poking manually. **Not** full offensive-framework auth
  flows (BloodHound/impacket Kerberos/NTLM) in v1 → **enumeration/version-detection grade**, not
  real protocol auth.
- **Telemetry is a first-class output.** Every facade interaction emits a structured, ECS-aligned
  JSON event. This is the core deliverable for the detection/SOC use case.
- **Deployment:** Docker, **one container per fake host**, real per-host static IPs on a
  user-defined bridge network so topology is genuine and a red-teamer can attach.
- **Scoring:** out of scope for v1 — "just log everything." Objectives are descriptive metadata
  only; no automated pass/fail engine yet.

Greenfield: directory is empty except `pyproject.toml` (already scaffolded a moment before plan
mode: package `rangefinder`, python>=3.10, dep `pydantic>=2.5`, console script
`rangefinder=rangefinder.cli:main`). Single runtime dependency by design — everything else stdlib,
which keeps the container image small and the protocol behavior predictable.

## Architecture — four layers

1. **Model layer** (`rangefinder/config/`) — pydantic v2 models; the JSON config is the single
   source of truth. Range → network → hosts → services (+ identities, objectives). Services are a
   **typed discriminated union on `type`** so authoring gets editor autocomplete, `validate` catches
   typos at compile time, and we can export a JSON Schema.
2. **Facade layer** (`rangefinder/facades/`) — a registry keyed by service `type` mapping to
   `(facade_class, config_model)`. Each facade reads its already-typed config + host context and
   renders protocol-accurate responses. **Facade instances are shared across connections — all
   per-connection state lives in locals / a `ConnScope`, never on `self`.**
3. **Runtime layer** (`rangefinder/runtime/`) — per-host supervisor: one asyncio event loop serving
   all of that host's facades concurrently; binds all listeners up front (abort all if any fails);
   graceful SIGTERM/SIGINT shutdown that beats Docker's 10s SIGKILL.
4. **Telemetry layer** (`rangefinder/telemetry/`) — canonical ECS-aligned event → JSON-lines to
   stdout (container-native) + optional file sink; synchronous flush-per-event so nothing is lost
   on shutdown.

## v1 scope — runnable end-to-end

Two protocol facades, **stdlib-only** (highest coverage per effort, no fragile third-party deps):
- **`http`** (`asyncio.start_server`): server header, route/path table (status/body/body_file/
  content-type/planted-vuln tag), default 404, HEAD support, correct `Content-Length`/`Date`/
  `Server`, body draining + keep-alive (so scanners don't desync), read timeouts, 405 on
  method-mismatch. Satisfies curl/dirb/gobuster + HTTP version detection.
- **`banner`** (generic TCP; `ssh`/`ftp`/`smtp` are presets/examples of it): sends a configurable
  server-speaks-first banner immediately on connect (correct terminator — `\r\n` for SSH), optional
  line-regex→response rules, connection + line logging. Tuned for nmap `-sV`.

Both emit full telemetry. Config schema also *defines* `ldap`/`smb`/`dns` service + AD `identities`
models so configs are forward-shaped, but their **protocol facades are explicitly v2** — in v1 a DC
host represents 389/445/53 as `banner` decoys (ports open, believable banners) so nmap sweeps see a
realistic multi-host topology today.

Deferred to v2 (same skeleton): enumeration-grade LDAP rendering `identities`, SMB share
enumeration, DNS zone responses, real SSH transport (asyncssh), TLS/HTTPS, a scoring engine over
`objectives`, and entry-point facade plugins.

## Module layout

```
rangefinder/
  cli.py                     # argparse: validate / schema / gen / run / up / down
  config/
    services.py              # per-facade pydantic config models + BuiltinService union
    model.py                 # RangeConfig, Network, Host, Identities(ADUser/ADGroup), Objective, OS
    loader.py                # load_config(path) -> RangeConfig; ConfigError
  facades/
    registry.py              # register(type, config_model); _REGISTRY[type]=(facade_cls, cfg_model)
    base.py                  # Facade ABC, FacadeContext, ConnScope, _wrapped_handle safety wrapper
    http.py                  # HttpFacade
    banner.py                # BannerFacade
    __init__.py              # imports http+banner to trigger registration
  telemetry/
    event.py                 # ECS-aligned Event model + ConnScope factory helpers
    emitter.py               # Emitter, StdoutSink, FileSink
  runtime/
    supervisor.py            # HostSupervisor: bind-all, serve-all, graceful shutdown
  orchestrate/
    compose.py               # build_compose(cfg)->dict ; write_outputs() ; JSON-as-YAML
Dockerfile                   # single runtime image, non-root
examples/corp.json           # example range
tests/                       # config validation + facade response unit tests
README.md                    # model, usage, honest fidelity limits
```

## Key interfaces (settled)

- **Registry** (`facades/registry.py`): `register(type_key, config_model)` decorator populates
  `_REGISTRY[type_key] = (facade_cls, config_model)`. `BuiltinService` union in `services.py` is
  built from the registered config models (static list for v1; plugin/`model_rebuild` path is a
  documented v2 extension, not built now).
- **Service config models** (`services.py`): each variant `ServiceBase` subclass with
  `model_config = ConfigDict(extra="forbid")`, `type: Literal[...]`, real default `port`, and its
  own fields (e.g. `HttpConfig.paths: dict[str, HttpPath]`, `BannerConfig.banner`/`rules`).
- **Facade base** (`facades/base.py`):
  `Facade.from_config(cfg_model, ctx) -> Facade` (classmethod; resolves `body_file` relative to
  config dir, no socket yet); `async handle(conn, reader, writer)` (per-connection logic, must not
  raise on client misbehavior); base provides `start()` / `serve_forever()` / `stop()` and the
  `_wrapped_handle` wrapper that isolates exceptions, extracts peer, mints `conn.id`, and emits
  connection open/close events. `FacadeContext(host_id, host_ip, emitter)` injected, immutable.
- **Telemetry** (`telemetry/event.py`): ECS field names — `@timestamp`, `event.{kind,category,
  type,action,outcome,dataset}`, `source.ip/port`, `destination.ip/port`, `network.{transport,
  protocol}`, `host.{name,id}`, `service.{type,id}`, `url.*`/`http.*`/`user_agent.original` for
  HTTP, plus a `rangefinder.*` namespace (`conn_id`, `matched_route`, `vuln_id`, `rule_id`,
  `banner`, `recv_preview`). Matched-vuln events set `event.kind="alert"` + `rangefinder.vuln_id`
  so SIEM rules fire trivially. `ConnScope` carries the factory helpers so facades never hand-build
  dicts. `StdoutSink` writes `model_dump_json(exclude_none=True) + "\n"` and flushes per event.
- **Supervisor** (`runtime/supervisor.py`): `loop.add_signal_handler(SIGTERM/SIGINT, stop.set)`;
  bind all facades (roll back all on any failure), `serve_forever` tasks, wait on stop, then
  `server.close()` + cancel tasks, bounded by `wait_for` under Docker's grace period. Returns 0 on
  clean stop. Detect duplicate ports at build time with a clear error, not a raw OSError mid-boot.

## Orchestration decisions (settled)

- **compose file = `json.dumps(compose, indent=2)`** written to `docker-compose.yml`. JSON is valid
  YAML 1.2 and compose reads it fine — **no YAML dependency**, and it sidesteps every YAML
  implicit-typing quote pitfall. Omit the deprecated top-level `version:` key.
- **Networking:** one user-defined `bridge` network with explicit `ipam.config.subnet` (required for
  static IPs — the default bridge rejects `ipv4_address`); each host pinned to its config `ip`.
  Validator rejects IPs outside the subnet, the network address, and gateway collisions; hosts
  should start at `.10`.
- **Privileged ports (22/53/80/389/445):** container runs **non-root** (`USER 10001`) with per-
  container `sysctls: ["net.ipv4.ip_unprivileged_port_start=0"]` — network-namespaced, so no
  `--privileged`, no host impact. Preferred over root or ambient-capability fiddling.
- **Attacker attachment (default):** a disposable `attacker` service on the same network behind a
  compose `profiles: ["attacker"]` (opt-in, doesn't auto-start), with `cap_add: [NET_RAW,
  NET_ADMIN]` so `nmap -sS`/ping sweeps don't silently degrade. Run via
  `docker compose --profile attacker run --rm attacker`. Document loopback port-exposure
  (`gen --expose loopback`) as the alternative, with its collision/fidelity caveats.
- **Self-contained output:** `gen` copies the validated config to `outdir/config.json` and bind-
  mounts `./config.json:/range/config.json:ro` (relative to the compose file's dir) so the stack is
  portable. `gen` prints the exact `docker build` + `docker compose up -d` follow-ups.
- **Dockerfile:** `python:3.12-slim`, `PYTHONUNBUFFERED=1`, `pip install .`, non-root user,
  `ENTRYPOINT ["rangefinder"]` so per-host `command` is just `["run","--host",<id>,"--config",
  "/range/config.json"]`.

## CLI

```
rangefinder validate <config>          # load+validate; print host/service/identity summary; nonzero on error
rangefinder schema [-o file]           # export JSON Schema from the pydantic models
rangefinder gen <config> -o <outdir>   # emit docker-compose.yml + config.json; print next steps
rangefinder run --host <id> --config <p>  # in-container entrypoint: serve that host's facades
rangefinder up|down [-o <outdir>]      # thin subprocess wrappers over `docker compose` (never shell=True)
```

## Example range (`examples/corp.json`)

Multi-host `corp` range on `10.13.37.0/24`: `web01` (fully interactive `http` intranet with
`/robots.txt`, `/admin` 401, a planted-vuln route; plus `ssh` banner), `dc01` (banner decoys on
389/445/53 in v1 + carries `identities` metadata: Domain Admins, a `svc-backup` account with a
password planted in its `description` — the classic LDAP-description-leak objective), and `ws01`
(smb banner). Includes an `objectives` entry describing the intended find. Doubles as the fixture
for tests and the walkthrough in the README.

## Correctness pitfalls to honor (from design review)

- Per-connection state must never live on the shared facade instance (concurrency bug).
- HTTP: always drain request bodies (`Content-Length`) or keep-alive desyncs; send correct
  `Content-Length`/`Date`; support HEAD; read-timeout idle connections.
- Banner: emit immediately with the exact terminator; stay silent on non-matching probes rather than
  reply garbage (avoids nmap "tcpwrapped"/soft-match failures); TCP only (no `-sU`).
- Compose: static IPs need explicit `ipam.subnet`; pick uncommon RFC1918 space to avoid host-route
  collisions; host `id` must match `^[a-z0-9][a-z0-9-]{0,62}$` (it's the compose service + DNS name).
- Validate fully before opening any socket; bad config exits 2, never half-starts.

## Honest fidelity limits (to document in README)

Enumeration/version-detection grade only — no real crypto handshakes (SSH KEX, TLS, SMB dialect
negotiation, LDAP BIND, Kerberos/NTLM), so BloodHound/impacket flows fail past the banner **by
design**. TCP only. Planted vulns are canned request/response decoys that answer scanners and
populate telemetry; they are not exploitable.

## Verification

1. `pip install -e .` then `rangefinder validate examples/corp.json` → prints summary, exit 0;
   a deliberately broken config (ip outside subnet, dup port, unknown type) → clear error, exit 2.
2. `rangefinder schema` → valid JSON Schema with a `oneOf`/discriminator over service types.
3. Unit tests (`pytest`): drive `HttpFacade`/`BannerFacade` handlers over in-memory
   `asyncio` stream pairs; assert response bytes (status line, headers, HEAD-no-body, 404 default,
   405 on bad method, banner + terminator) and assert the emitted telemetry event shape/fields.
4. `rangefinder gen examples/corp.json -o build/` → inspect `build/docker-compose.yml`
   (static IPs in subnet, sysctl present, attacker profile, no `version:` key).
5. End-to-end: `docker build -t rangefinder:latest .` → `docker compose -f build/docker-compose.yml
   up -d` → `docker compose --profile attacker run --rm attacker`, then from the attacker container
   `nmap -sV 10.13.37.0/24`, `curl -i http://10.13.37.20/`, `dirb http://10.13.37.20/`; confirm
   realistic responses and that `docker compose logs` shows one JSON telemetry line per interaction
   (connection open/close, http_request with UA, banner_sent, vuln_matched alert).
