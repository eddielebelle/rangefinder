# rangefinder

Declarative cyber-range generator for **authorized** security testing. Author a fake
network as one JSON file; rangefinder renders it into lightweight protocol **facades**
that answer real recon/enumeration tooling (nmap, curl, dirb/gobuster, ldapsearch) and
emit **SIEM-ready telemetry** for every interaction. No real AD domain, no real web app —
just facades that respond convincingly enough to test against, and log everything.

Built for: detection/SOC evaluations, recon/enumeration tooling, and human red-teamers.

> **Scope of realism (read this).** rangefinder is *enumeration / version-detection*
> grade. It does **not** perform real cryptographic handshakes — SSH KEX, TLS, SMB dialect
> negotiation, LDAP BIND, Kerberos/NTLM — so tools that need a real auth flow
> (BloodHound, impacket) will fail past the banner **by design**. Planted "vulns" are
> canned request/response decoys that answer scanners and populate telemetry; they are
> not exploitable. TCP only (no UDP / `nmap -sU`).

## Install

```bash
pip install -e .
```

## Concepts

A range config has four parts:

- **network** — the subnet the range lives on.
- **hosts** — each becomes one container with a static IP; each host has **services**.
- **services** — a typed, discriminated list. Each `type` maps to a facade. v1 ships
  `http` and `banner`; `ldap`/`smb`/`dns` are defined in the schema but their facades
  arrive in v2 (represent those ports as `banner` decoys for now).
- **identities** / **objectives** — AD users/groups and scenario objectives. Descriptive
  metadata in v1 (the LDAP facade will render `identities` in v2).

### Service types

| type | facade | notes |
|------|--------|-------|
| `http` | HTTP/1.1 server | server header, canned route table, planted-vuln routes, HEAD, keep-alive |
| `banner` | generic TCP banner | server-speaks-first banner for nmap `-sV`; optional line-regex rules. `ssh`/`ftp`/`smtp` are just banner presets |
| `ldap` `smb` `dns` | *(v2)* | config models exist; use `banner` decoys until the facades ship |

## CLI

```bash
rangefinder validate examples/corp.json     # validate + summarize (exit 2 on error)
rangefinder schema -o range.schema.json      # export JSON Schema for editor autocomplete
rangefinder gen examples/corp.json -o build/ # emit build/docker-compose.yml + config.json
rangefinder run --host web01 --config examples/corp.json   # serve one host (container entrypoint)
rangefinder up   -o build/                   # docker compose up -d  (thin wrapper)
rangefinder down -o build/                   # docker compose down
```

## Run a range

```bash
docker build -t rangefinder:latest .                            # facade runtime image
docker build -t rangefinder-attacker:latest docker/attacker     # attacker toolbox (nmap, curl, ldap-utils, dnsutils)
rangefinder gen examples/corp.json -o build/
docker compose -f build/docker-compose.yml up -d
```

Each host container serves all of its facades on their real ports (80, 22, 445, …) at the
host's static IP. Attach an attacker to the same network to test:

```bash
docker compose -f build/docker-compose.yml --profile attacker run --rm attacker
# inside the attacker container:
nmap -sV 10.13.37.0/24
curl -i http://10.13.37.20/
dirb http://10.13.37.20/
```

Alternative: expose ports to host loopback instead of using an attacker container. This
loses subnet-sweep fidelity and forces port remapping (multiple hosts can't share
`127.0.0.1:445`), so the attacker-on-network default is recommended.

## Telemetry

Every facade writes one JSON line per interaction to stdout (captured by
`docker compose logs`). Fields follow **Elastic Common Schema** names, with range-specific
detail under a `rangefinder.*` namespace. Connection open/close, HTTP requests (method,
path, user-agent, status), and banner exchanges are all recorded. Hits on a planted-vuln
route set `event.kind: "alert"` and carry `rangefinder.vuln_id`, so a SIEM detection rule
fires trivially — this is the core hook for detection/SOC evaluation.

Example event (an HTTP hit on a planted vuln):

```json
{"@timestamp":"2026-07-03T10:00:00.000Z","event":{"kind":"alert","category":["web"],
"action":"http_request","dataset":"rangefinder.http"},"source":{"ip":"10.13.37.99"},
"destination":{"ip":"10.13.37.20","port":80},"http":{"request":{"method":"GET"},
"response":{"status_code":200}},"url":{"path":"/.git/HEAD"},
"user_agent":{"original":"gobuster/3.6"},
"rangefinder":{"vuln_id":"exposed-git-dir","conn_id":"..."}}
```

## Architecture

```
config/       pydantic models; JSON is the single source of truth (discriminated union on `type`)
facades/      registry + Facade base + http/banner facades (stdlib asyncio, per-connection ConnScope)
telemetry/    ECS-aligned event builders + stdout/file/list sinks
runtime/      per-host supervisor: serve all facades in one loop, graceful SIGTERM shutdown
orchestrate/  config -> docker-compose (JSON-as-YAML, static IPs, attacker profile)
```

## Extending

Add a facade by (1) defining its config model in `config/services.py` and adding it to the
`BuiltinService` union, and (2) writing a `Facade` subclass decorated with
`@register("type")`, imported in `facades/__init__.py`. The runtime, telemetry, and
orchestration layers pick it up automatically.

## Development

```bash
pip install -e '.[dev]'
pytest
```

## Legal

For use only against systems and networks you are authorized to test. You are responsible
for how you deploy and use ranges built with this tool.
