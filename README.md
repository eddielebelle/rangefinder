# rangefinder

Declarative cyber-range generator for **authorized** security testing. Author a fake
network as one JSON file; rangefinder renders it into lightweight protocol **facades**
that answer real recon/enumeration tooling (nmap, curl, dirb/gobuster, ldapsearch) and
emit **SIEM-ready telemetry** for every interaction. No real AD domain, no real web app —
just facades that respond convincingly enough to test against, and log everything.

Built for: detection/SOC evaluations, recon/enumeration tooling, and human red-teamers.

> **Scope of realism (read this).** rangefinder is *enumeration / version-detection*
> grade. It does **not** validate credentials or complete real domain auth (Kerberos/NTLM
> single sign-on), so tools that pivot on authenticated domain access (BloodHound
> collection, secretsdump) will not complete **by design**. The **LDAP** facade speaks real
> LDAPv3 for enumeration (anonymous bind + search; LDAPS via `tls: true`) but has no
> SASL/StartTLS or writes. HTTP and LDAP serve over TLS with a self-signed cert (nmap
> fingerprints it); other TLS ports (RDP, IMAPS, …) remain decoys for now. The
> **SMB** facade (impacket-backed) serves the configured shares as real files and captures
> NTLM auth attempts without validating them (`readonly` is advisory). The **SSH** facade
> does a real key exchange and captures credential attempts, but its shell is a decoy (no
> command execution). Planted "vulns" are canned decoys that answer scanners and populate
> telemetry; they are not exploitable. TCP only (no UDP / `nmap -sU`).

## Install

```bash
pip install -e .
```

## Concepts

A range config has four parts:

- **network** — the subnet the range lives on.
- **hosts** — each becomes one container with a static IP; each host has **services**.
- **services** — a typed, discriminated list. Each `type` maps to a facade. Implemented:
  `http`, `banner`, `ssh`, `ldap`, `smb`, `dns`.
- **identities** / **objectives** — AD users/groups (rendered by the LDAP facade) and
  scenario objectives (descriptive metadata).

### Service types

| type | facade | notes |
|------|--------|-------|
| `http` | HTTP/1.1(S) server | server header, canned route table, planted-vuln routes, HEAD, keep-alive. `tls: true` for HTTPS. Routes gate on Basic auth (`auth_realm`/`auth_users`) and every credential attempt is captured as telemetry |
| `banner` | generic TCP banner | text banner + regex rules (FTP/SMTP/POP3), or `binary: true` with `banner_hex` / hex `match_hex`+`respond_hex` rules for binary protocols (MySQL greeting, RDP X.224) so nmap `-sV` versions them |
| `ssh` | real SSH server | asyncssh-backed: genuine key exchange, so clients reach auth. Captures every password/public-key attempt as telemetry and rejects it; `accept_creds` lets a planted login succeed into a decoy shell that logs typed commands. `server_version` sets the OpenSSH banner nmap reads |
| `ldap` | LDAPv3(S) directory | real BER wire protocol; renders `identities` (users/groups) and the range's Windows hosts (computer objects + Domain Controllers OU) into a DIT; anonymous bind + RootDSE + subtree search + and/or/not/equality/present/substrings filters. `tls: true` serves LDAPS. Enumeration-grade (no cred validation / SASL / writes) |
| `smb` | SMB2 file server | impacket-backed; renders `shares` as real backing files, so `smbclient -L` / `enum4linux` list shares and read planted files; captures NTLM auth attempts. `readonly` is advisory |
| `dns` | DNS server (UDP+TCP) | authoritative A/AAAA/CNAME/NS/PTR/MX/TXT/SRV from `records`, autofills A records for range hosts, serves the `_ldap._tcp` / `_kerberos._tcp` SRV records tools use to locate a DC. No recursion / AXFR / DNSSEC |

## CLI

```bash
rangefinder validate examples/corp.json     # validate + summarize (exit 2 on error)
rangefinder schema -o range.schema.json      # export JSON Schema for editor autocomplete
rangefinder gen examples/corp.json -o build/ # emit build/docker-compose.yml + config.json
rangefinder score examples/acme.json log.jsonl   # score objectives against a telemetry log
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
ldapsearch -x -H ldap://10.13.37.10 -b "DC=corp,DC=local" -s sub "(objectClass=user)"
smbclient -N -L //10.13.37.10          # list shares; then //10.13.37.10/BACKUPS to browse
dig @10.13.37.10 _ldap._tcp.dc._msdcs.corp.local SRV   # locate the "DC"
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

## Importing real infrastructure

To build a range that mirrors a real environment (for detection testing against *your*
network), import an nmap scan:

```bash
nmap -sV -sC -oX scan.xml 10.0.0.0/24        # -sC / --script drives the posture layer
rangefinder import nmap scan.xml --name prod-replica -o prod.json
rangefinder validate prod.json               # then gen + up as usual
```

The importer produces two layers:

- **Topology + versions** — each up host → a range host; each open port → a facade
  (http/https → `http`, ssh → `ssh`, else a labelled `banner` decoy with the detected
  version). Subnet is derived from the host IPs (`--subnet` to override).
- **Security posture** — nmap NSE `<script>` output is translated into config that
  *reproduces the misconfigurations found*: exposed web paths (`http-git`, `http-enum`)
  become planted routes tagged as vulns; null-session SMB shares (`smb-enum-shares`)
  become a real `smb` facade; and each finding (anonymous LDAP/FTP, weak TLS,
  unauthenticated Redis/Mongo, …) becomes an auto-generated **objective** — so the
  imported range ships with a scorecard of the org's real weaknesses.

**Posture, not data.** The importer captures the *property* of a weakness (a path is
exposed, a share is null-session readable, LDAP answers anonymously) and structural
names/paths — never bulk data or secret values. Share contents are placeholdered. This
keeps the replica safe to share while still faithful to what a defender needs to detect.
Run nmap with NSE scripts to populate the posture layer; a bare `-sV` yields topology only.

## Scoring

Scoring is a **separate reader** of the telemetry — the facades keep emitting the full
logs; the scorer just evaluates them, so you keep both. Each `objective` can carry a
`detect` rule: a list of **signals**, where the objective is MET when any signal's
conditions all hold on a single event. Conditions match a dotted event field with
`equals` / `contains` / `regex`:

```json
{ "id": "obj-svc-sql-cred", "title": "Recover the svc-sql credential",
  "description": "Exposed via a web config and an SMB share.",
  "detect": [
    { "label": "read the exposed web db.config",
      "all": [ { "field": "event.action", "equals": "http_request" },
               { "field": "url.path", "contains": "/backup/db.config" } ] },
    { "label": "read the IT credential vault over SMB",
      "all": [ { "field": "event.action", "equals": "smb_file_access" },
               { "field": "rangefinder.smb.path", "contains": "vault-export" } ] }
  ] }
```

Run it against a captured log (a file, or piped from `docker compose logs`):

```bash
docker compose -f build/docker-compose.yml logs | rangefinder score examples/acme.json -
# [MET  ] obj-svc-sql-cred — first via "read the exposed web db.config" by 10.20.0.2 (http_request)
# [UNMET] obj-ssh-foothold
# Summary: 1/4 objectives met
```

The report gives, per objective, the first matching event (when, source IP, action), the
signal that fired, and how many events matched from which sources. Objectives with no
`detect` are reported `UNSCORED`. Use `--json` for machine output. (v1 matches within a
single event; cross-event sequences are a future enhancement.)

## Architecture

```
config/       pydantic models; JSON is the single source of truth (discriminated union on `type`)
facades/      registry + Facade base + http/banner/ssh/ldap/smb/dns facades
telemetry/    ECS-aligned event builders + stdout/file/list sinks
runtime/      per-host supervisor: serve all facades in one loop, graceful SIGTERM shutdown
orchestrate/  config -> docker-compose (JSON-as-YAML, static IPs, attacker profile)
scoring.py    offline objective scorer over the telemetry log
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
