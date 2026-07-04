# rangefinder

[![CI](https://github.com/eddielebelle/rangefinder/actions/workflows/ci.yml/badge.svg)](https://github.com/eddielebelle/rangefinder/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)

Declarative cyber-range generator for **authorized** security testing. Author a fake
network as one JSON file; rangefinder renders it into lightweight protocol **facades**
that answer real recon/enumeration tooling (nmap, curl, dirb/gobuster, ldapsearch) and
emit **SIEM-ready telemetry** for every interaction. No real AD domain, no real web app —
just facades that respond convincingly enough to test against, and log everything.

Built for: detection/SOC evaluations, recon/enumeration tooling, and human red-teamers.

For the *why* — the problem it targets, the two-plane architecture, how fidelity is verified, the
endpoint/EDR seam, and where it fits an agentic security stack — see **[DESIGN.md](DESIGN.md)**.
For a real end-to-end run (deploy → attack → score → verify, with captured output), see the
**[walkthrough](docs/walkthrough.md)**; for turning an attack into ground-truth-validated SIEM
rules with a blue-team agent, see **[detection](docs/detection.md)**.

> **Scope of realism (read this).** rangefinder is *enumeration / version-detection*
> grade. The `kerberos` facade issues real, crackable AS-REP-roast and Kerberoast (TGS)
> tickets over RC4 (the roasting path attackers use), but it does **not** validate
> credentials or complete real single sign-on. `GetUserSPNs.py` end-to-end additionally
> needs the NTLM LDAP bind (next phase); the AES AS-exchange has a salt caveat. Tools that
> pivot on authenticated domain access (BloodHound collection, secretsdump) will not
> complete **by design**. The **LDAP** facade speaks real
> LDAPv3 for enumeration (anonymous bind + search; LDAPS via `tls: true`) but has no
> SASL/StartTLS or writes. HTTP and LDAP serve over TLS with a self-signed cert (nmap
> fingerprints it); other TLS ports (IMAPS, …) remain decoys for now. The **RDP** facade
answers the X.224 security negotiation, upgrades to TLS with the host cert, and — when NLA
is required — challenges over CredSSP so `rdp-ntlm-info` leaks the host's name/domain/OS
build; it stops before the RDP graphics/MCS layer (an unauthenticated session is rejected,
as on a hardened box). The
> **SMB** facade (impacket-backed) serves the configured shares as real files and validates
> NTLM against the `identities` NT hashes (pass-the-hash), while still allowing null-session
> enumeration (`readonly` is advisory). The **SSH** facade
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
  `http`, `banner`, `ssh`, `ldap`, `smb`, `dns`, `rdp`.
- **identities** / **objectives** — AD users/groups (rendered by the LDAP facade) and
  scenario objectives (descriptive metadata).

### Service types

| type | facade | notes |
|------|--------|-------|
| `http` | HTTP/1.1(S) server | server header, canned route table, planted-vuln routes, HEAD, keep-alive. `tls: true` for HTTPS. Routes gate on Basic auth (`auth_realm`/`auth_users`) or NTLM (`auth_ntlm: true`, validated against the identities NT hashes — IIS/OWA-style); every credential attempt is captured as telemetry |
| `banner` | generic TCP banner | text banner + regex rules (FTP/SMTP/POP3), or `binary: true` with `banner_hex` / hex `match_hex`+`respond_hex` rules for binary protocols (MySQL greeting, RDP X.224) so nmap `-sV` versions them |
| `ssh` | real SSH server | asyncssh-backed: genuine key exchange, so clients reach auth. Captures every password/public-key attempt as telemetry and rejects it; `accept_creds` lets a planted login succeed into a decoy shell that logs typed commands. `server_version` sets the OpenSSH banner nmap reads |
| `kerberos` | KDC (roasting) | answers AS-REQ + TGS-REQ on 88 (UDP+TCP) with AES/RC4 pre-auth (advertises the salt via PA-ETYPE-INFO2). **AS-REP roasting**: a `no_preauth` account yields a real `$krb5asrep$` (GetNPUsers). **Kerberoasting**: an account with an `spn` yields a `$krb5tgs$` over the AS→TGS flow. Crackable tickets, logged as alerts. A roasting decoy, not a full KDC |
| `ldap` | LDAPv3(S) directory | real BER wire protocol; renders `identities` (users/groups/SPNs) and the range's Windows hosts (computer objects + DC OU) into a DIT; anonymous bind + RootDSE + subtree search + and/or/not/equality/present/substrings filters. **Validates NTLM binds** (SASL GSS-SPNEGO + MS Sicily) against `identities` NT hashes. `tls: true` serves LDAPS |
| `smb` | SMB2/3 file server | impacket-backed; renders `shares` as real backing files (`smbclient -L` / `enum4linux` enumerate them). **Validates NTLM** against `identities` NT hashes — pass-the-hash succeeds with the right hash, a wrong hash is rejected (failed logon → alert) — while null-session enumeration still works. `readonly` is advisory. Negotiates up to **SMB 3.1.1** (`max_dialect`) with a per-host ServerGUID, real uptime, and 3.1.1 preauth-integrity/encryption/signing negotiate contexts; a signed/credentialed 3.1.1 session needs AES-CMAC the backend can't do, so signing is advertised-not-required at 3.1.1 |
| `dns` | DNS server (UDP+TCP) | authoritative A/AAAA/CNAME/NS/PTR/MX/TXT/SRV from `records`, autofills A records for range hosts, serves the `_ldap._tcp` / `_kerberos._tcp` SRV records tools use to locate a DC. No recursion / AXFR / DNSSEC |
| `rdp` | RDP (NLA) endpoint | answers the X.224 security negotiation, upgrades to TLS with the host cert, and (when `nla_required`) challenges over CredSSP so `rdp-enum-encryption` reports NLA-required and `rdp-ntlm-info` leaks NetBIOS/DNS name, domain and OS build (`os_version`). Captures the `mstshash` cookie + any CredSSP logon as telemetry. Stops before the RDP graphics/MCS layer |

## CLI

```bash
rangefinder validate examples/corp.json     # validate + summarize (exit 2 on error)
rangefinder schema -o range.schema.json      # export JSON Schema for editor autocomplete
rangefinder gen examples/corp.json -o build/ # emit build/docker-compose.yml + config.json
rangefinder import nmap scan.xml -o cfg.json      # discover topology from an nmap scan
rangefinder capture http https://host/ -o cfg.json  # record a live web server -> faithful facade
rangefinder capture ldap 10.0.0.10 -o cfg.json    # record a live directory -> faithful facade
rangefinder capture smb  10.0.0.20 -o cfg.json    # record live file shares -> faithful facade
rangefinder capture dns  10.0.0.10 --zone acme.corp  # record a live DNS zone -> faithful facade
rangefinder verify http http://10.0.0.30/         # measure replica fidelity vs the live target
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

> **Rebuild the image after upgrading.** Generated configs (capture/import) are stamped
> with a config-schema version; if you deploy one against a stale runtime image that
> predates a schema change, the container fails fast with a clear "rebuild the image"
> error instead of silently. Run `docker build -t rangefinder:latest .` after pulling
> changes.

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
GetNPUsers.py -dc-ip 10.20.0.10 -no-pass -usersfile users.txt acme.corp/   # AS-REP roast
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

## Recreating real infrastructure

Build a range that mirrors a real environment in two steps: **discover** the topology,
then **capture** each service's real behavior so its weaknesses carry through.

```bash
# 1. discover — nmap fingerprints what's listening -> a config skeleton
nmap -sV -oX scan.xml 10.0.0.0/24
rangefinder import nmap scan.xml --name prod-replica -o prod.json

# 2. capture — record a live service's actual responses into a faithful facade
rangefinder capture http https://10.0.0.30/ -o web.json          # crawl -> http facade
rangefinder capture ldap 10.0.0.10 -o dc.json                    # anonymous dir dump -> ldap facade
rangefinder capture smb  10.0.0.20 -o fs.json                    # null-session shares -> smb facade
rangefinder capture http https://10.0.0.30/ --scrub -o web.json  # redact secrets to share
```

The design principle: **the range carries the weakness, not a catalog that names it.**
`import` is pure discovery (host → range host; port → facade). `capture` is record-replay
— it probes the live service and records the actual `(status, headers, body)` it returned,
and the facade replays them. Any weakness in the real responses (an exposed `/.git`, a
directory listing, a verbose error, a leaked config, whatever anonymous access returns)
reproduces automatically, because it was captured — not because any code recognizes it.
Round-tripped end to end, nmap's `http-git` script flags the exposed repo on the *replica*
just as it would on the original.

**Verbatim by default, `--scrub` optional.** A capture holds real content, which is fine
for a range owned by the org it mirrors; `--scrub` runs captured content (across all three
captors) through a redactor that removes key/value secrets (`password=…`, connection
strings), private keys, cloud/provider tokens (AWS, GitHub, Slack, …), JWTs, bearer/basic
auth, URL credentials, and PII (emails, SSNs, Luhn-valid cards), and consistently
pseudonymizes emails so references stay intact. Structure stays faithful, so the weakness
still carries through. It is heuristic, not a guarantee — review before sharing (e.g. a
password written in free prose with no `password=` marker won't be caught).

`capture ldap` binds (anonymously by default), reads the RootDSE, and subtree-searches each
naming context — recording the entries the directory actually returned. If anonymous bind
exposes the directory on the real DC, the replica exposes the same directory (users, groups,
computer objects, a service account's leaked `description`); if it's locked down, the replica
returns just as little. `capture smb` does the same for file shares: it lists shares and walks
the file tree readable at the given access level (null session by default), recording the files
verbatim — so a null-session-readable share reproduces with the same tree on the replica.
`capture dns` records a zone: it takes a zone transfer (AXFR) if the server allows one — the
transfer being permitted is itself an exposure that carries through — otherwise it queries a
probe set of the names tooling asks for (the apex, common hostnames, and the AD service SRV
records). (`http`, `ldap`, `smb`, and `dns` captors ship; text is captured verbatim,
binary/oversized files are recorded by name with a placeholder.)

### Verifying fidelity

How do you know the replica is a *feasible* recreation? `verify` measures it as black-box
differential equivalence — the only honest test, since it compares what the **tooling** sees,
not implementation. It captures the live target, serves the generated facade in-process on a
loopback port, then probes **both** with the same client and diffs protocol-aware equivalence
classes:

```bash
rangefinder verify http http://10.0.0.30/           # per route: status + body + security headers
rangefinder verify ldap 10.0.0.10 --bind-dn cn=admin,... --password …   # entry DNs + attribute sets
rangefinder verify smb  10.0.0.20 --username … --password …   # share names + file tree + content
rangefinder verify dns  10.0.0.10 --zone acme.corp            # record answer sets per name/type
```

```
Fidelity: http  http://10.0.0.30/
  7/7 faithful (100.0%) from the consumer's perspective
  fidelity boundary:
    - uncaptured paths diverge: real 404 vs replica 404 for a path that was never probed
  => FAITHFUL
```

It reports a **score** (faithful / total), an explicit **divergence list**, and a **fidelity
boundary** — the map of where to stop trusting the replica. Two honesty rules are built in:
the real target is always re-fetched live (comparing the facade to its own captured bytes
would be a tautology), and fidelity is only claimed for the *perspective the capture
exercised* (e.g. an anonymous bind — never a credentialed or deeper read it never saw).
Exit code is non-zero on any divergence, so it gates in CI. Validated against genuine
third-party software (nginx, OpenLDAP, Samba, CoreDNS), not just against itself — a run
against CoreDNS caught a real capture bug (relative SRV/MX targets), which is exactly what
the harness is for.

Every run also checks the **detection perspective**: the telemetry the replica emits while
probed is captured, so the report shows how many SIEM events and alerts the tool actions
produced — and for HTTP a route the facade serves but never *logs* surfaces as a detection
"blind spot". A range that answers tools but stays silent in the SIEM fails the SOC-eval
purpose, so `verify` reports `FAITHFUL & OBSERVABLE` only when both hold.

`verify http --nmap` adds the recon-tool perspective: it runs `nmap -sV` against the real
target and the replica and compares the service/version fingerprint (skipped with a note if
nmap isn't installed).

Equivalence is defined per protocol at the level the *tooling* cares about — e.g. SMB share
and path names are compared case-insensitively because SMB itself is, so a replica that
serves `PUBLIC` for a real `public` reads as faithful (a client reaches the same share
either way) and the case normalisation is surfaced as a boundary note, not a false failure.

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
`detect` are reported `UNSCORED`. Use `--json` for machine output.

### Kill chains (cross-event)

Beyond single-event `detect`, an objective can carry a `sequence` — an ordered set of
steps that must occur **in order**, by default by the **same source**, optionally within a
time window. This scores multi-stage attacks ("authenticated *then* read the file"):

```json
{ "id": "obj-killchain", "title": "Foothold then data theft",
  "description": "The same attacker gains SSH access and then reads files over SMB.",
  "sequence": {
    "same_source": true, "within": "10m",
    "steps": [
      { "label": "SSH foothold",
        "all": [ { "field": "event.action", "equals": "ssh_auth" },
                 { "field": "event.outcome", "equals": "success" } ] },
      { "label": "read a file over SMB",
        "all": [ { "field": "event.action", "equals": "smb_file_access" } ] }
    ] } }
```

A met sequence prints the chain as a per-attacker narrative:

```
[MET] obj-killchain — Foothold then data theft
       kill chain completed at 2026-… by 10.20.0.2:
         1. SSH foothold          at 2026-…:12 (ssh_auth)
         2. read a file over SMB  at 2026-…:13 (smb_file_access)
```

(An objective may use `detect`, `sequence`, or both — met if either fires.)

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
