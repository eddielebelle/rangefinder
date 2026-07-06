# Security Policy

rangefinder is a security tool: one part of it (`capture`) connects to live infrastructure, and the
ranges it builds are intentionally deceptive services. This document states plainly **what it does on
your network**, **how to handle the data it produces**, and **how to report a vulnerability** in
rangefinder itself. Every behavioural claim below is what the code actually does — the capture path is
a few hundred lines of mostly-standard-library Python under [`rangefinder/capture/`](rangefinder/capture/),
auditable in a sitting.

## Reporting a vulnerability

Please report security issues **privately** — do not open a public issue or PR that describes the flaw.

- **Preferred:** GitHub → the repository **Security** tab → **Report a vulnerability** (private
  advisory).

This is a personal project maintained on a best-effort basis; I'll acknowledge reports as quickly as I
can and credit reporters who'd like it. Responsible disclosure is appreciated.

## What rangefinder does on your network

rangefinder has two planes (see [DESIGN.md](DESIGN.md)): a **builder/control plane** that constructs a
range, and a **data plane** — the facades — that a range runs.

### `capture` is read-only, single-host, and local-only

`capture` is the only part that touches live systems. When you run `rangefinder capture <proto> <host>`:

- **It connects only to the host you name.** No network scan, no other systems reached — and the HTTP
  crawler only ever fetches paths on that host (it constructs every request from the target and does not
  follow links or redirects off-host).
- **It reads at your access level**, using the same requests a recon tool makes — anonymous by default,
  authenticated only with credentials you pass. SMB share enumeration/reads, LDAP searches, HTTP
  `GET`/`OPTIONS`/`TRACE`, and SSH/DNS posture probes.
- **It never writes to, modifies, or deletes anything on the target.** There are no write/create/delete
  code paths, and no command execution (`subprocess`/`exec`) anywhere in the capture modules.
- **It writes captured data only to the local file you choose** (plus a `.capture-report.md` provenance
  sidecar). Nothing is transmitted anywhere — no telemetry, no analytics, no phone-home. *Every* network
  connection the tool opens goes to the capture target.
- **It tells you what it's doing before it connects** — a banner naming the target, the access level, and
  the destination file. With no output file at an interactive terminal, it prints the captured twin for
  review and asks before saving it.

### Captured twins can contain secrets — treat them as sensitive

A faithful twin holds the **real content** the target returned — share files, directory attributes, web
bodies — which may include credentials, keys, or PII. By design this is captured **verbatim** unless you
pass `--scrub`. So:

- Treat a captured `*.json` twin and its `*.capture-report.md` sidecar as **sensitive data** — as
  sensitive as the estate they mirror.
- Use `--scrub` to redact secrets before sharing a twin. It is a **heuristic redactor, not a guarantee**
  (e.g. a password written in free prose with no `password=` marker won't be caught) — review before
  sharing.
- Keep twins of a real estate only on systems authorized to hold that estate's data.

### Facades are decoys, not real services

The services a range runs answer enumeration/recon tooling accurately and log every interaction, but they
**do not execute code**: SSH/shell surfaces are decoys, "planted vulns" are canned responses, and no
captured content is ever run. A range reproduces the attack *surface* (what is enumerable, leaked, or
roastable) and the telemetry each technique generates — **not** attack execution. This is the
network-and-identity plane, not endpoint code execution.

### Ranges are intentionally exposed — keep them isolated

A range deliberately presents weak-looking, credential-leaking services. Run it on its **own disposable
bridge network** (the default) and **do not expose a range to untrusted networks or the internet** — it is
built to be attacked safely in a lab, not hardened for public exposure. Telemetry is written to the
container's stdout and/or a local file; it is not sent anywhere by the tool.

## Authorized use only

Capture, deploy, and test **only** against systems and networks you are authorized to assess. You are
responsible for how you build and use ranges with this tool. See the Legal note in the [README](README.md).

## Supported versions

rangefinder is pre-1.0 and evolving; fixes land on `main`. The latest `main` is the supported version.
