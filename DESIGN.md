# rangefinder — design & rationale

This document explains *why* rangefinder is built the way it is, what problem it targets, where
it deliberately stops, and how it fits a modern (increasingly agentic) security-evaluation
stack. The [README](README.md) covers *what* it is and how to run it; this is the *why*.

## The problem

Automated purple teaming, detection engineering, and autonomous red-team agents all need the
same scarce thing: **a target to run against that is realistic enough to be meaningful, cheap
enough to run at scale, and instrumented well enough to know what happened.**

Today you pick two of three:

- **Real VMs / a real AD domain** — realistic and observable, but slow, expensive, and painful
  to reset between runs. You can't spin up a thousand permutations.
- **Shallow mocks / honeypot banners** — cheap and disposable, but they don't fool real tooling,
  so an attack either no-ops or behaves nothing like it would against production. The eval is
  invalid.

rangefinder aims at the missing middle: **faithful protocol facades** — lightweight servers that
answer real recon/enumeration/attack tooling accurately, emit SIEM-ready telemetry for every
interaction, and cost a container each.

## The thesis

> A range is a **ground-truth detection-eval target**: author or capture a network as one JSON
> file, deploy it as one container per host, point real (or autonomous) attack tooling at it, and
> collect a complete, labelled ECS telemetry transcript of everything that touched it.

The facades are a *means*. The product is **cheap + realistic + labelled targets at scale**. Three
properties fall out of that, and they're the whole point:

1. **Realistic enough that attacks behave as they would against real infra** — verified, not
   asserted (see *Fidelity is verified* below).
2. **Ground truth by construction** — every interaction emits an ECS event; planted objectives and
   kill-chain sequences declare the intended attack path, so detection coverage is *measurable*.
3. **Disposable** — one JSON file → `docker compose up` → thousands of permutations, torn down on
   demand.

## Architecture: two planes joined by a versioned contract

rangefinder is really two subsystems that meet at a schema:

```
  BUILDER / control plane                 FACADE / data plane
  (author-time, operator machine)         (deploy-time, inside each container)
  ────────────────────────────            ─────────────────────────────────
  capture/   record-replay real infra     facades/   http ssh ldap smb dns
  importers/ nmap discovery                          kerberos rdp banner
  orchestrate/ docker-compose gen          runtime/   per-host supervisor
  verify/    differential-equivalence      telemetry/ ECS JSON emitter
  scoring/   objectives + kill-chains      ntlm, tls  protocol helpers
        │                                        ▲
        │        config.json (pydantic model)    │
        └──────── + SCHEMA_VERSION stamp ─────────┘
                  the versioned interface
```

- The **builder** reaches real networks (capture/scan), produces artifacts (`config.json`,
  `docker-compose.yml`), and never runs in production.
- The **facade runtime** consumes a config, serves protocols, emits telemetry, and touches nothing
  else. It is the deliberately-exposed surface, so it should stay minimal.
- The **config schema is the contract.** The builder *stamps* `SCHEMA_VERSION`; the runtime loader
  *refuses* a config newer than it understands. That versioned boundary is what lets the two planes
  evolve independently — and, in a product, lets a platform integrate the builder as an SDK while
  shipping facade containers as eval targets.

## Fidelity is verified, not claimed

The failure mode of every "realistic mock" is that its realism is an assertion. rangefinder treats
fidelity as a **measurable, black-box property**: `rangefinder verify <proto> <target>` captures a
live service, stands up the generated facade in-process, probes **both** with the same client, and
diffs protocol-aware equivalence classes — producing a `faithful/total` score, a divergence list,
and an explicit fidelity boundary.

Crucially, it's checked against **independent third-party oracles**, not the tool's own output:

| Facade | Verified against |
|--------|------------------|
| http   | nginx |
| ldap   | OpenLDAP |
| smb    | Samba |
| dns    | CoreDNS |

This harness has already earned its keep — it caught a real capture bug (AXFR returning relative
SRV/MX targets) and forced an equivalence-class fix (SMB case-insensitivity), rather than shipping
a plausible-but-wrong range. For a detection-eval product, this *is* the credibility argument:
"we prove the facade is behavior-equivalent to real X from the attacker's and the detector's side."

## Capture-from-real: the range carries the weakness

A design principle worth stating explicitly: **rangefinder records weaknesses into faithful
facades rather than cataloguing them in a side-report.** `capture http|ldap|smb|dns <host>`
record-replays a live service — an exposed `.git`, a password in an LDAP `description`, a readable
share — so the *replica carries the same weakness*, verbatim, because it was captured, not
detected. `--scrub` redacts secrets/PII while preserving structure.

That's the wedge for a purple-teaming context: you can mint a range that mirrors a *specific*
customer's real environment, so the eval is relevant to *that* estate — not a generic lab.

## Ground truth: objectives, kill-chains, ECS

Every facade interaction emits an ECS-aligned JSON event; matched planted vulns and captured
credential attempts raise `event.kind: "alert"`. `objectives` declare intended findings and
ordered **kill-chain sequences** (same-source, windowed), and the offline `score` engine replays a
log against them to produce a per-attacker narrative. So a run yields both *what the attacker did*
and *whether the intended path completed* — the labelled ground truth an automated purple-team or
detection eval needs.

## Scope, and the deliberate boundary

rangefinder is **enumeration / version-detection grade on the network + identity plane**. It does
this plane well: recon, HTTP, real SSH key exchange, LDAP(S) directory enumeration, SMB2/3 share
enumeration + pass-the-hash, a Kerberos KDC that issues real crackable AS-REP/Kerberoast tickets,
DNS, and an RDP/NLA endpoint that leaks host/domain/OS over CredSSP.

It **does not** emulate the **endpoint / EDR plane** — real process execution, implants, C2, host
telemetry. The SSH/RDP shells are decoys; no code runs. This is a deliberate scope choice: it's the
plane where facades give the best fidelity-per-dollar, and where a large fraction of AD attack
*detection* actually lives (Kerberos/LDAP/SMB logs, network sensors).

The endpoint plane is a **clean seam, not a hole**:

- **ECS is the common pipeline.** Facade (network/identity) events and a real endpoint agent's (EDR)
  events land in the *same* detection pipeline because rangefinder emits ECS by construction.
- A range can mix **`facade` hosts** (cheap, most of the estate) with **real-endpoint hosts** (a few
  containers/VMs running an EDR agent for the host plane). The config model already discriminates
  host types; this is an extension, not a rewrite.

So the honest whole-problem picture: *facades cover the wire, agents cover the host, ECS unifies the
telemetry, rangefinder orchestrates the mix.*

## Where this fits: AI security

rangefinder's three core properties — realistic, disposable, ground-truth-instrumented — make it a
natural **substrate for agentic security evaluation**:

- **A safe target for autonomous offensive agents.** Network-isolated, one container per host, no
  real software to break out of — so you can point an autonomous red-team agent at it with no
  real-world blast radius. Because every interaction is a labelled ECS event, you get a complete
  transcript of what the agent touched: coverage, path, noise, and which detections it tripped.
  That transcript is exactly what evaluating an autonomous attacker (or a detection for
  agent-driven attacks) requires.

- **Agent-as-realism-judge.** rangefinder's own realism was regression-tested by dispatching a
  blind, network-isolated AI agent as an attacker and measuring its *conviction* that the range is
  real (not refusal — conviction), then treating the shifting tell-list as a realism-regression
  signal after each facade change. This is an AI-evaluation technique applied to the tool itself,
  and it drove concrete fixes (per-host SMB ServerGUID, SMB 3.1.1 negotiation, RDP/NLA, RootDSE
  completeness, certificate validity windows).

The through-line: building **instrumented environments where offensive AI can be run safely and
measured against ground truth** is a discipline in its own right — and it's what a modern automated
purple-teaming stack (agents on both the red and blue side) is increasingly made of.

## Honest limitations

Stated plainly, because a fidelity tool that hides its boundary is worthless:

- **Enumeration / version-detection grade.** Facades answer recon and the specific attack paths
  below; they are not general-purpose servers.
- **Kerberos** issues real crackable AS-REP-roast and Kerberoast (TGS) tickets over RC4 (the
  roasting path attackers use) but does not complete real single sign-on; `GetUserSPNs.py`
  end-to-end is blocked by LDAP sign/seal.
- **SMB** negotiates up to 3.1.1 with proper preauth/encryption/signing contexts, but the impacket
  backend signs HMAC-SHA256 (2.x), so a *signed/credentialed* 3.1.1 session isn't supported —
  recon and null-session enumeration are.
- **SSH** does a real key exchange and captures every credential attempt, but the shell is a decoy
  (no command execution).
- **RDP** answers the security negotiation and leaks host/domain/OS over CredSSP, but stops before
  the graphics/MCS layer.
- **No endpoint/EDR plane** (see *Scope* above). **Planted vulns are canned decoys** that answer
  scanners and populate telemetry; they are not exploitable.

## Status

Built and tested end-to-end (112 tests): 8 facades (http, banner, ssh, ldap, smb, dns, kerberos,
rdp); record-replay capture (http, ldap, smb, dns) + nmap import; the differential-equivalence
`verify` harness against nginx/OpenLDAP/Samba/CoreDNS; objective + kill-chain scoring; ECS
telemetry; docker-compose orchestration with per-host static IPs. Two example ranges ship
(`examples/corp.json`, `examples/acme.json`).
