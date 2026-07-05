# rangefinder — working context

A declarative generator for lightweight protocol **facades** that answer real recon/attack
tooling accurately and emit ECS telemetry, deployed one container per host. See `README.md`
(usage) and `DESIGN.md` (rationale).

## Product thesis — keep this central

rangefinder is **one stage of a pipeline, not an end in itself**:

> **capture → faithful twin → test with autonomous red-team agents → harvest findings → emit detections/solutions**

1. **Capture** a real estate into a *faithful twin* (record-replay — the range *carries* the
   weakness because it was captured, it is not planted).
2. **Test** the twin by turning autonomous red-team agents loose on it — safely, disposably,
   off production.
3. **Identify issues** — because the twin is faithful, what an agent finds there transfers to
   the real estate.
4. **Provide rules/solutions** — convert findings + telemetry into deployable detections and
   remediations. This is the ultimate deliverable.

### Role of each component (core vs fixture)

- **Capture** (`capture/`) — the foundation. Deepening its faithfulness (credentialed capture,
  binary LDAP attrs, more protocols) is the core investment.
- **Facade realism + the agent-as-judge** — QA for the twin. The judge answers *"is the twin
  faithful enough that agent findings transfer to the real estate?"* — it is not vanity.
- **ECS telemetry** (`telemetry/`) — the observation layer that feeds rule generation.
- **Rules/solutions generation** — the actual product deliverable, and the least-built piece.
- **Authored example ranges** (`examples/acme.json`, `examples/calderwood.json`, with planted
  creds/objectives) — dev fixtures and demos to build the pipeline before real captures exist.
  Not the flagship; the planting is a fixture artifact, not the value.

### Two boundaries to hold eyes-open

1. **The twin reproduces the attack *surface*, not attack *execution*.** Facades expose what is
   enumerable / leaked / roastable and the telemetry each technique *attempt* generates — but
   they do not run code (shells are decoys). So the pipeline surfaces exposure / identity /
   misconfig issues and generates detections for recon / credential-access / discovery tactics —
   not full exploit chains or endpoint lateral-movement-via-execution. This is the **network +
   identity plane**, not endpoint/EDR.
2. **North-star fidelity principle:** the goal is not "everything works" but **"everything that
   does not work fails the way real security fails, not like a broken emulator."** A hardened
   server cleanly rejecting an attempt is faithful; an emulator throwing an implementation error
   (e.g. `Bad SMB2 signature`) is a tell. Judge every fidelity gap against this.

### The posture-provenance contract — how a facade earns a security default

Security posture (signing, anonymous access, SMB1, dialect ceiling, auth gates, AXFR…) must be
*measured and carried*, never guessed. A guessed-open default fabricates findings — a false
CRITICAL an agent "discovers" that does not exist on the real estate — which is the one failure
mode that breaks the transfer promise. So every posture field runs the same loop, protocol-agnostic
(the shared machinery lives in `capture/posture.py`, honored per-facade, locked in `verify`):

> **measure the posture → reproduce it in the facade → fail *closed* on the unmeasured → surface
> the provenance → lock it in verify.**

- **Fail closed:** an unmeasured security field defaults to the *restrictive* value. Worst case we
  under-report (safe — the tool drives remediation); a fail-open default invents findings.
- **Surface the provenance:** capture emits a `*.capture-report.md` sidecar tiering every field as
  **measured / assumed / unmeasurable** — the twin never claims silent knowledge it doesn't have.
- New protocols inherit this contract; a new posture probe is not done until the facade honors it
  *and* `verify` diffs it.

## Working notes

- Tests: `pytest` (135 passing). CI runs the suite on Python 3.10 / 3.11 / 3.12.
- Changes flow through a branch + PR with green CI before merging to `main`.
- Layers (see `DESIGN.md` for the two-plane split): `config/` is the schema contract; `facades/`
  + `runtime/` + `telemetry/` are the data plane (run inside each container); `capture/` +
  `importers/` + `orchestrate/` + `verify` + `scoring` are the builder/control plane.
