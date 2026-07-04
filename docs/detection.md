# From attack to validated detections

The end of the pipeline: turn what an attack did into deployable SIEM rules — **validated
against ground truth**, not just plausible. This is a real run; the rules below were written by
a blue-team agent and graded by `rangefinder detect`.

## Why the range makes this work

A range emits **labelled** ECS telemetry: run an attack and you get the malicious events; use
it normally and you get a benign baseline. That turns detection rules into something you can
*measure*. `rangefinder detect` runs a [Sigma](https://sigmahq.io) rule back over both logs and
reports:

- **TP** — does it fire on the attack?
- **FP** — does it stay quiet on benign traffic?
- **overfit** — does it cheat by keying on the attacker's specific IP / port / timestamp instead
  of the technique?

A rule is `VALID` only if it fires, is quiet, and generalises.

## The loop: a blue-team agent writes the rules

We captured labelled telemetry from a range run — a **benign** baseline (a legitimate anonymous
read of the `PUBLIC` share, plus normal web/DNS) and an **attack** window (null-session loot of
the `HR`/`IT`/`FINANCE` shares, an anonymous LDAP mass-enumeration, and an AS-REP roast). A
blue-team agent was given both logs and the `detect` harness as its own validation oracle, and
asked to write Sigma rules that separate them.

It found three techniques and produced a `VALID` rule for each:

| Technique | ATT&CK | Result |
|-----------|--------|--------|
| Anonymous SMB access to a non-public share | T1135 | TP 4/30, FP 0/50 — VALID |
| Anonymous LDAP bind (directory recon) | T1087.002 | TP 1/30, FP 0/50 — VALID |
| Kerberos AS-REP roasting | T1558.004 | TP 1/30, FP 0/50 — VALID |

(The three rules are in [`examples/detections/`](../examples/detections).)

## The interesting part: the harness caught a bad rule

The agent's *first* SMB rule keyed on the obvious signal — `smb_auth` + `auth.method: anonymous`:

```
$ rangefinder detect --attack attack.jsonl --benign benign.jsonl --rule smb-anon-naive.yml
  [FAIL] Anonymous SMB logon (naive)
         TP 4/30   FP 1/50   -> NOISY (1 false positive(s) on benign traffic)
```

**NOISY** — because the benign baseline contains a legitimate anonymous session to the `PUBLIC`
share, so "any null session" collides with normal traffic. The agent realised the malicious /
benign distinction lives one event later, on the tree-connect target (`rangefinder.smb.share`):
benign anonymous access only ever touches `PUBLIC`, while the attacker mounts `HR`/`IT`/`FINANCE`.
It re-anchored the rule on the tree-connect with a `not public_share` allow-list:

```yaml
detection:
  selection:
    event.action: smb_tree_connect
  public_share:
    rangefinder.smb.share: [PUBLIC, IPC$]
  condition: selection and not public_share
```

```
$ rangefinder detect --attack attack.jsonl --benign benign.jsonl --rule smb-anon-sensitive-share.yml
  [PASS] Anonymous SMB access to a non-public share
         TP 4/30   FP 0/50   -> VALID
```

**VALID** — fires on all four malicious tree-connects, zero false positives, and generalises
(it detects "anonymous session reaching any non-public share," not the attacker's specific IP or
share names, which the harness would have flagged as overfit).

## The point

The agent brings judgement — it reads messy telemetry, reasons about what's suspicious, and
writes real rule logic with ATT&CK mapping. The **harness brings ground truth** — it catches the
noisy first draft and confirms the refinement, so what you ship is *measured*, not guessed. Same
pattern as the red-team judge, pointed at defense: the agent proposes, the deterministic harness
grades against truth.

And because the grading is objective, this doubles as an **eval for the blue agent itself** — you
can measure how good a detection-engineering agent is by its rules' precision/recall against the
range's ground truth, symmetric to evaluating the red-team agent that generated the attack.
