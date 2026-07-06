"""End-to-end detection loop: range objective -> live facade telemetry -> compiled Sigma -> validated.

This is the whole product thesis in one test, run against a *real served facade* (not hand-built
events): an objective declares what to detect, an attacker action drives the facade and it emits ECS
telemetry, the objective compiles to a Sigma rule, and that rule is validated to fire on the attack
telemetry and stay silent on benign traffic — a deployable detection proven on the twin's own logs.
"""

import asyncio
import base64

from helpers import make_ctx, serve_and_exchange

from rangefinder import detect as det
from rangefinder.config.model import Condition, Objective, Signal
from rangefinder.config.services import HttpConfig, HttpPath
from rangefinder.facades.http import HttpFacade

# The objective a range author declares — "someone authenticated to the admin panel".
_ADMIN_OBJECTIVE = Objective(
    id="obj-admin-panel",
    title="Break into the web admin panel",
    description="A weak Basic-auth credential accepted on /admin.",
    detect=[Signal(all=[
        Condition(field="event.action", equals="http_auth"),
        Condition(field="url.path", contains="/admin"),
        Condition(field="event.outcome", equals="success"),
    ])],
)


def _b64(user, pw):
    return base64.b64encode(f"{user}:{pw}".encode()).decode()


def _req(path, auth=None, method="GET"):
    head = f"{method} {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n"
    if auth:
        head += f"Authorization: Basic {_b64(*auth)}\r\n"
    return (head + "\r\n").encode()


def _drive(payload):
    """Serve a fresh admin-panel facade, send one request, return the ECS events it emitted."""
    ctx, sink = make_ctx()
    facade = HttpFacade.from_config(HttpConfig(port=80, paths={
        "/admin": HttpPath(auth_realm="ACME", auth_users={"admin": "s3cret"}, body="PANEL"),
        "/": HttpPath(body="home"),
    }), ctx)
    asyncio.run(serve_and_exchange(facade, payload))
    return list(sink.events)


def test_objective_compiles_to_a_rule_validated_on_live_facade_telemetry():
    # ATTACK: authenticate to the admin panel — the objective — producing real http_auth telemetry.
    attack = _drive(_req("/admin", auth=("admin", "s3cret")))
    # BENIGN: browse the home page, and a FAILED admin login (wrong creds) — neither is the objective.
    benign = _drive(_req("/")) + _drive(_req("/admin", auth=("root", "wrong")))

    # The facade really emitted the objective's event...
    assert any(e["event"]["action"] == "http_auth" and e["event"]["outcome"] == "success"
               for e in attack)

    # ...the objective compiles to Sigma, and the rule is graded against the twin's own telemetry.
    rule = det.compile_objective(_ADMIN_OBJECTIVE, "acme")
    result = det.validate(rule, attack, benign)
    assert result.true_positives >= 1     # fires on the real attack telemetry
    assert result.false_positives == 0    # silent on benign (home browse + failed login)
    assert result.ok                      # VALID -> a deployable, ground-truth-confirmed detection


def test_benign_only_telemetry_does_not_validate_the_rule():
    # No attack occurred -> the rule never fires -> it is a MISS, not shipped (the fail-closed gate).
    benign = _drive(_req("/")) + _drive(_req("/admin", auth=("root", "wrong")))
    rule = det.compile_objective(_ADMIN_OBJECTIVE, "acme")
    result = det.validate(rule, benign, [])
    assert result.true_positives == 0 and not result.ok
