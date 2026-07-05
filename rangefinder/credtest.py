"""Live credential validation — the mechanism that makes a coherence edge *measured*.

`coherence` surfaces a suspected credential path statically (a reused secret, a secret sitting in a
leaked file) but its own docstring is clear that it cannot certify the edge is faithful to the real
estate. This module closes that gap: it tries a credential against a live service and reports
whether it actually authenticates — turning "suspected" into measured / refuted.

Every validator fails **closed**: unreachable, a protocol/backend error, or a timeout returns
``None`` (untested), never a spurious ``True``. So `verify estate` can only ever promote an edge to
"real" on a genuine successful authentication, never on a probe that merely didn't get an answer.

Authorization: this attempts logins with operator-supplied credentials against operator-supplied
targets — the same authority `capture` already uses to bind/log in. It is credential-access testing
on systems you are authorized to test, not a spray tool.
"""

from __future__ import annotations


def validate_credential(kind: str, host: str, port: int, username: str, secret: str, *,
                        domain: str = "", path: str = "/", tls: bool = False,
                        timeout: float = 5.0) -> bool | None:
    """Try (username, secret) against a live ``kind`` service at host:port.

    Returns True if it authenticates, False if the service rejects it, None if the probe was
    inconclusive (unreachable / unsupported kind / backend error) — fail-closed.
    """
    if kind == "ldap":
        from rangefinder.capture.ldap import probe_credential
        return probe_credential(host, port, username, secret, tls=tls, timeout=timeout)
    if kind == "smb":
        from rangefinder.capture.smb import probe_credential
        return probe_credential(host, port, username, secret, domain=domain, timeout=timeout)
    if kind == "ssh":
        from rangefinder.capture.ssh import probe_credential
        return probe_credential(host, port, username, secret, timeout=timeout)
    if kind == "http":
        return _validate_http(host, port, username, secret, path=path, tls=tls, timeout=timeout)
    return None  # unknown kind -> untested, never a false positive


def _validate_http(host, port, username, secret, *, path="/", tls=False, timeout=5.0) -> bool | None:
    """HTTP Basic auth, baseline-anchored so a *public* route can't read as authenticated.

    We first request the route with no credentials: only if it actually challenges (401/403) do we
    then send the credential. True only when the route challenged *and* accepted; a route that
    serves 2xx without auth is inconclusive (None), never True — the fail-open that would fabricate
    an exploitable finding. Redirects are not followed (a 302 to a public 200 page is not an auth).
    """
    import base64
    import ssl
    import urllib.error
    import urllib.request

    scheme = "https" if tls else "http"
    url = f"{scheme}://{host}:{port}{path}"

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None

    handlers = [_NoRedirect]
    if tls:
        handlers.append(urllib.request.HTTPSHandler(context=ssl._create_unverified_context()))
    opener = urllib.request.build_opener(*handlers)

    def _status(auth: bool):
        req = urllib.request.Request(url)
        if auth:
            token = base64.b64encode(f"{username}:{secret}".encode()).decode()
            req.add_header("Authorization", "Basic " + token)
        try:
            with opener.open(req, timeout=timeout) as resp:
                return resp.status
        except urllib.error.HTTPError as exc:
            return exc.code
        except Exception:
            return None

    unauth = _status(False)
    if unauth not in (401, 403):
        return None                    # unreachable, or the route isn't credential-protected here
    authed = _status(True)
    if authed is None:
        return None
    if authed in (401, 403):
        return False                   # credential rejected
    return authed < 400 or None        # challenged then accepted -> authenticated; else inconclusive


__all__ = ["validate_credential"]
