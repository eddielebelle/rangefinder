import asyncio

from helpers import actions, make_ctx, serve_and_exchange

from rangefinder.config.services import HttpConfig, HttpPath
from rangefinder.facades.http import HttpFacade


def _facade(**kw):
    ctx, sink = make_ctx()
    cfg = HttpConfig(port=80, **kw)
    return HttpFacade.from_config(cfg, ctx), sink


def _req(path="/", method="GET"):
    return f"{method} {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n".encode()


def test_root_route_ok():
    facade, sink = _facade(paths={"/": HttpPath(body="hello world")})
    data = asyncio.run(serve_and_exchange(facade, _req("/")))
    assert data.startswith(b"HTTP/1.1 200 OK\r\n")
    assert b"Server: Apache/2.4.52 (Ubuntu)" in data
    assert b"Content-Length: 11" in data
    assert data.endswith(b"hello world")
    assert "http_request" in actions(sink)


def test_unknown_path_404():
    facade, _ = _facade(paths={"/": HttpPath(body="x")})
    data = asyncio.run(serve_and_exchange(facade, _req("/nope")))
    assert data.startswith(b"HTTP/1.1 404 Not Found\r\n")


def test_head_has_no_body_but_content_length():
    facade, _ = _facade(paths={"/": HttpPath(body="abcdef")})
    data = asyncio.run(serve_and_exchange(facade, _req("/", "HEAD")))
    head, _, body = data.partition(b"\r\n\r\n")
    assert b"Content-Length: 6" in head
    assert body == b""


def test_method_not_allowed_405():
    facade, _ = _facade(paths={"/": HttpPath(methods=["GET"], body="x")})
    data = asyncio.run(serve_and_exchange(facade, _req("/", "POST")))
    assert data.startswith(b"HTTP/1.1 405 Method Not Allowed\r\n")
    assert b"Allow: GET" in data


def test_vuln_route_emits_alert():
    facade, sink = _facade(
        paths={"/.git/HEAD": HttpPath(body="ref: x", vuln_id="exposed-git")}
    )
    asyncio.run(serve_and_exchange(facade, _req("/.git/HEAD")))
    alerts = [e for e in sink.events if e["event"].get("kind") == "alert"]
    assert alerts and alerts[0]["rangefinder"]["vuln_id"] == "exposed-git"


def _b64(user, pw):
    import base64

    return base64.b64encode(f"{user}:{pw}".encode()).decode()


def test_basic_auth_challenge_and_capture():
    facade, sink = _facade(
        paths={"/admin": HttpPath(auth_realm="ACME", auth_users={"admin": "s3cret"}, body="PANEL")}
    )
    # No credentials -> 401 challenge
    data = asyncio.run(serve_and_exchange(facade, _req("/admin")))
    assert data.startswith(b"HTTP/1.1 401")
    assert b'WWW-Authenticate: Basic realm="ACME"' in data


def test_basic_auth_wrong_creds_captured_as_failure():
    facade, sink = _facade(
        paths={"/admin": HttpPath(auth_realm="ACME", auth_users={"admin": "s3cret"}, body="PANEL")}
    )
    payload = (
        f"GET /admin HTTP/1.1\r\nHost: x\r\nAuthorization: Basic {_b64('root', 'toor')}\r\n"
        "Connection: close\r\n\r\n"
    ).encode()
    data = asyncio.run(serve_and_exchange(facade, payload))
    assert data.startswith(b"HTTP/1.1 401")
    auth = next(e for e in sink.events if e["event"]["action"] == "http_auth")
    assert auth["rangefinder"]["auth"] == {"scheme": "basic", "user": "root", "password": "toor"}
    assert auth["event"]["outcome"] == "failure"


def test_basic_auth_valid_creds_served_and_captured():
    facade, sink = _facade(
        paths={"/admin": HttpPath(auth_realm="ACME", auth_users={"admin": "s3cret"}, body="PANEL")}
    )
    payload = (
        f"GET /admin HTTP/1.1\r\nHost: x\r\nAuthorization: Basic {_b64('admin', 's3cret')}\r\n"
        "Connection: close\r\n\r\n"
    ).encode()
    data = asyncio.run(serve_and_exchange(facade, payload))
    assert data.startswith(b"HTTP/1.1 200 OK")
    assert data.endswith(b"PANEL")
    auth = next(e for e in sink.events if e["event"]["action"] == "http_auth")
    assert auth["event"]["outcome"] == "success"


def test_telemetry_records_user_agent_and_status():
    facade, sink = _facade(paths={"/": HttpPath(body="x")})
    payload = b"GET /?q=1 HTTP/1.1\r\nHost: x\r\nUser-Agent: gobuster/3.6\r\nConnection: close\r\n\r\n"
    asyncio.run(serve_and_exchange(facade, payload))
    req = next(e for e in sink.events if e["event"]["action"] == "http_request")
    assert req["user_agent"]["original"] == "gobuster/3.6"
    assert req["url"]["query"] == "q=1"
    assert req["http"]["response"]["status_code"] == 200


def test_options_advertises_allowed_methods():
    facade, _ = _facade(paths={"/": HttpPath(body="x")},
                        allowed_methods=["GET", "HEAD", "POST", "OPTIONS"])
    data = asyncio.run(serve_and_exchange(facade, _req("/", "OPTIONS")))
    assert data.startswith(b"HTTP/1.1 200 ")
    assert b"Allow: GET, HEAD, POST, OPTIONS" in data


def test_trace_echoes_when_enabled():
    facade, _ = _facade(paths={"/": HttpPath(body="x")}, trace_enabled=True)
    data = asyncio.run(serve_and_exchange(facade, _req("/", "TRACE")))
    assert data.startswith(b"HTTP/1.1 200 OK\r\n")
    assert b"message/http" in data
    assert b"TRACE / HTTP/1.1" in data          # the request is echoed back (XST)


def test_trace_refused_by_default():
    facade, _ = _facade(paths={"/": HttpPath(body="x")})  # trace_enabled defaults False
    data = asyncio.run(serve_and_exchange(facade, _req("/", "TRACE")))
    assert data.startswith(b"HTTP/1.1 405 Method Not Allowed\r\n")
    assert b"TRACE / HTTP/1.1" not in data       # nothing echoed — fail-closed


def test_options_does_not_bypass_auth_or_fabricate_paths():
    """OPTIONS is resource-scoped, not a server-wide 200: on a gated route it still challenges,
    and on an unknown path it 404s — it must not fabricate accessible surface (fail-closed)."""
    facade, _ = _facade(
        allowed_methods=["GET", "HEAD", "POST", "OPTIONS"],
        paths={
            "/": HttpPath(body="home"),
            "/admin": HttpPath(body="secret", auth_realm="admin", auth_users={"a": "b"}),
        })
    ok = asyncio.run(serve_and_exchange(facade, _req("/", "OPTIONS")))
    assert ok.startswith(b"HTTP/1.1 200 ") and b"Allow: GET, HEAD, POST, OPTIONS" in ok
    gated = asyncio.run(serve_and_exchange(facade, _req("/admin", "OPTIONS")))
    assert gated.startswith(b"HTTP/1.1 401 ")          # auth not bypassed
    missing = asyncio.run(serve_and_exchange(facade, _req("/nope", "OPTIONS")))
    assert missing.startswith(b"HTTP/1.1 404 ")        # no fabricated endpoint


def test_options_not_advertised_when_unmeasured():
    """With allowed_methods unmeasured (None, the fail-closed default), OPTIONS is not answered
    with a fabricated 200 + Allow — it falls through to the normal 405."""
    facade, _ = _facade(paths={"/": HttpPath(methods=["GET"], body="x")})  # allowed_methods=None
    data = asyncio.run(serve_and_exchange(facade, _req("/", "OPTIONS")))
    assert data.startswith(b"HTTP/1.1 405 Method Not Allowed\r\n")
