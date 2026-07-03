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


def test_telemetry_records_user_agent_and_status():
    facade, sink = _facade(paths={"/": HttpPath(body="x")})
    payload = b"GET /?q=1 HTTP/1.1\r\nHost: x\r\nUser-Agent: gobuster/3.6\r\nConnection: close\r\n\r\n"
    asyncio.run(serve_and_exchange(facade, payload))
    req = next(e for e in sink.events if e["event"]["action"] == "http_request")
    assert req["user_agent"]["original"] == "gobuster/3.6"
    assert req["url"]["query"] == "q=1"
    assert req["http"]["response"]["status_code"] == 200
