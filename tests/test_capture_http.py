import asyncio

from helpers import make_ctx

from rangefinder.capture import capture_http
from rangefinder.config.model import RangeConfig
from rangefinder.config.services import HttpConfig, HttpPath
from rangefinder.facades.http import HttpFacade


def _target_facade():
    ctx, _ = make_ctx()
    cfg = HttpConfig(
        port=80,
        server_header="nginx/1.18.0 (Ubuntu)",
        paths={
            "/": HttpPath(body="<html><a href='/portal'>portal</a>home</html>"),
            "/portal": HttpPath(body="portal page"),
            "/robots.txt": HttpPath(content_type="text/plain; charset=utf-8",
                                    body="User-agent: *\nDisallow: /secret\n"),
            "/secret": HttpPath(body="top secret data"),
            # a real exposure — capture must reproduce it without knowing what it is
            "/.git/HEAD": HttpPath(content_type="text/plain; charset=utf-8",
                                   body="ref: refs/heads/main\n"),
            # /config.json is in the probe list, so it gets discovered + captured
            "/config.json": HttpPath(content_type="application/json",
                                     body='{"db_password":"Sup3rSecret!"}'),
        },
    )
    return HttpFacade.from_config(cfg, ctx)


async def _capture(**kw):
    facade = _target_facade()
    facade.bind_host = "127.0.0.1"
    facade.port = 0
    await facade.start()
    try:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None, lambda: capture_http(f"http://127.0.0.1:{facade.bound_port}/", **kw)
        )
    finally:
        await facade.stop()


def test_capture_reproduces_exposures_verbatim():
    service, warnings, report = asyncio.run(_capture())
    # emitted config is a valid http service
    RangeConfig.model_validate({
        "name": "t", "network": {"subnet": "10.0.0.0/24"},
        "hosts": [{"id": "web", "hostname": "web", "ip": "10.0.0.10", "services": [service]}],
    })
    assert service["type"] == "http"
    assert service["server_header"] == "nginx/1.18.0 (Ubuntu)"

    # every captor now returns a provenance report (shared framework, not smb-only)
    assert report.protocol == "http"
    status = {i.field: i.status for i in report.items}
    assert status.get("server_header") == "measured"
    assert status.get("tls") == "measured"

    paths = service["paths"]
    # exposure carried through with no git-specific code
    assert paths["/.git/HEAD"]["body"] == "ref: refs/heads/main\n"
    # crawled link
    assert "/portal" in paths
    # discovered via robots.txt Disallow, then captured
    assert paths["/secret"]["body"] == "top secret data"


def test_scrub_redacts_secrets_but_keeps_route():
    service, *_ = asyncio.run(_capture(scrub=True))
    leak = service["paths"]["/config.json"]["body"]
    assert "Sup3rSecret" not in leak
    assert "REDACTED" in leak
    # the route still exists (structure faithful) — the weakness location carries through
    assert "/config.json" in service["paths"]


def test_verbatim_keeps_secrets():
    service, *_ = asyncio.run(_capture())
    assert "Sup3rSecret" in service["paths"]["/config.json"]["body"]
