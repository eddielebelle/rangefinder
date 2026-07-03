import asyncio

from helpers import actions, make_ctx, serve_and_exchange

from rangefinder.config.services import BannerConfig, BannerRule
from rangefinder.facades.banner import BannerFacade


def _facade(**kw):
    ctx, sink = make_ctx()
    cfg = BannerConfig(port=22, **kw)
    return BannerFacade.from_config(cfg, ctx), sink


def test_sends_banner_with_terminator():
    facade, sink = _facade(
        protocol="ssh",
        banner="SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4",
        close_after_banner=True,
    )
    data = asyncio.run(serve_and_exchange(facade, b""))
    assert data == b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n"
    assert "banner_sent" in actions(sink)


def test_rule_response():
    facade, sink = _facade(
        protocol="ftp",
        banner="220 corp-ftp",
        rules=[BannerRule(match=r"^USER", respond="331 Password required", close_after=True)],
    )
    data = asyncio.run(serve_and_exchange(facade, b"USER admin\r\n"))
    assert b"220 corp-ftp\r\n" in data
    assert b"331 Password required\r\n" in data
    assert "line_received" in actions(sink)


def test_empty_banner_decoy_just_opens_port():
    # Represents an ldap/smb decoy: port open, no banner, closes immediately.
    facade, sink = _facade(protocol="ldap", banner="", close_after_banner=True)
    data = asyncio.run(serve_and_exchange(facade, b""))
    assert data == b"\r\n"  # empty banner + terminator
    acts = actions(sink)
    assert "connection_open" in acts and "connection_close" in acts
