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


def test_binary_greeting_sent_on_connect():
    # MySQL-style: raw binary greeting sent immediately on connect.
    facade, sink = _facade(
        protocol="mysql", binary=True, banner_hex="0a382e302e3335", close_after_banner=True
    )
    data = asyncio.run(serve_and_exchange(facade, b""))
    assert data == bytes.fromhex("0a382e302e3335")
    assert "banner_sent" in actions(sink)


def test_binary_rule_responds_to_probe():
    # RDP-style: no greeting; respond to a client probe matched by hex.
    facade, sink = _facade(
        protocol="ms-wbt-server",
        binary=True,
        rules=[BannerRule(match_hex="0300", respond_hex="030000130ed0", close_after=True)],
    )
    data = asyncio.run(serve_and_exchange(facade, bytes.fromhex("030000130ee0")))
    assert data == bytes.fromhex("030000130ed0")
    assert "line_received" in actions(sink)


def test_empty_banner_decoy_just_opens_port():
    # Represents an ldap/smb decoy: port open, no banner, closes immediately.
    facade, sink = _facade(protocol="ldap", banner="", close_after_banner=True)
    data = asyncio.run(serve_and_exchange(facade, b""))
    assert data == b"\r\n"  # empty banner + terminator
    acts = actions(sink)
    assert "connection_open" in acts and "connection_close" in acts


def test_mysql_greeting_randomized_per_connection():
    """Real mysqld varies the salt + connection id each connect; a static handshake is a tell."""
    from rangefinder.facades.banner import _randomize_mysql_greeting

    base = bytes.fromhex(
        "5a0000000a382e302e33352d307562756e7475302e32322e30342e31003600000001020304050607"
        "0800fff7210200ff811500000000000000000000090a0b0c0d0e0f10111213006d7973716c5f6e61"
        "746976655f70617373776f726400")
    a = _randomize_mysql_greeting(base)
    b = _randomize_mysql_greeting(base)
    assert a != b                        # per-connection randomness
    assert len(a) == len(base)           # structure/length preserved
    assert a[:5] == base[:5]             # packet header + protocol version intact
    nul = base.index(0, 5)
    assert a[5:nul] == base[5:nul]       # server-version string preserved
    assert a[nul + 1:nul + 5] != base[nul + 1:nul + 5]   # connection id no longer the static 0x36
    # non-handshake input is passed through untouched
    assert _randomize_mysql_greeting(b"\x00\x00\x00\x00\xff") == b"\x00\x00\x00\x00\xff"
