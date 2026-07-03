import asyncio
import ssl

from helpers import make_ctx

from rangefinder.config.services import HttpConfig, HttpPath
from rangefinder.facades.http import HttpFacade
from rangefinder.tls import server_context


def test_cert_has_expected_sans():
    ctx = server_context("WEB01", ["web01.acme.corp", "10.20.0.30"])
    assert isinstance(ctx, ssl.SSLContext)
    # cached: same inputs return the same context
    assert server_context("WEB01", ["web01.acme.corp", "10.20.0.30"]) is ctx


def test_https_facade_serves_over_tls():
    async def run():
        ctx, sink = make_ctx()
        cfg = HttpConfig(port=443, tls=True, paths={"/": HttpPath(body="secure")})
        facade = HttpFacade.from_config(cfg, ctx)
        assert facade.protocol == "https"
        facade.bind_host = "127.0.0.1"
        facade.port = 0
        await facade.start()
        try:
            client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            client_ctx.check_hostname = False
            client_ctx.verify_mode = ssl.CERT_NONE
            reader, writer = await asyncio.open_connection(
                "127.0.0.1", facade.bound_port, ssl=client_ctx
            )
            writer.write(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            await writer.drain()
            data = await reader.read(-1)
            writer.close()
        finally:
            await facade.stop()
        return data

    data = asyncio.run(run())
    assert data.startswith(b"HTTP/1.1 200 OK")
    assert data.endswith(b"secure")
