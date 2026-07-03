import asyncio

from rangefinder.facades.base import Facade, FacadeContext
from rangefinder.telemetry.emitter import Emitter, ListSink


def make_ctx() -> tuple[FacadeContext, ListSink]:
    sink = ListSink()
    ctx = FacadeContext(
        host_id="h1",
        host_name="H1",
        host_ip="127.0.0.1",
        emitter=Emitter([sink]),
        config_dir=".",
    )
    return ctx, sink


async def serve_and_exchange(facade: Facade, payload: bytes) -> bytes:
    """Bind *facade* on an ephemeral port, send *payload*, return all response bytes."""
    facade.port = 0  # override configured port with an ephemeral one for tests
    facade.bind_host = "127.0.0.1"
    await facade.start()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", facade.bound_port)
        writer.write(payload)
        await writer.drain()
        data = await reader.read(-1)  # until EOF
        writer.close()
        await writer.wait_closed()
    finally:
        await facade.stop()
    return data


def actions(sink: ListSink) -> list[str]:
    return [e["event"]["action"] for e in sink.events]
