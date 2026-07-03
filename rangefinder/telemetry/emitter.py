"""Telemetry sinks and the fan-out emitter.

Events are dicts. Sinks serialize them to a single JSON line. Writes are synchronous
and flushed per event so nothing is buffered-and-lost when the container receives
SIGTERM. A single asyncio event loop means no locking is required.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Protocol, TextIO


def _dumps(event: dict) -> str:
    # default=str keeps the emitter robust against stray non-JSON values (e.g. an
    # IP address object) rather than crashing a live facade.
    return json.dumps(event, separators=(",", ":"), default=str)


class Sink(Protocol):
    def write(self, event: dict) -> None: ...

    def close(self) -> None: ...


class StdoutSink:
    """Writes one JSON line per event to stdout (container-native log stream)."""

    def __init__(self, stream: TextIO | None = None) -> None:
        self._stream = stream if stream is not None else sys.stdout

    def write(self, event: dict) -> None:
        self._stream.write(_dumps(event) + "\n")
        self._stream.flush()

    def close(self) -> None:  # stdout is not ours to close
        try:
            self._stream.flush()
        except Exception:
            pass


class FileSink:
    """Appends JSON lines to a file."""

    def __init__(self, path: str | Path) -> None:
        self._fh = open(path, "a", encoding="utf-8", buffering=1)

    def write(self, event: dict) -> None:
        self._fh.write(_dumps(event) + "\n")
        self._fh.flush()

    def close(self) -> None:
        try:
            self._fh.close()
        except Exception:
            pass


class ListSink:
    """Collects events in memory. Intended for tests."""

    def __init__(self) -> None:
        self.events: list[dict] = []

    def write(self, event: dict) -> None:
        self.events.append(event)

    def close(self) -> None:
        pass


class Emitter:
    """Fans an event out to every configured sink."""

    def __init__(self, sinks: list[Sink]) -> None:
        self._sinks = sinks

    def emit(self, event: dict) -> None:
        for sink in self._sinks:
            try:
                sink.write(event)
            except Exception:
                # Telemetry must never take down a facade. Swallow sink failures.
                pass

    def close(self) -> None:
        for sink in self._sinks:
            sink.close()
