"""Config loading and validation with friendly error reporting."""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import ValidationError

from rangefinder.config.model import SCHEMA_VERSION, RangeConfig


class ConfigError(Exception):
    """Raised when a range config cannot be read or fails validation."""


def load_config(path: str | Path) -> RangeConfig:
    """Read and validate a range config from *path*.

    Raises ConfigError with a human-readable message on any failure (missing file,
    invalid JSON, or schema validation error). A top-level ``$schema`` key is allowed
    (editors use it to locate the JSON Schema) and stripped before validation.
    """
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise ConfigError(f"config file not found: {p}") from None
    except OSError as exc:
        raise ConfigError(f"cannot read config {p}: {exc}") from exc

    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"{p}: invalid JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise ConfigError(f"{p}: top-level config must be a JSON object")

    data.pop("$schema", None)

    # Check the schema stamp before validation so a config newer than this build produces a
    # clear "rebuild the image" error rather than a cryptic unknown-field rejection.
    stamped = data.get("schema_version")
    if isinstance(stamped, int) and stamped > SCHEMA_VERSION:
        raise ConfigError(
            f"{p}: config needs config-schema v{stamped}, but this rangefinder build only "
            f"supports up to v{SCHEMA_VERSION}. The runtime image is likely stale — rebuild "
            f"it (docker build -t rangefinder:latest .) or upgrade rangefinder."
        )

    try:
        return RangeConfig.model_validate(data)
    except ValidationError as exc:
        raise ConfigError(_format_validation_error(p, exc)) from exc


def _format_validation_error(path: Path, exc: ValidationError) -> str:
    lines = [f"{path}: config validation failed ({exc.error_count()} error(s)):"]
    for err in exc.errors():
        loc = ".".join(str(part) for part in err["loc"]) or "<root>"
        lines.append(f"  - {loc}: {err['msg']}")
    return "\n".join(lines)
