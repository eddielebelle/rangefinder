"""Facade registry keyed by service ``type``.

Config models live in ``rangefinder.config.services``; this registry only maps a type
string to its runtime facade class, so importing the facade layer never pulls the config
layer into a cycle. Facade modules self-register via the ``@register("type")`` decorator;
``rangefinder.facades.__init__`` imports them so the registry is populated on import.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Callable

from rangefinder.config.services import IMPLEMENTED_TYPES

if TYPE_CHECKING:  # avoid import cycle at runtime
    from rangefinder.facades.base import Facade, FacadeContext

_REGISTRY: dict[str, type] = {}


def register(type_key: str) -> Callable[[type], type]:
    def deco(cls: type) -> type:
        if type_key in _REGISTRY:
            raise ValueError(f"facade type {type_key!r} already registered")
        cls.type_name = type_key
        _REGISTRY[type_key] = cls
        return cls

    return deco


def registered_types() -> list[str]:
    return sorted(_REGISTRY)


def build_facade(service_cfg, ctx: "FacadeContext") -> "Facade":
    """Instantiate the facade for *service_cfg*.

    Raises NotImplementedError for a service type whose config model exists but whose
    protocol facade is not shipped yet (ldap/smb/dns in v1), with a hint to use a
    ``banner`` decoy instead. Raises ValueError for an entirely unknown type.
    """
    type_key = service_cfg.type
    cls = _REGISTRY.get(type_key)
    if cls is None:
        if type_key not in IMPLEMENTED_TYPES:
            raise NotImplementedError(
                f"service type {type_key!r} is defined in the schema but its facade "
                f"is not implemented in this release; represent it as a 'banner' "
                f"service for now. Implemented types: {sorted(IMPLEMENTED_TYPES)}"
            )
        raise ValueError(f"unknown service type {type_key!r}")
    return cls.from_config(service_cfg, ctx)
