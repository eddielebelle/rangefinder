"""Facade layer. Importing this package registers all built-in facades."""

from rangefinder.facades.base import ConnScope, Facade, FacadeContext
from rangefinder.facades.registry import build_facade, register, registered_types

# Import concrete facades for their registration side effects.
from rangefinder.facades import banner as _banner  # noqa: F401
from rangefinder.facades import http as _http  # noqa: F401
from rangefinder.facades import ldap as _ldap  # noqa: F401
from rangefinder.facades import smb as _smb  # noqa: F401

__all__ = [
    "Facade",
    "FacadeContext",
    "ConnScope",
    "build_facade",
    "register",
    "registered_types",
]
