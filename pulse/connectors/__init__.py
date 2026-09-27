# pulse/connectors/__init__.py
# ----------------------------
# Connector registry. Every module in this package is imported once on
# first use; each one decorates its class with `@register`, which adds
# it to the registry. Adding an integration = drop a file here.
#
#     from pulse import connectors
#     connectors.get("virustotal")
#     connectors.all_connectors(kind="enrichment")
#     connectors.run_action("virustotal", "lookup_ip", {"ip": "8.8.8.8"}, cfg)
#
# See base.py for the Connector interface and the fail-safe contract.

from __future__ import annotations

import importlib
import logging
import pkgutil

from .base import Connector, register, _REGISTRY

log = logging.getLogger(__name__)

__all__ = ["Connector", "register", "get", "all_connectors",
           "config_for", "run_action"]

_discovered = False


def _discover():
    """Import every connector module in this package exactly once.

    A module that fails to import is logged and skipped, so one broken
    integration can't take the rest down with it."""
    global _discovered
    if _discovered:
        return
    _discovered = True
    for mod in pkgutil.iter_modules(__path__):
        if mod.name.startswith("_") or mod.name == "base":
            continue
        try:
            importlib.import_module(f"{__name__}.{mod.name}")
        except Exception:
            log.exception("Failed to load connector module %s", mod.name)


def get(key):
    """Return the registered connector for `key`, or None."""
    _discover()
    return _REGISTRY.get(key)


def all_connectors(kind=None):
    """Registered connectors, optionally narrowed to one kind, in a
    stable order (by key) so the UI doesn't reshuffle between loads."""
    _discover()
    out = [c for c in _REGISTRY.values() if kind is None or c.kind == kind]
    return sorted(out, key=lambda c: c.key)


def config_for(connector, pulse_config, db_path=None):
    """Build the runtime config dict for `connector` from pulse.yaml."""
    cfg = dict(connector.config_from_pulse(pulse_config or {}) or {})
    if db_path is not None:
        cfg["db_path"] = db_path
    return cfg


def run_action(key, action, inputs, config):
    """Run one connector action. Never raises: an unknown connector or
    action, or any error inside the connector, returns None."""
    connector = get(key)
    if connector is None or action not in connector.actions():
        return None
    try:
        return connector.run(action, inputs or {}, config or {})
    except Exception:
        log.exception("Connector %s.%s failed", key, action)
        return None
