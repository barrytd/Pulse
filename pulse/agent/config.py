"""Agent config — persisted state for the Pulse Agent runtime.

Lives at ``%PROGRAMDATA%\\Pulse\\agent.yaml`` on Windows by default so
the SYSTEM-privileged service install (Sprint 7 Phase B) can read + write
it. Falls back to ``~/.pulse/agent.yaml`` on non-Windows so dev / Linux
machines can run the agent for testing.

The file holds the long-lived agent token (`pa_…`) — treat it like a
password. The Windows installer locks the file's ACL to SYSTEM +
Administrators (Phase B). For now, we just rely on filesystem
permissions of the home/programdata directory.
"""

from __future__ import annotations

import os
import platform
from dataclasses import asdict, dataclass, field
from typing import List, Optional

import yaml


@dataclass
class AgentConfig:
    """Everything the agent needs to do its job. ``server_url`` and
    ``agent_token`` are mandatory after enrollment; the remaining fields
    have safe defaults so a fresh enroll-then-run flow works without
    further config edits."""

    server_url:    str = ""
    agent_id:      Optional[int] = None
    agent_token:   str = ""
    name:          str = ""
    enrolled_at:   Optional[str] = None
    # Polling cadence — how often to scan + ship findings. Heartbeat is
    # tied to a separate, faster cadence (see runtime.py).
    scan_interval_sec:      int = 30 * 60     # 30 minutes
    heartbeat_interval_sec: int = 60          # 1 minute
    # Days of history to scan on each pass. The agent keeps a baseline
    # so subsequent scans only see *new* events, but on first run we
    # bound the lookback to keep the initial sync sane.
    scan_days:              int = 1
    # Channels — optional override. If empty, the agent reads the
    # standard set ("Security", "System", "Application").
    channels:               List[str] = field(default_factory=list)
    # TLS verification toggle — for local dev against a self-signed cert.
    # Leave ``True`` in any deployment that talks to the real Pulse server.
    verify_tls:             bool = True


def default_config_path() -> str:
    """Conventional on-disk location of the agent config.

    On Windows we prefer ``%PROGRAMDATA%\\Pulse\\agent.yaml`` because
    that's where a SYSTEM-installed Windows service can read + write the
    file without UAC prompts on every restart. Elsewhere we fall back to
    a per-user file under the home directory."""
    if platform.system() == "Windows":
        base = os.environ.get("PROGRAMDATA") or r"C:\ProgramData"
        return os.path.join(base, "Pulse", "agent.yaml")
    home = os.path.expanduser("~")
    return os.path.join(home, ".pulse", "agent.yaml")


def load_config(path: Optional[str] = None) -> AgentConfig:
    """Read an agent config off disk. Missing file → fresh default
    config (so a brand-new install can run ``enroll`` without a config
    file having to exist first)."""
    real_path = path or default_config_path()
    if not os.path.exists(real_path):
        return AgentConfig()
    with open(real_path, "r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}
    if not isinstance(raw, dict):
        raise ValueError(f"agent config at {real_path} is not a YAML mapping")
    # Drop any keys the dataclass doesn't know about so an older config
    # format that's been hand-edited doesn't crash the load.
    valid = {k: raw.get(k) for k in AgentConfig.__dataclass_fields__ if k in raw}
    return AgentConfig(**valid)


def save_config(cfg: AgentConfig, path: Optional[str] = None) -> str:
    """Write an agent config to disk. Creates parent directories if
    they don't exist. Returns the resolved path so callers can log it.

    The token field is plaintext on disk — that's intentional for the
    same reason SSH keys are: the agent has to use it as a Bearer header,
    and the OS-level filesystem ACL is the right place to gate access.
    """
    real_path = path or default_config_path()
    parent = os.path.dirname(real_path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(real_path, "w", encoding="utf-8") as fh:
        yaml.safe_dump(asdict(cfg), fh, default_flow_style=False, sort_keys=True)
    return real_path
