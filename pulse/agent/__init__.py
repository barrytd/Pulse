# pulse.agent — downloadable Pulse Agent runtime.
#
# This package is the *client* half of the agent / server split that
# kicked off in Sprint 7. The server-side wire layer (enrollment exchange,
# heartbeat ingest, findings ingest) shipped in v1.6.0 under
# `pulse/agents.py` + `POST /api/agent/*`. This package is what runs on
# the customer's Windows host: enrolls itself, periodically scans the
# local event logs, and ships findings up to the configured Pulse server.
#
# The runtime stays light by design — every detection rule the server
# uses is reachable here too because we share `pulse.core.detections`.
# No new rule code lives in the agent.

from pulse.agent.config import AgentConfig, default_config_path, load_config, save_config
from pulse.agent.transport import AgentTransport, TransportError
from pulse.agent.scanner import scan_for_findings
from pulse.agent.runtime import AgentRuntime

__all__ = [
    "AgentConfig",
    "AgentRuntime",
    "AgentTransport",
    "TransportError",
    "default_config_path",
    "load_config",
    "save_config",
    "scan_for_findings",
]
