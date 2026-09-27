# pulse/connectors/outbound_webhook.py
# ------------------------------------
# Response connector: POST a JSON payload to a URL the admin sets, so a
# playbook can hand off to anything else (n8n, Zapier, Tines, a SOAR, an
# internal service).
#
# Set under Settings (pulse.yaml `outbound_webhook`): the URL, an optional
# signing secret, and whether private/LAN destinations are allowed. A
# playbook can never supply or change the URL.
#
# The payload is only what the playbook step says:
#     {"source": "pulse", "event": <event input or "pulse.playbook">,
#      "message": <message input>, "sent_at": <UTC ISO time>}
# Nothing about the finding is added automatically; a step includes a
# finding field only by putting a placeholder in its message.
#
# With a secret set, each request carries
#     X-Pulse-Timestamp: <unix seconds>
#     X-Pulse-Signature: sha256=<hex HMAC-SHA256(secret, "<timestamp>.<body>")>
# so the receiver can check it came from Pulse and isn't a replay.
#
# kind="response": every send waits for approval. Nothing cached. The URL
# goes through base.request_guarded (https, no loopback / metadata, no
# redirects, private only when allowed). Failures return ok=False.

from __future__ import annotations

import hashlib
import hmac
import json
import time
import urllib.error
from datetime import datetime, timezone

from .base import Connector, DestinationRefused, register, request_guarded

MAX_MESSAGE = 8000
MAX_EVENT = 100


def _settings(pulse_config):
    block = (pulse_config or {}).get("outbound_webhook") or {}
    return {"url": str(block.get("url") or "").strip(),
            "secret": str(block.get("secret") or "").strip(),
            "allow_private": bool(block.get("allow_private"))}


def build_payload(event, message):
    return {"source": "pulse", "event": (event or "pulse.playbook")[:MAX_EVENT],
            "message": message[:MAX_MESSAGE],
            "sent_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat()}


def sign(secret, timestamp, body):
    mac = hmac.new(secret.encode("utf-8"), f"{timestamp}.".encode("utf-8") + body, hashlib.sha256)
    return "sha256=" + mac.hexdigest()


def send(cfg, payload):
    """POST `payload`; returns an ok/message dict. Never raises."""
    if not cfg.get("url"):
        return {"ok": False, "message": "No outbound webhook URL is set under Settings."}
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    headers = {}
    if cfg.get("secret"):
        ts = str(int(time.time()))
        headers["X-Pulse-Timestamp"] = ts
        headers["X-Pulse-Signature"] = sign(cfg["secret"], ts, body)
    try:
        status, _ = request_guarded(cfg["url"], body=body, headers=headers,
                                    allow_private=cfg.get("allow_private", False))
    except DestinationRefused as e:
        return {"ok": False, "message": str(e)}
    except urllib.error.HTTPError as e:
        if 300 <= e.code < 400:
            return {"ok": False, "message": "The webhook answered with a redirect, which Pulse doesn't follow."}
        return {"ok": False, "message": f"The webhook returned HTTP {e.code}."}
    except (urllib.error.URLError, TimeoutError, OSError):
        return {"ok": False, "message": "Couldn't reach the webhook URL."}
    return {"ok": True, "status": status, "message": f"Sent (HTTP {status})."}


@register
class OutboundWebhookConnector(Connector):
    key = "outbound_webhook"
    name = "Outbound webhook"
    kind = "response"
    config_fields = ["url"]
    result_fields = {}

    def actions(self):
        return ["send"]

    def action_label(self, action):
        return "Send to your webhook"

    def action_inputs(self, action):
        return [
            {"name": "message", "label": "Message", "required": True, "multiline": True},
            {"name": "event", "label": "Event name (optional, e.g. pulse.finding)",
             "required": False, "multiline": False},
        ]

    def config_from_pulse(self, pulse_config):
        return _settings(pulse_config)

    def run(self, action, inputs, config):
        if action != "send":
            return None
        message = str(inputs.get("message") or "").strip()
        if not message:
            return {"ok": False, "message": "Nothing to send (empty message)."}
        return send(config, build_payload(str(inputs.get("event") or "").strip(), message))
