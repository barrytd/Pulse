# pulse/connectors/chat_webhook.py
# --------------------------------
# Response connector: post a message to the team's Slack and/or Discord.
#
# Uses the webhooks already configured under Settings (pulse.yaml
# `delivery.slack` / `delivery.discord`, or the legacy `webhook` block).
# A recipe can only supply the message text, never a URL, so a playbook
# can't be turned into a way to make the server POST to arbitrary hosts.
#
# kind="response": every post waits for human approval.

from __future__ import annotations

from .base import Connector, register

MAX_TEXT = 2000


def _targets(pulse_config):
    """[(flavor, url)] for every enabled chat webhook in pulse.yaml."""
    cfg = pulse_config if isinstance(pulse_config, dict) else {}
    out = []
    delivery = cfg.get("delivery") or {}
    for flavor in ("slack", "discord"):
        block = delivery.get(flavor) or {}
        url = str(block.get("webhook_url") or "").strip()
        if block.get("enabled") and url:
            out.append((flavor, url))
    if not out:
        legacy = cfg.get("webhook") or {}
        url = str(legacy.get("url") or "").strip()
        if legacy.get("enabled") and url:
            flavor = legacy.get("flavor") or ("discord" if "discord" in url else "slack")
            out.append((flavor, url))
    return out


@register
class ChatWebhookConnector(Connector):
    key = "webhook"
    name = "Slack / Discord"
    kind = "response"
    config_fields = ["targets"]

    def actions(self):
        return ["post_message"]

    def config_from_pulse(self, pulse_config):
        return {"targets": _targets(pulse_config)}

    def action_inputs(self, action):
        return [{"name": "text", "label": "Message", "required": True, "multiline": True}]

    def run(self, action, inputs, config):
        if action != "post_message":
            return None
        from ..alerts.webhook import _post_json

        text = str(inputs.get("text") or "").strip()[:MAX_TEXT]
        if not text:
            return {"ok": False, "message": "Nothing to post (empty text)."}
        targets = config.get("targets") or []
        if not targets:
            return {"ok": False, "message": "No Slack or Discord webhook is set up under Settings."}
        sent = []
        for flavor, url in targets:
            payload = {"content": text} if flavor == "discord" else {"text": text}
            if _post_json(url, payload):
                sent.append(flavor)
        if sent:
            return {"ok": True, "message": "Posted to " + " and ".join(sent) + "."}
        return {"ok": False, "message": "The webhook post failed."}
