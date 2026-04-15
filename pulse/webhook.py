# pulse/webhook.py
# -----------------
# Posts Pulse alerts to Slack or Discord via an incoming-webhook URL.
#
# WHY WEBHOOKS?
# Email is great for a boss who reads their inbox. It's useless for getting
# a teenager's attention. A Slack or Discord push notification lands in
# under a second on a phone that's already in your hand.
#
# Both services accept a POST of JSON to a user-generated URL — no API
# token, no OAuth, just a secret URL. We detect which service the URL
# points at and format the payload to match.
#
# SECURITY NOTE:
# The webhook URL IS the credential. Anyone who can read it can post
# messages as the integration. Treat it like a password — never return
# the full URL from the config API, never log it, and never commit a
# real one into pulse.yaml in a public repo.

import json
import urllib.request
import urllib.error


# Slack incoming-webhook URLs start with this prefix.
_SLACK_PREFIX   = "https://hooks.slack.com/"
# Discord webhook URLs. The /api/webhooks path is the stable bit.
_DISCORD_HOSTS  = ("discord.com", "discordapp.com", "ptb.discord.com", "canary.discord.com")

# Colour stripes for Slack/Discord attachments. Matches the dashboard palette.
_SEVERITY_HEX = {
    "CRITICAL": "#8e44ad",
    "HIGH":     "#e74c3c",
    "MEDIUM":   "#e67e22",
    "LOW":      "#3498db",
}

# Discord embeds take an integer, not a #rrggbb string.
_SEVERITY_INT = {sev: int(hex_[1:], 16) for sev, hex_ in _SEVERITY_HEX.items()}


def detect_flavor(url):
    """Guess whether a webhook URL belongs to Slack or Discord.

    Returns "slack", "discord", or None (unknown). Callers fall back to
    Slack's format as the lingua-franca — most integrations accept it.
    """
    if not url:
        return None
    lower = url.lower()
    if lower.startswith(_SLACK_PREFIX):
        return "slack"
    if any(host in lower for host in _DISCORD_HOSTS):
        return "discord"
    return None


def validate_webhook_config(webhook_config):
    """Return None if the config can send, or a human error string if not.

    Same contract as emailer.validate_email_config so the dispatcher can
    short-circuit with a useful message on missing pieces.
    """
    if not webhook_config:
        return "webhook config missing"
    if not webhook_config.get("enabled"):
        return "webhook disabled"
    url = (webhook_config.get("url") or "").strip()
    if not url:
        return "webhook url not set"
    if not url.startswith(("http://", "https://")):
        return "webhook url must start with http:// or https://"
    return None


def send_webhook(webhook_config, findings, *, hostname=None, timeout=10):
    """Fire one webhook POST covering `findings`.

    Returns True on 2xx, False on any failure. Never raises — callers are
    generally in a "best effort" alerting loop and shouldn't crash a scan
    just because Slack is down.

    `flavor` in the config overrides auto-detection. Leave it empty to
    let us guess from the URL.
    """
    err = validate_webhook_config(webhook_config)
    if err:
        return False

    url = webhook_config["url"].strip()
    flavor = (webhook_config.get("flavor") or "").strip().lower() or detect_flavor(url) or "slack"

    if flavor == "discord":
        payload = _build_discord_payload(findings, hostname)
    else:
        payload = _build_slack_payload(findings, hostname)

    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "User-Agent": "Pulse/1.1"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return 200 <= resp.status < 300
    except urllib.error.HTTPError as e:
        # Discord returns 204 No Content on success but may return 400 on bad
        # payload — treat anything non-2xx as failure.
        return 200 <= e.code < 300
    except (urllib.error.URLError, TimeoutError, OSError):
        return False


# ---------------------------------------------------------------------------
# Payload builders
# ---------------------------------------------------------------------------

def _header_text(findings, hostname):
    counts = {}
    for f in findings or []:
        counts[f.get("severity", "LOW")] = counts.get(f.get("severity", "LOW"), 0) + 1
    pieces = []
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if counts.get(sev):
            pieces.append(f"{counts[sev]} {sev}")
    summary = ", ".join(pieces) or f"{len(findings or [])} finding(s)"
    host_part = f" on {hostname}" if hostname else ""
    return f"Pulse detected {summary}{host_part}"


def _truncate(text, limit):
    if not text:
        return ""
    if len(text) <= limit:
        return text
    return text[: limit - 3].rstrip() + "..."


def _build_slack_payload(findings, hostname):
    """Slack uses `attachments` with `color` stripes. Classic format — works
    for every incoming webhook regardless of workspace settings."""
    findings = list(findings or [])
    text = _header_text(findings, hostname)

    attachments = []
    # Cap to keep the message readable. Anyone hit by >10 fresh findings
    # has bigger problems than a truncated Slack notification.
    for f in findings[:10]:
        severity = f.get("severity", "LOW")
        attachments.append({
            "color": _SEVERITY_HEX.get(severity, "#808080"),
            "title": f"[{severity}] {f.get('rule', 'Unknown rule')}",
            "text":  _truncate(f.get("details") or f.get("description") or "", 500),
            "mrkdwn_in": ["text"],
        })

    if len(findings) > 10:
        attachments.append({
            "color": "#808080",
            "text":  f"+{len(findings) - 10} more — open the Pulse dashboard for the full list.",
        })

    return {"text": text, "attachments": attachments}


def _build_discord_payload(findings, hostname):
    """Discord uses `embeds` with an integer colour. Max 10 embeds per
    message; we cap at that boundary to avoid the 400 response Discord
    would throw otherwise."""
    findings = list(findings or [])
    text = _header_text(findings, hostname)

    embeds = []
    for f in findings[:9]:  # leave room for the overflow embed
        severity = f.get("severity", "LOW")
        embeds.append({
            "title":       _truncate(f"[{severity}] {f.get('rule', 'Unknown rule')}", 250),
            "description": _truncate(f.get("details") or f.get("description") or "", 1500),
            "color":       _SEVERITY_INT.get(severity, 0x808080),
        })

    if len(findings) > 9:
        embeds.append({
            "title": "More findings",
            "description": f"+{len(findings) - 9} more — open the Pulse dashboard for the full list.",
            "color": 0x808080,
        })

    return {"content": text, "embeds": embeds}
