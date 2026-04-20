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
# token, no OAuth, just a secret URL.
#
# SECURITY NOTE:
# The webhook URL IS the credential. Anyone who can read it can post
# messages as the integration. Treat it like a password — never return
# the full URL from the config API, never log it, and never commit a
# real one into pulse.yaml in a public repo.

import json
import urllib.request
import urllib.error
from datetime import datetime, timezone


# Slack incoming-webhook URLs start with this prefix.
_SLACK_PREFIX  = "https://hooks.slack.com/"
# Discord webhook URLs. The /api/webhooks path is the stable bit.
_DISCORD_HOSTS = ("discord.com", "discordapp.com", "ptb.discord.com", "canary.discord.com")

# Colour stripes for Slack attachments + Discord embeds. Matches dashboard.
_SEVERITY_HEX = {
    "CRITICAL": "#c0392b",
    "HIGH":     "#e67e22",
    "MEDIUM":   "#f1c40f",
    "LOW":      "#27ae60",
}

# Discord embeds take an integer colour, not a #rrggbb string.
_SEVERITY_INT = {sev: int(hex_[1:], 16) for sev, hex_ in _SEVERITY_HEX.items()}

# Coloured circle emojis used in the Slack severity breakdown line.
_SEVERITY_EMOJI = {
    "CRITICAL": "\U0001F534",  # red circle
    "HIGH":     "\U0001F7E0",  # orange circle
    "MEDIUM":   "\U0001F7E1",  # yellow circle
    "LOW":      "\U0001F7E2",  # green circle
}

_SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


def detect_flavor(url):
    """Guess whether a webhook URL belongs to Slack or Discord.

    Returns "slack", "discord", or None (unknown).
    """
    if not url:
        return None
    lower = url.lower()
    if lower.startswith(_SLACK_PREFIX):
        return "slack"
    if any(host in lower for host in _DISCORD_HOSTS):
        return "discord"
    return None


# ---------------------------------------------------------------------------
# Transport
# ---------------------------------------------------------------------------

def _post_json(url, payload, timeout=10):
    """POST one JSON payload. Returns True on 2xx, False on anything else.
    Never raises — webhook failures should never crash a scan."""
    if not url:
        return False
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "User-Agent": "Pulse/1.2"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return 200 <= resp.status < 300
    except urllib.error.HTTPError as e:
        return 200 <= e.code < 300
    except (urllib.error.URLError, TimeoutError, OSError):
        return False


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def _validate_url(url, expected_flavor=None):
    """Return None if URL is usable, or a human error string if not.
    When `expected_flavor` is supplied, reject mismatched URLs."""
    if not url:
        return "webhook url not set"
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        return "webhook url must start with http:// or https://"
    if expected_flavor:
        flavor = detect_flavor(url)
        if flavor and flavor != expected_flavor:
            return f"url looks like a {flavor} webhook, not {expected_flavor}"
    return None


def validate_slack_url(url):
    return _validate_url(url, expected_flavor="slack")


def validate_discord_url(url):
    return _validate_url(url, expected_flavor="discord")


def validate_webhook_config(webhook_config):
    """Legacy single-URL validator — kept for the pre-delivery.* config path."""
    if not webhook_config:
        return "webhook config missing"
    if not webhook_config.get("enabled"):
        return "webhook disabled"
    return _validate_url((webhook_config.get("url") or "").strip())


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _severity_counts(findings):
    counts = {sev: 0 for sev in _SEVERITY_ORDER}
    for f in findings or []:
        sev = (f.get("severity") or "LOW").upper()
        if sev in counts:
            counts[sev] += 1
    return counts


def _highest_severity(findings):
    """First severity bucket (in CRITICAL→LOW order) with at least one hit."""
    counts = _severity_counts(findings)
    for sev in _SEVERITY_ORDER:
        if counts[sev]:
            return sev
    return "LOW"


def _sort_by_severity(findings):
    rank = {sev: i for i, sev in enumerate(_SEVERITY_ORDER)}
    return sorted(
        findings or [],
        key=lambda f: rank.get((f.get("severity") or "LOW").upper(), 99),
    )


def _truncate(text, limit):
    if not text:
        return ""
    if len(text) <= limit:
        return text
    return text[: limit - 3].rstrip() + "..."


# ---------------------------------------------------------------------------
# Slack — block kit
# ---------------------------------------------------------------------------

def build_slack_payload(findings, *, hostname=None, score=None, grade=None,
                        report_path=None, scan_dt=None, top_n=3):
    """Build the Slack webhook payload (Block Kit).

    The message is shaped as:
      - header:  "Pulse Threat Report — <date>"
      - section: host/score/grade/severity line with circle emojis
      - divider
      - context: top N findings ("• [HIGH] Rule — description")
      - "...and X more findings"  (only if there are more)
      - context: "Full report saved locally at <path>"
    """
    findings = list(findings or [])
    scan_dt = scan_dt or datetime.now()
    counts = _severity_counts(findings)

    # Header — uses plain_text, max 150 chars.
    header = {
        "type": "header",
        "text": {
            "type": "plain_text",
            "text": _truncate(
                f"Pulse Threat Report \u2014 {scan_dt.strftime('%Y-%m-%d')}",
                150,
            ),
            "emoji": True,
        },
    }

    # Host / score / grade line.
    meta_lines = []
    if hostname:
        meta_lines.append(f"*Host:* {hostname}")
    if score is not None:
        meta_lines.append(f"*Score:* {score}")
    if grade:
        meta_lines.append(f"*Grade:* {grade}")
    meta_text = "  ".join(meta_lines) if meta_lines else "*Host:* unknown"

    severity_parts = []
    for sev in _SEVERITY_ORDER:
        n = counts[sev]
        if n:
            severity_parts.append(f"{_SEVERITY_EMOJI[sev]} *{n}* {sev.title()}")
    severity_text = "  ".join(severity_parts) if severity_parts else "No findings."

    info_section = {
        "type": "section",
        "text": {"type": "mrkdwn", "text": meta_text + "\n" + severity_text},
    }

    blocks = [header, info_section, {"type": "divider"}]

    # Top N findings — sorted highest severity first.
    sorted_findings = _sort_by_severity(findings)
    top = sorted_findings[:top_n]
    if top:
        lines = []
        for f in top:
            sev = (f.get("severity") or "LOW").upper()
            rule = f.get("rule") or "Unknown rule"
            desc = f.get("description") or f.get("details") or ""
            lines.append(
                f"{_SEVERITY_EMOJI.get(sev, '')} *[{sev}]* {rule} \u2014 "
                f"{_truncate(desc, 180)}"
            )
        blocks.append({
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": "\n".join(lines)}],
        })

    if len(sorted_findings) > top_n:
        more = len(sorted_findings) - top_n
        blocks.append({
            "type": "context",
            "elements": [
                {"type": "mrkdwn", "text": f"...and *{more}* more findings."},
            ],
        })

    if report_path:
        blocks.append({
            "type": "context",
            "elements": [
                {"type": "mrkdwn",
                 "text": f"Full report saved locally at `{report_path}`"},
            ],
        })

    # `text` is the fallback for clients that can't render blocks (and is
    # what shows in the mobile push banner).
    summary = f"Pulse: {sum(counts.values())} finding(s)"
    if hostname:
        summary += f" on {hostname}"
    return {"text": summary, "blocks": blocks}


def send_slack(webhook_url, findings, *, hostname=None, score=None, grade=None,
               report_path=None, scan_dt=None, timeout=10):
    """Post a Slack block-kit message summarising `findings`.
    Returns True on success, False on any failure."""
    err = validate_slack_url(webhook_url)
    if err:
        return False
    payload = build_slack_payload(
        findings, hostname=hostname, score=score, grade=grade,
        report_path=report_path, scan_dt=scan_dt,
    )
    return _post_json(webhook_url.strip(), payload, timeout=timeout)


# ---------------------------------------------------------------------------
# Discord — embeds
# ---------------------------------------------------------------------------

def build_discord_payload(findings, *, hostname=None, score=None, grade=None,
                          report_path=None, scan_dt=None, top_n=3):
    """Build the Discord webhook payload (single rich embed).

    The embed layout:
      - title:       "Pulse Threat Report"
      - color:       matches highest severity (green if none)
      - description: Host / Score / Grade
      - fields:      one per severity level with count
      - second embed: top N findings
      - footer:      "Full report saved locally at <path>"  (if given)
      - timestamp:   scan time (ISO-8601 with Z)
    """
    findings = list(findings or [])
    scan_dt = scan_dt or datetime.now()
    counts = _severity_counts(findings)
    has_any = any(counts.values())
    dominant = _highest_severity(findings) if has_any else None

    # Colour: highest severity, or green "secure" if clean.
    color = _SEVERITY_INT.get(dominant, int("27ae60", 16))

    desc_lines = []
    if hostname:
        desc_lines.append(f"**Host:** {hostname}")
    if score is not None:
        desc_lines.append(f"**Score:** {score}")
    if grade:
        desc_lines.append(f"**Grade:** {grade}")
    description = "\n".join(desc_lines) if desc_lines else "Scan complete."

    fields = []
    for sev in _SEVERITY_ORDER:
        fields.append({
            "name":   sev.title(),
            "value":  str(counts[sev]),
            "inline": True,
        })

    # ISO-8601 with a trailing Z — Discord expects UTC timestamps.
    if scan_dt.tzinfo is None:
        ts = scan_dt.replace(tzinfo=timezone.utc).isoformat()
    else:
        ts = scan_dt.astimezone(timezone.utc).isoformat()
    # Python's isoformat emits +00:00 for UTC; Discord accepts both but Z is canonical.
    ts = ts.replace("+00:00", "Z")

    embeds = [{
        "title":       "Pulse Threat Report",
        "description": description,
        "color":       color,
        "fields":      fields,
        "timestamp":   ts,
    }]
    if report_path:
        embeds[0]["footer"] = {
            "text": f"Full report saved locally at {report_path}"
        }

    # Second embed: top N findings.
    sorted_findings = _sort_by_severity(findings)
    top = sorted_findings[:top_n]
    if top:
        lines = []
        for f in top:
            sev = (f.get("severity") or "LOW").upper()
            rule = f.get("rule") or "Unknown rule"
            desc = f.get("description") or f.get("details") or ""
            lines.append(f"**[{sev}]** {rule} \u2014 {_truncate(desc, 180)}")
        if len(sorted_findings) > top_n:
            lines.append(
                f"*...and {len(sorted_findings) - top_n} more findings.*"
            )
        embeds.append({
            "title":       "Top findings",
            "description": _truncate("\n\n".join(lines), 3800),
            "color":       color,
        })

    content = f"Pulse scan complete \u2014 {sum(counts.values())} finding(s)"
    if hostname:
        content += f" on {hostname}"
    return {"content": content, "embeds": embeds}


def send_discord(webhook_url, findings, *, hostname=None, score=None, grade=None,
                 report_path=None, scan_dt=None, timeout=10):
    """Post a Discord embed summarising `findings`.
    Returns True on success, False on any failure."""
    err = validate_discord_url(webhook_url)
    if err:
        return False
    payload = build_discord_payload(
        findings, hostname=hostname, score=score, grade=grade,
        report_path=report_path, scan_dt=scan_dt,
    )
    return _post_json(webhook_url.strip(), payload, timeout=timeout)


# ---------------------------------------------------------------------------
# Legacy single-URL entry point — kept so the old `webhook:` config block
# continues to work for users who haven't migrated to `delivery:` yet.
# ---------------------------------------------------------------------------

def send_webhook(webhook_config, findings, *, hostname=None, timeout=10,
                 score=None, grade=None, report_path=None, scan_dt=None):
    """Send a webhook using the legacy `webhook:` config block.

    `flavor` in the config overrides auto-detection. Leave it empty to
    let us guess from the URL. Returns True on success."""
    err = validate_webhook_config(webhook_config)
    if err:
        return False

    url = (webhook_config.get("url") or "").strip()
    flavor = ((webhook_config.get("flavor") or "").strip().lower()
              or detect_flavor(url) or "slack")

    if flavor == "discord":
        payload = build_discord_payload(
            findings, hostname=hostname, score=score, grade=grade,
            report_path=report_path, scan_dt=scan_dt,
        )
    else:
        payload = build_slack_payload(
            findings, hostname=hostname, score=score, grade=grade,
            report_path=report_path, scan_dt=scan_dt,
        )
    return _post_json(url, payload, timeout=timeout)
