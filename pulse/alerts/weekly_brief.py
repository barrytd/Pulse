# pulse/alerts/weekly_brief.py
# ----------------------------
# Weekly threat brief: a digest e-mailed to the alert recipient covering
# every scan, finding, and score-change in the trailing N days. Designed
# to be the "Monday-morning recap" that lands in an analyst's inbox so
# they don't have to log in to know if anything changed over the weekend.
#
# This module owns three concerns, in order of dependency:
#   1. compose_weekly_brief()  — pure aggregator over the DB.
#   2. _build_*_body()         — render the dict into HTML + plain text.
#   3. send_weekly_brief()     — SMTP send, mirroring emailer.send_alert().
#
# It is intentionally self-contained: no scheduler, no caller-injected
# state. The API and CLI both call compose_weekly_brief() to read the
# data and send_weekly_brief() to deliver it.

from __future__ import annotations

import smtplib
from collections import Counter
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from pulse import database
from pulse.alerts.emailer import (
    SEVERITY_COLORS,
    validate_email_config,
)


# Maximum rows to render in the digest's "top rules" / "top hosts" /
# "critical findings" sections. Keeps the email scannable on a phone.
_MAX_TOP_RULES = 5
_MAX_TOP_HOSTS = 5
_MAX_CRITICAL  = 5


# ---------------------------------------------------------------------------
# 1. Composer — read the DB and shape the brief
# ---------------------------------------------------------------------------

def compose_weekly_brief(db_path, days=7, now=None):
    """Aggregate scans + findings from the trailing window into a brief dict.

    Parameters
    ----------
    db_path : str
        Path to the SQLite file. Reused as-is by ``database.get_*``.
    days : int
        Window in days (default 7 — "weekly"). Clamped to [1, 365].
    now : datetime | None
        Injectable clock for tests.

    Returns
    -------
    dict
        Shape consumed by ``_build_html_body`` / ``_build_plain_body``::

            {
                "period_days":      int,
                "period_start":     "YYYY-MM-DD",
                "period_end":       "YYYY-MM-DD",
                "scans_run":        int,
                "findings_total":   int,
                "severity_counts":  {CRITICAL, HIGH, MEDIUM, LOW},
                "score_start":      int | None,
                "score_end":        int | None,
                "score_delta":      int | None,
                "top_rules":        [{"rule": str, "count": int, "severity": str}],
                "top_hosts":        [{"host": str, "findings": int, "scans": int}],
                "critical_findings": [findings, max=_MAX_CRITICAL],
            }
    """
    try:
        days = int(days)
    except (TypeError, ValueError):
        days = 7
    days = max(1, min(days, 365))

    now = now or datetime.now()
    period_end   = now.strftime("%Y-%m-%d")
    period_start = (now - timedelta(days=days - 1)).strftime("%Y-%m-%d")

    scans    = database.get_scans_since(db_path, days)    or []
    findings = database.get_findings_since(db_path, days) or []

    # Severity counts. Default keys present even when zero so the renderer
    # always has every cell to draw — no "KeyError on LOW" footguns.
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev = (f.get("severity") or "").upper()
        if sev in sev_counts:
            sev_counts[sev] += 1

    # Score trend: oldest-vs-newest scan that has a non-None score in the
    # window. Compared against scan timestamps, not daily-score rows, so a
    # week with no scans returns (None, None, None) instead of stale data.
    scored = [s for s in scans if s.get("score") is not None]
    if scored:
        score_end   = scored[0]["score"]      # newest scan first
        score_start = scored[-1]["score"]
        score_delta = score_end - score_start
    else:
        score_end = score_start = score_delta = None

    # Top rules — count by rule name, keep the worst severity seen so the
    # badge colour reflects how serious the rule is, not the last hit.
    rule_counter = Counter()
    rule_worst   = {}
    sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    for f in findings:
        rule = f.get("rule") or "Unknown"
        rule_counter[rule] += 1
        sev = (f.get("severity") or "LOW").upper()
        if sev_rank.get(sev, 0) > sev_rank.get(rule_worst.get(rule, "LOW"), 0):
            rule_worst[rule] = sev
    top_rules = [
        {"rule": r, "count": c, "severity": rule_worst.get(r, "LOW")}
        for r, c in rule_counter.most_common(_MAX_TOP_RULES)
    ]

    # Top hosts — finding count per hostname (or filename when hostname is
    # blank, e.g. uploaded .evtx with no source machine identified).
    host_findings = Counter()
    host_scans    = Counter()
    for s in scans:
        host = (s.get("hostname") or s.get("filename") or "unknown").strip() or "unknown"
        host_findings[host] += int(s.get("total_findings") or 0)
        host_scans[host]    += 1
    top_hosts = [
        {"host": h, "findings": host_findings[h], "scans": host_scans[h]}
        for h, _ in host_findings.most_common(_MAX_TOP_HOSTS)
        if host_findings[h] > 0
    ]

    # Critical findings preview — first N CRITICAL rows, already sorted
    # newest-scan first by the underlying query.
    critical_preview = [
        f for f in findings if (f.get("severity") or "").upper() == "CRITICAL"
    ][:_MAX_CRITICAL]

    return {
        "period_days":       days,
        "period_start":      period_start,
        "period_end":        period_end,
        "scans_run":         len(scans),
        "findings_total":    len(findings),
        "severity_counts":   sev_counts,
        "score_start":       score_start,
        "score_end":         score_end,
        "score_delta":       score_delta,
        "top_rules":         top_rules,
        "top_hosts":         top_hosts,
        "critical_findings": critical_preview,
    }


# ---------------------------------------------------------------------------
# 2. Renderers — HTML + plain text
# ---------------------------------------------------------------------------

def _build_subject(brief):
    crit = brief["severity_counts"]["CRITICAL"]
    high = brief["severity_counts"]["HIGH"]
    days = brief["period_days"]
    if crit > 0:
        return f"[Pulse] Weekly brief — {crit} CRITICAL, {high} HIGH (last {days}d)"
    if high > 0:
        return f"[Pulse] Weekly brief — {high} HIGH (last {days}d)"
    if brief["findings_total"] > 0:
        return f"[Pulse] Weekly brief — {brief['findings_total']} findings (last {days}d)"
    return f"[Pulse] Weekly brief — all clear (last {days}d)"


def _delta_arrow(delta):
    if delta is None or delta == 0:
        return ""
    return "+" + str(delta) if delta > 0 else str(delta)


def _build_plain_body(brief):
    sev = brief["severity_counts"]
    lines = []
    lines.append(f"Pulse Weekly Threat Brief — {brief['period_start']} to {brief['period_end']}")
    lines.append("")
    lines.append(f"Scans run:      {brief['scans_run']}")
    lines.append(f"Findings total: {brief['findings_total']}")
    lines.append(
        f"Severity:       CRITICAL={sev['CRITICAL']}  HIGH={sev['HIGH']}  "
        f"MEDIUM={sev['MEDIUM']}  LOW={sev['LOW']}"
    )
    if brief["score_end"] is not None:
        delta = _delta_arrow(brief["score_delta"])
        delta_str = f" ({delta})" if delta else ""
        lines.append(f"Score trend:    {brief['score_start']} -> {brief['score_end']}{delta_str}")
    else:
        lines.append("Score trend:    no scored scans in window")
    lines.append("")

    if brief["top_rules"]:
        lines.append("Top triggered rules:")
        for r in brief["top_rules"]:
            lines.append(f"  - [{r['severity']}] {r['rule']} ({r['count']})")
        lines.append("")
    if brief["top_hosts"]:
        lines.append("Top hosts by findings:")
        for h in brief["top_hosts"]:
            lines.append(f"  - {h['host']}: {h['findings']} findings across {h['scans']} scan(s)")
        lines.append("")
    if brief["critical_findings"]:
        lines.append("Recent critical findings:")
        for f in brief["critical_findings"]:
            ts = f.get("timestamp") or f.get("scanned_at") or ""
            host = f.get("hostname") or f.get("filename") or "?"
            lines.append(f"  - {ts} {host} — {f.get('rule', 'Unknown')}")
        lines.append("")
    lines.append("— Pulse")
    return "\n".join(lines)


def _build_html_body(brief):
    sev = brief["severity_counts"]

    def _sev_pill(label, count):
        c = SEVERITY_COLORS.get(label, {"bg": "#888", "text": "#fff"})
        return (
            f'<span style="display:inline-block; padding:4px 10px; border-radius:12px; '
            f'background:{c["bg"]}; color:{c["text"]}; font-size:12px; font-weight:600; '
            f'margin-right:6px;">{label} {count}</span>'
        )

    pills = "".join(_sev_pill(k, sev[k]) for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW"))

    if brief["score_end"] is not None:
        delta = brief["score_delta"] or 0
        if delta > 0:
            arrow_color = "#10b981"; arrow = "&#9650;"
        elif delta < 0:
            arrow_color = "#ef4444"; arrow = "&#9660;"
        else:
            arrow_color = "#6b7280"; arrow = "&#9472;"
        score_html = (
            f'<div style="font-size:14px; color:#374151;">Score trend: '
            f'<strong>{brief["score_start"]}</strong> &rarr; '
            f'<strong>{brief["score_end"]}</strong> '
            f'<span style="color:{arrow_color}; font-weight:600;">{arrow} {abs(delta)}</span></div>'
        )
    else:
        score_html = '<div style="font-size:14px; color:#6b7280;">No scored scans in this window.</div>'

    rules_html = ""
    if brief["top_rules"]:
        rows = "".join(
            f'<tr><td style="padding:6px 8px; border-bottom:1px solid #e5e7eb;">'
            f'<span style="display:inline-block; padding:2px 8px; border-radius:10px; '
            f'background:{SEVERITY_COLORS.get(r["severity"], {"bg":"#888"})["bg"]}; '
            f'color:#fff; font-size:11px; font-weight:600; margin-right:8px;">'
            f'{r["severity"]}</span>{r["rule"]}</td>'
            f'<td style="padding:6px 8px; border-bottom:1px solid #e5e7eb; '
            f'text-align:right; color:#111827; font-weight:600;">{r["count"]}</td></tr>'
            for r in brief["top_rules"]
        )
        rules_html = (
            '<h3 style="margin:24px 0 8px; color:#111827; font-size:14px;">Top triggered rules</h3>'
            f'<table style="width:100%; border-collapse:collapse; font-size:13px;">{rows}</table>'
        )

    hosts_html = ""
    if brief["top_hosts"]:
        rows = "".join(
            f'<tr><td style="padding:6px 8px; border-bottom:1px solid #e5e7eb; '
            f'font-family:ui-monospace, monospace; font-size:12px;">{h["host"]}</td>'
            f'<td style="padding:6px 8px; border-bottom:1px solid #e5e7eb; '
            f'text-align:right; color:#111827;">{h["findings"]}</td>'
            f'<td style="padding:6px 8px; border-bottom:1px solid #e5e7eb; '
            f'text-align:right; color:#6b7280;">{h["scans"]} scan{"s" if h["scans"] != 1 else ""}</td></tr>'
            for h in brief["top_hosts"]
        )
        hosts_html = (
            '<h3 style="margin:24px 0 8px; color:#111827; font-size:14px;">Top hosts</h3>'
            f'<table style="width:100%; border-collapse:collapse; font-size:13px;">'
            f'<thead><tr><th style="text-align:left; padding:6px 8px; '
            f'color:#6b7280; font-size:11px; text-transform:uppercase;">Host</th>'
            f'<th style="text-align:right; padding:6px 8px; color:#6b7280; '
            f'font-size:11px; text-transform:uppercase;">Findings</th>'
            f'<th style="text-align:right; padding:6px 8px; color:#6b7280; '
            f'font-size:11px; text-transform:uppercase;">Activity</th></tr></thead>'
            f'<tbody>{rows}</tbody></table>'
        )

    crit_html = ""
    if brief["critical_findings"]:
        rows = "".join(
            f'<li style="margin:6px 0; color:#374151; font-size:13px;">'
            f'<strong>{(f.get("rule") or "Unknown")}</strong> &middot; '
            f'<span style="color:#6b7280;">'
            f'{f.get("hostname") or f.get("filename") or "?"} &middot; '
            f'{f.get("timestamp") or f.get("scanned_at") or ""}</span></li>'
            for f in brief["critical_findings"]
        )
        crit_html = (
            '<h3 style="margin:24px 0 8px; color:#b91c1c; font-size:14px;">Recent critical findings</h3>'
            f'<ul style="margin:0; padding-left:20px;">{rows}</ul>'
        )

    return (
        '<!doctype html><html><body style="margin:0; padding:0; background:#f3f4f6; '
        'font-family:-apple-system, Segoe UI, sans-serif; color:#111827;">'
        '<div style="max-width:640px; margin:24px auto; background:#ffffff; '
        'border:1px solid #e5e7eb; border-radius:8px; overflow:hidden;">'
        '<div style="padding:18px 22px; border-bottom:1px solid #e5e7eb; '
        'background:#0b1220; color:#f3f4f6;">'
        '<div style="font-size:11px; letter-spacing:1px; text-transform:uppercase; '
        'color:#9ca3af; margin-bottom:4px;">Pulse weekly brief</div>'
        f'<div style="font-size:18px; font-weight:600;">'
        f'{brief["period_start"]} &rarr; {brief["period_end"]}</div></div>'
        '<div style="padding:22px;">'
        '<div style="display:grid; grid-template-columns:1fr 1fr; gap:16px; margin-bottom:16px;">'
        '<div>'
        '<div style="font-size:11px; color:#6b7280; text-transform:uppercase; letter-spacing:0.5px;">'
        'Scans</div>'
        f'<div style="font-size:24px; font-weight:600; color:#111827;">{brief["scans_run"]}</div>'
        '</div>'
        '<div>'
        '<div style="font-size:11px; color:#6b7280; text-transform:uppercase; letter-spacing:0.5px;">'
        'Findings</div>'
        f'<div style="font-size:24px; font-weight:600; color:#111827;">{brief["findings_total"]}</div>'
        '</div>'
        '</div>'
        f'<div style="margin-bottom:14px;">{pills}</div>'
        f'{score_html}'
        f'{rules_html}'
        f'{hosts_html}'
        f'{crit_html}'
        '<p style="margin-top:24px; font-size:11px; color:#9ca3af;">'
        'You\'re receiving this because Pulse is configured to send weekly briefs '
        'to this address. Disable from Settings &rarr; Notifications.</p>'
        '</div></div></body></html>'
    )


# ---------------------------------------------------------------------------
# 3. Send — SMTP delivery, mirrors emailer.send_alert() shape
# ---------------------------------------------------------------------------

def send_weekly_brief(email_config, recipient, brief):
    """Email a composed brief. Returns True on send, False otherwise.

    Mirrors ``emailer.send_alert`` so an operator who already has SMTP
    working for alerts gets the brief through the same pipe with no
    additional config. The recipient comes from ``alerts.recipient`` or
    falls back to ``email.recipient`` — the API layer resolves that and
    passes it in here, so this function only needs the resolved address.
    """
    if not recipient:
        return False
    error = validate_email_config(email_config)
    if error:
        print(f"  [!] Weekly brief not sent: {error}")
        return False

    smtp_host = email_config["smtp_host"]
    smtp_port = int(email_config["smtp_port"])
    sender    = email_config["sender"]
    password  = email_config["password"]

    msg = MIMEMultipart("alternative")
    msg["From"]    = sender
    msg["To"]      = recipient
    msg["Subject"] = _build_subject(brief)
    msg.attach(MIMEText(_build_plain_body(brief), "plain"))
    msg.attach(MIMEText(_build_html_body(brief),  "html"))

    try:
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(sender, password)
            server.sendmail(sender, [recipient], msg.as_string())
        return True
    except smtplib.SMTPAuthenticationError:
        print("  [!] Weekly brief not sent: SMTP authentication failed.")
    except smtplib.SMTPConnectError:
        print("  [!] Weekly brief not sent: could not connect to SMTP server.")
    except Exception as exc:  # noqa: BLE001
        print(f"  [!] Weekly brief not sent: {exc}")
    return False
