# pulse/emailer.py
# -----------------
# Handles sending the finished report via email.
#
# HOW EMAIL WORKS IN PYTHON:
# Python has two built-in modules for email:
#   - smtplib: handles the actual connection and sending (like a postal worker)
#   - email:   handles building the message (subject, body, attachments)
#
# The flow is:
#   1. Build a MIMEMultipart("alternative") message with two body versions:
#        - text/plain  (fallback for clients that can't render HTML)
#        - text/html   (the rich version shown by Gmail, Outlook, Apple Mail, etc.)
#   2. Connect to the SMTP server with TLS encryption
#   3. Log in and send
#
# WHY "alternative"?
#   "alternative" tells the email client "pick the best version you can render".
#   Email clients read the parts last-to-first and render the richest one they
#   support, so HTML goes last.
#
# WHY INLINE CSS?
#   Email clients strip <style> blocks and ignore class-based CSS.
#   Every style rule must be written directly on the element as style="...".

import os
import socket
import smtplib
from datetime import datetime
from pathlib import Path
from email.mime.application import MIMEApplication  # PDF attachment part
from email.mime.multipart import MIMEMultipart  # Container: holds text + HTML
from email.mime.text import MIMEText            # Plain text / HTML body parts


# ---------------------------------------------------------------------------
# Severity colour palette — used in badges and alert bar accent
# ---------------------------------------------------------------------------

SEVERITY_COLORS = {
    "CRITICAL": {"bg": "#c0392b", "text": "#ffffff"},
    "HIGH":     {"bg": "#e67e22", "text": "#ffffff"},
    "MEDIUM":   {"bg": "#f1c40f", "text": "#333333"},
    "LOW":      {"bg": "#27ae60", "text": "#ffffff"},
}

# Sort order for findings: highest severity first
_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

# Rank -> severity lookup used when comparing against the alert threshold.
# "HIGH" has rank 1, so finding_rank <= threshold_rank means the finding
# is at or above the threshold (remember: lower number = higher severity).
_SEVERITY_RANK = _SEVERITY_ORDER

# Maximum findings shown in the email body
_MAX_FINDINGS_SHOWN = 3

# Maximum findings listed inside an alert email. Alerts are meant to be
# terse — "something bad happened, here's a taste" — not the full report.
_MAX_ALERT_FINDINGS_SHOWN = 5


def _header_color(severity_counts):
    """Top-border accent colour and alert bar left-border for the email."""
    if severity_counts.get("CRITICAL", 0) > 0:
        return "#c0392b"   # red
    if severity_counts.get("HIGH", 0) > 0:
        return "#e67e22"   # orange
    if severity_counts.get("MEDIUM", 0) > 0:
        return "#f1c40f"   # yellow
    return "#27ae60"       # green (all clear)


def _alert_title(severity_counts):
    """One-line severity label for the alert bar heading."""
    if severity_counts.get("CRITICAL", 0) > 0:
        return "Critical severity alert"
    if severity_counts.get("HIGH", 0) > 0:
        return "High severity alert"
    if severity_counts.get("MEDIUM", 0) > 0:
        return "Medium severity alert"
    if severity_counts.get("LOW", 0) > 0:
        return "Low severity alert"
    return "Scan complete"


def _context_summary(severity_counts):
    """
    Returns a 1-2 sentence plain-English context blurb based on the highest
    severity level present.  Used in the plain-text fallback body.
    """
    if severity_counts.get("CRITICAL", 0) > 0:
        return (
            "Active attack patterns were detected. "
            "Immediate investigation is recommended."
        )
    if severity_counts.get("HIGH", 0) > 0:
        return (
            "Suspicious activity was detected that requires review. "
            "No active attack chains identified."
        )
    if severity_counts.get("MEDIUM", 0) > 0 or severity_counts.get("LOW", 0) > 0:
        return "Low-risk activity was flagged. Review at your earliest convenience."
    return "No suspicious activity was detected during this scan."


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def validate_email_config(email_config):
    """
    Checks that the email config has all required fields filled in.

    Parameters:
        email_config (dict): The "email" section from pulse.yaml.

    Returns:
        str or None: An error message string if invalid, None if all good.
    """
    if not email_config:
        return "No email section found in pulse.yaml."

    required = ["smtp_host", "smtp_port", "sender", "recipient", "password"]
    for field in required:
        value = email_config.get(field)
        if not value:
            return (
                f"Email config is missing '{field}'. "
                f"Fill in the email section of pulse.yaml."
            )

    return None


def filter_alert_findings(findings, threshold):
    """
    Returns only the findings whose severity is at or above the threshold.

    Severity ranks go: CRITICAL(0) < HIGH(1) < MEDIUM(2) < LOW(3). Lower
    number = more serious. A finding passes the gate if its rank is <=
    the threshold's rank (i.e. it is as severe or more severe).

    Parameters:
        findings (list):  Finding dicts, each with a "severity" key.
        threshold (str):  "CRITICAL", "HIGH", "MEDIUM", or "LOW".

    Returns:
        list: Subset of findings that meet or exceed the threshold.
    """
    threshold_rank = _SEVERITY_RANK.get((threshold or "HIGH").upper(), 1)
    result = []
    for f in findings:
        sev = (f.get("severity") or "LOW").upper()
        if _SEVERITY_RANK.get(sev, 3) <= threshold_rank:
            result.append(f)
    return result


# ---------------------------------------------------------------------------
# PDF attachment helpers
# ---------------------------------------------------------------------------

def _build_pdf_bytes(findings, scan_meta):
    """Render a PDF report for these findings. Returns bytes or None on failure.

    We never let a PDF failure block the email — the caller is expected to
    drop a note into the body instead."""
    try:
        from pulse.reports.pdf_report import build_pdf
        return build_pdf(findings, scan_meta=scan_meta)
    except Exception:
        return None


def _pdf_filename(scan_meta, scan_dt):
    """Name the attachment: pulse-report-YYYY-MM-DD-scan<id>.pdf.

    Falls back to a date-only filename when the caller has no scan_id
    (e.g. live monitor alerts that don't correspond to a saved scan row).
    """
    date = (scan_dt or datetime.now()).strftime("%Y-%m-%d")
    scan_id = (scan_meta or {}).get("scan_id") or (scan_meta or {}).get("id")
    if scan_id:
        return f"pulse-report-{date}-scan{scan_id}.pdf"
    return f"pulse-report-{date}.pdf"


def _wrap_with_pdf(inner, pdf_bytes, filename):
    """Wrap an `alternative` text/html container in a `mixed` multipart
    that also carries the PDF. The text+html alternative stays intact so
    email clients keep rendering the rich body."""
    outer = MIMEMultipart("mixed")
    # Copy headers (From/To/Subject etc.) from the inner payload so the
    # caller can keep setting them on the original MIMEMultipart. Skip
    # Content-Type / MIME-Version — those belong to each part and
    # duplicating them on the outer breaks Python 3.14's generator
    # (it follows the second Content-Type and tries to flatten the
    # multipart list payload as text).
    _skip = {"content-type", "mime-version"}
    for key, value in list(inner.items()):
        if key.lower() in _skip:
            continue
        outer[key] = value
        del inner[key]
    outer.attach(inner)

    attachment = MIMEApplication(pdf_bytes, _subtype="pdf")
    attachment.add_header("Content-Disposition", "attachment", filename=filename)
    outer.attach(attachment)
    return outer


def send_alert(email_config, alert_config, triggering_findings,
               scan_dt=None, db_path=None, pdf_bytes=None, pdf_filename=None,
               pdf_failure_note=False):
    """
    Sends a short threshold-tripped alert email.

    This is NOT the full report. It's a terse "wake up" message listing
    only the findings that tripped the threshold. SMTP credentials come
    from email_config (same server used by --email). Recipient comes
    from alert_config.recipient, or falls back to email.recipient.

    Cooldown handling:
      - Before sending, the caller should have already filtered out
        rules that were recently alerted (use was_recently_alerted()).
      - After a successful send, the caller should record_alert() for
        each unique rule in triggering_findings.
      - We don't do the cooldown check here because the caller may want
        to send one email covering several rules; letting this function
        decide "skip" would make that harder.

    Parameters:
        email_config (dict):          SMTP credentials (smtp_host, sender, etc.)
        alert_config (dict):          alerts section from pulse.yaml
        triggering_findings (list):   Findings at or above threshold.
        scan_dt (datetime):           When the scan ran. Defaults to now.
        db_path (str):                Unused here — reserved for future use.

    Returns:
        bool: True if sent, False if not (config missing, SMTP error, etc.)
    """
    if not triggering_findings:
        return False

    error = validate_email_config(email_config)
    if error:
        print(f"  [!] Alert not sent: {error}")
        return False

    smtp_host = email_config["smtp_host"]
    smtp_port = int(email_config["smtp_port"])
    sender    = email_config["sender"]
    password  = email_config["password"]

    # Alert recipient overrides report recipient. If alerts.recipient is
    # null/missing in pulse.yaml, fall back to the email.recipient field.
    alert_recipient = (alert_config or {}).get("recipient") or email_config.get("recipient")
    if not alert_recipient:
        print("  [!] Alert not sent: no recipient configured.")
        return False

    if scan_dt is None:
        scan_dt = datetime.now()

    hostname = _get_hostname()

    # Highest severity in this alert drives the subject and accent colour.
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in triggering_findings:
        sev = (f.get("severity") or "LOW").upper()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    inner = MIMEMultipart("alternative")
    inner["From"]    = sender
    inner["To"]      = alert_recipient
    inner["Subject"] = _build_alert_subject(severity_counts, len(triggering_findings), hostname)

    plain = _build_alert_plain_body(severity_counts, triggering_findings, hostname, scan_dt,
                                    pdf_failed=pdf_failure_note)
    html  = _build_alert_html_body(severity_counts, triggering_findings, hostname, scan_dt,
                                   pdf_failed=pdf_failure_note)

    inner.attach(MIMEText(plain, "plain"))
    inner.attach(MIMEText(html,  "html"))

    msg = _wrap_with_pdf(inner, pdf_bytes, pdf_filename) if pdf_bytes else inner

    try:
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(sender, password)
            server.sendmail(sender, alert_recipient, msg.as_string())
        return True

    except smtplib.SMTPAuthenticationError:
        print("  [!] Alert failed: SMTP authentication error. Check pulse.yaml credentials.")
        return False
    except smtplib.SMTPConnectError:
        print(f"  [!] Alert failed: could not connect to {smtp_host}:{smtp_port}.")
        return False
    except Exception as e:
        print(f"  [!] Alert failed: {e}")
        return False


def _severity_counts(findings):
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings or []:
        sev = (f.get("severity") or "LOW").upper()
        if sev in counts:
            counts[sev] += 1
    return counts


def dispatch_alerts(db_path, findings, email_config, alert_config,
                    webhook_config=None, delivery_config=None, scan_meta=None):
    """
    Threshold-filter, cooldown-check, and fan out to every enabled channel.

    Single entry point used by:
      - CLI scan (main.py)
      - /api/scan upload + /api/scan/system
      - scheduled_scan runner
      - live-monitor loop

    Flow:
      1. Gate on alerts.enabled.
      2. Apply global alerts.threshold and cooldown to build `fresh` list.
      3. For each delivery channel (email / slack / discord):
         - check `delivery.<channel>.enabled`
         - apply per-channel `critical_only` tightening
         - send; per-channel failures never block the others
      4. Record an alert_log row per rule if ANY channel succeeded.

    Parameters:
        db_path (str | None):           SQLite path; None skips cooldown + record.
        findings (list):                All findings from the scan.
        email_config (dict):            email section of pulse.yaml (SMTP).
        alert_config (dict):            alerts section of pulse.yaml.
        webhook_config (dict | None):   Legacy single-URL webhook block — only
                                        used when delivery_config is absent so
                                        old pulse.yaml configs keep working.
        delivery_config (dict | None):  New delivery.{email,slack,discord} block.
        scan_meta (dict | None):        Optional scan context passed to the
                                        email (PDF filename) and webhooks
                                        (host/score/grade/report_path).

    Returns dict with:
        enabled, threshold, over_threshold, skipped_rules,
        fresh, sent (email), webhook_sent (any webhook), slack_sent,
        discord_sent, pdf_attached, recipient.
    """
    result = {
        "enabled":        False,
        "threshold":      None,
        "over_threshold": 0,
        "skipped_rules":  [],
        "fresh":          0,
        "sent":           False,
        "webhook_sent":   False,
        "slack_sent":     False,
        "discord_sent":   False,
        "pdf_attached":   False,
        "recipient":      None,
    }

    alert_config = alert_config or {}
    if not alert_config.get("enabled"):
        return result
    result["enabled"] = True

    if not findings:
        return result

    threshold = alert_config.get("threshold", "HIGH")
    cooldown  = int(alert_config.get("cooldown_minutes", 60))
    result["threshold"] = threshold

    alertable = filter_alert_findings(findings, threshold)
    result["over_threshold"] = len(alertable)
    if not alertable:
        return result

    from pulse.database import record_alert, was_recently_alerted

    fresh = []
    skipped = set()
    for f in alertable:
        rule = f.get("rule", "")
        if db_path and was_recently_alerted(db_path, rule, cooldown):
            skipped.add(rule)
        else:
            fresh.append(f)

    result["skipped_rules"] = sorted(skipped)
    result["fresh"] = len(fresh)
    if not fresh:
        return result

    # --- Per-channel config resolution --------------------------------
    # If `delivery` is supplied, it's authoritative. Otherwise fall back
    # to legacy email/webhook flags so pre-delivery pulse.yaml files and
    # the existing test suite keep working.
    delivery = delivery_config or {}
    email_cfg = delivery.get("email") or {}
    slack_cfg = delivery.get("slack") or {}
    disc_cfg  = delivery.get("discord") or {}

    legacy_mode = delivery_config is None

    email_enabled = email_cfg.get("enabled", True) if not legacy_mode else True
    # Per-channel critical-only tightens the global threshold further.
    def _apply_channel_threshold(only):
        if not only:
            return fresh
        return filter_alert_findings(fresh, "CRITICAL")

    email_fresh = _apply_channel_threshold(email_cfg.get("critical_only"))
    slack_fresh = _apply_channel_threshold(slack_cfg.get("critical_only"))
    disc_fresh  = _apply_channel_threshold(disc_cfg.get("critical_only"))

    meta = scan_meta or {}
    scan_dt     = meta.get("scan_dt") or datetime.now()
    hostname    = meta.get("hostname") or _get_hostname()
    score       = meta.get("score")
    grade       = meta.get("grade")
    report_path = meta.get("report_path")

    # --- Email -------------------------------------------------------
    email_ok = False
    if email_enabled and email_fresh:
        pdf_bytes = None
        pdf_filename = None
        pdf_failed = False
        if email_cfg.get("attach_pdf", True):
            pdf_filename = _pdf_filename(meta, scan_dt)
            pdf_bytes = _build_pdf_bytes(email_fresh, meta)
            if pdf_bytes is None:
                pdf_failed = True
        email_ok = send_alert(
            email_config, alert_config, email_fresh,
            scan_dt=scan_dt,
            pdf_bytes=pdf_bytes, pdf_filename=pdf_filename,
            pdf_failure_note=pdf_failed,
        )
        result["pdf_attached"] = bool(pdf_bytes and email_ok)
    result["sent"] = bool(email_ok)
    result["recipient"] = (alert_config.get("recipient")
                           or (email_config or {}).get("recipient"))

    # --- Slack -------------------------------------------------------
    slack_ok = False
    if not legacy_mode:
        if slack_cfg.get("enabled") and slack_fresh:
            from pulse.alerts.webhook import send_slack
            slack_ok = send_slack(
                slack_cfg.get("webhook_url"), slack_fresh,
                hostname=hostname, score=score, grade=grade,
                report_path=report_path, scan_dt=scan_dt,
            )
    result["slack_sent"] = bool(slack_ok)

    # --- Discord -----------------------------------------------------
    discord_ok = False
    if not legacy_mode:
        if disc_cfg.get("enabled") and disc_fresh:
            from pulse.alerts.webhook import send_discord
            discord_ok = send_discord(
                disc_cfg.get("webhook_url"), disc_fresh,
                hostname=hostname, score=score, grade=grade,
                report_path=report_path, scan_dt=scan_dt,
            )
    result["discord_sent"] = bool(discord_ok)

    # --- Legacy single-URL webhook fallback --------------------------
    legacy_ok = False
    if legacy_mode and webhook_config and webhook_config.get("enabled"):
        from pulse.alerts.webhook import send_webhook
        legacy_ok = send_webhook(
            webhook_config, fresh,
            hostname=hostname, score=score, grade=grade,
            report_path=report_path, scan_dt=scan_dt,
        )

    result["webhook_sent"] = bool(slack_ok or discord_ok or legacy_ok)

    # Record per-rule cooldown if anything delivered.
    any_ok = email_ok or slack_ok or discord_ok or legacy_ok
    if any_ok and db_path:
        unique_rules = {}
        for f in fresh:
            unique_rules[f.get("rule", "")] = f.get("severity")
        for rule, sev in unique_rules.items():
            record_alert(db_path, rule, severity=sev)

    return result


def _build_alert_subject(severity_counts, total, hostname):
    """Terse subject line. Example: '[PULSE ALERT] HIGH — 3 findings on DESKTOP-PC'"""
    if severity_counts.get("CRITICAL", 0) > 0:
        level = "CRITICAL"
    elif severity_counts.get("HIGH", 0) > 0:
        level = "HIGH"
    elif severity_counts.get("MEDIUM", 0) > 0:
        level = "MEDIUM"
    else:
        level = "LOW"
    suffix = f" on {hostname}" if hostname and hostname != "Unknown" else ""
    noun = "finding" if total == 1 else "findings"
    return f"[PULSE ALERT] {level} - {total} {noun}{suffix}"


def _build_alert_plain_body(severity_counts, findings, hostname, scan_dt, pdf_failed=False):
    """Plain-text alert body. Short: host, time, top N rules tripped."""
    sorted_f = sorted(findings, key=lambda f: _SEVERITY_ORDER.get(f.get("severity", "LOW"), 3))
    shown    = sorted_f[:_MAX_ALERT_FINDINGS_SHOWN]
    overflow = len(sorted_f) - len(shown)
    stamp    = scan_dt.strftime("%b %d, %Y %H:%M") if hasattr(scan_dt, "strftime") else str(scan_dt)

    lines = [
        "PULSE ALERT",
        "=" * 40,
        f"Host : {hostname}",
        f"Time : {stamp}",
        f"Total: {len(findings)} finding(s) at or above threshold",
        "",
        "Breakdown:",
        f"  CRITICAL : {severity_counts.get('CRITICAL', 0)}",
        f"  HIGH     : {severity_counts.get('HIGH', 0)}",
        f"  MEDIUM   : {severity_counts.get('MEDIUM', 0)}",
        f"  LOW      : {severity_counts.get('LOW', 0)}",
        "",
        "Triggering findings:",
    ]
    for f in shown:
        sev  = f.get("severity", "LOW")
        rule = f.get("rule", "Unknown")
        det  = (f.get("details") or f.get("description") or "").strip()
        if len(det) > 140:
            det = det[:137] + "..."
        lines.append(f"  [{sev}] {rule}")
        if det:
            lines.append(f"    {det}")
    if overflow > 0:
        lines.append(f"  ...and {overflow} more.")
    lines += [
        "",
        "Run `python main.py --format html` for the full report.",
    ]
    if pdf_failed:
        lines.append("")
        lines.append("NOTE: PDF attachment could not be generated.")
    lines += ["", "-- Pulse"]
    return "\n".join(lines)


def _build_alert_html_body(severity_counts, findings, hostname, scan_dt, pdf_failed=False):
    """Compact HTML alert body. Same palette as send_report but smaller."""
    accent = _header_color(severity_counts)
    sorted_f = sorted(findings, key=lambda f: _SEVERITY_ORDER.get(f.get("severity", "LOW"), 3))
    shown    = sorted_f[:_MAX_ALERT_FINDINGS_SHOWN]
    overflow = len(sorted_f) - len(shown)
    stamp    = scan_dt.strftime("%b %d, %Y %H:%M") if hasattr(scan_dt, "strftime") else str(scan_dt)

    rows = ""
    for i, f in enumerate(shown, start=1):
        sev    = f.get("severity", "LOW")
        colors = SEVERITY_COLORS.get(sev, SEVERITY_COLORS["LOW"])
        rule   = f.get("rule", "Unknown")
        det    = (f.get("details") or f.get("description") or "").strip()
        if len(det) > 180:
            det = det[:177] + "..."
        border = "border-bottom:1px solid #eeeeee;" if i < len(shown) or overflow > 0 else ""
        rows += f"""
        <tr><td style="padding:10px 0; {border}">
          <span style="background:{colors['bg']}; color:{colors['text']};
                       font-family:Arial,sans-serif; font-size:10px;
                       font-weight:bold; letter-spacing:1px;
                       padding:3px 8px; border-radius:4px; margin-right:10px;">
            {sev}
          </span>
          <span style="font-family:Arial,sans-serif; font-size:13px;
                       font-weight:bold; color:#222222;">{rule}</span>
          <div style="font-family:Arial,sans-serif; font-size:12px;
                      color:#666666; margin:4px 0 0 0;">{det}</div>
        </td></tr>"""

    overflow_line = ""
    if overflow > 0:
        overflow_line = f"""
        <tr><td style="padding-top:10px; font-family:Arial,sans-serif;
                       font-size:12px; color:#888888; font-style:italic;">
          ...and {overflow} more finding{"s" if overflow != 1 else ""}.
        </td></tr>"""

    return f"""<!DOCTYPE html>
<html><body style="margin:0; padding:0; background:#f0f0f0;">
  <table width="100%" cellpadding="0" cellspacing="0" border="0"
         style="background:#f0f0f0; padding:24px 0;">
    <tr><td align="center">
      <table width="560" cellpadding="0" cellspacing="0" border="0"
             style="background:#ffffff; border-radius:6px; overflow:hidden;
                    border:1px solid #e1e4e8; border-top:4px solid {accent};">
        <tr><td style="padding:20px 28px 8px 28px;">
          <div style="font-family:Arial,sans-serif; font-size:18px;
                      font-weight:bold; color:#c0392b; letter-spacing:2px;">
            PULSE ALERT
          </div>
          <div style="font-family:Arial,sans-serif; font-size:12px;
                      color:#666666; margin-top:4px;">
            {hostname} &middot; {stamp} &middot; {len(findings)} finding(s)
          </div>
        </td></tr>
        <tr><td style="padding:8px 28px 20px 28px;">
          <table width="100%" cellpadding="0" cellspacing="0" border="0">
            {rows}
            {overflow_line}
          </table>
        </td></tr>
        <tr><td style="padding:14px 28px; background:#f6f8fa;
                       border-top:1px solid #e1e4e8;
                       font-family:Arial,sans-serif; font-size:11px;
                       color:#888888;">
          Run <code>python main.py --format html</code> for the full report.
          {"<br/><span style='color:#c0392b;'>PDF attachment could not be generated.</span>" if pdf_failed else ""}
        </td></tr>
      </table>
    </td></tr>
  </table>
</body></html>"""


def send_report(email_config, severity_counts, total_findings,
                findings=None, scan_dt=None, report_path=None,
                pdf_bytes=None, pdf_filename=None, pdf_failure_note=False):
    """
    Sends the full report as an HTML email body (no attachment).

    The HTML body shows the top 3 findings sorted by severity, with an
    overflow note if more exist.  The "Review findings" button links to
    the local HTML report via a file:// URL.  If the saved report is not
    HTML, a companion HTML file is generated automatically so the link
    is always valid.

    Parameters:
        email_config (dict):     The "email" section from pulse.yaml.
        severity_counts (dict):  How many findings per severity level.
        total_findings (int):    Total number of findings.
        findings (list):         List of finding dicts to render.
        scan_dt (datetime):      When the scan ran. Defaults to now.
        report_path (str):       Path to the saved report file. Used to
                                 build the "Review findings" file:// URL.

    Returns:
        bool: True if sent successfully, False if an error occurred.
    """

    # --- VALIDATE CONFIG ---
    error = validate_email_config(email_config)
    if error:
        print(f"  [!] Email not sent: {error}")
        return False

    smtp_host  = email_config["smtp_host"]
    smtp_port  = int(email_config["smtp_port"])
    sender     = email_config["sender"]
    recipient  = email_config["recipient"]
    password   = email_config["password"]

    if scan_dt is None:
        scan_dt = datetime.now()

    hostname = _get_hostname()

    # Build the file:// URL for the "Review findings" button.
    # _ensure_html_report generates an HTML file if one doesn't exist yet.
    html_path  = _ensure_html_report(report_path, findings or [], scan_dt)
    report_url = Path(os.path.abspath(html_path)).as_uri()

    # --- BUILD THE MESSAGE ---
    inner = MIMEMultipart("alternative")
    inner["From"]    = sender
    inner["To"]      = recipient
    inner["Subject"] = _build_subject(severity_counts, total_findings)

    plain = _build_plain_body(severity_counts, total_findings,
                              pdf_failed=pdf_failure_note)
    html  = _build_html_body(severity_counts, total_findings,
                             findings or [], scan_dt, hostname,
                             report_url=report_url,
                             pdf_failed=pdf_failure_note)

    inner.attach(MIMEText(plain, "plain"))
    inner.attach(MIMEText(html,  "html"))

    msg = _wrap_with_pdf(inner, pdf_bytes, pdf_filename) if pdf_bytes else inner

    # --- SEND ---
    try:
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(sender, password)
            server.sendmail(sender, recipient, msg.as_string())

        return True

    except smtplib.SMTPAuthenticationError:
        print("  [!] Email failed: Authentication error.")
        print("      Check your sender address and password in pulse.yaml.")
        print("      Gmail users: use an App Password from myaccount.google.com/apppasswords")
        return False

    except smtplib.SMTPConnectError:
        print(f"  [!] Email failed: Could not connect to {smtp_host}:{smtp_port}.")
        print("      Check smtp_host and smtp_port in pulse.yaml.")
        return False

    except Exception as e:
        print(f"  [!] Email failed: {e}")
        return False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_hostname():
    """Returns the machine hostname, or 'Unknown' if it can't be determined."""
    try:
        return socket.gethostname()
    except Exception:
        return "Unknown"


def _ensure_html_report(report_path, findings, scan_dt):
    """
    Returns the path to an HTML version of the report, generating one if needed.

    Three cases:
      1. report_path ends with .html and the file exists  → return it as-is
      2. report_path is another format (.txt, .json, .csv) → generate a
         companion .html file at the same base path (e.g. report.txt →
         report_email.html) and return that path
      3. report_path is None → generate a timestamped file in reports/

    The generated file is a full Pulse HTML report, identical to what
    python main.py --format html would produce.
    """
    # Case 1: already an HTML file on disk
    if report_path and report_path.lower().endswith(".html") and os.path.isfile(report_path):
        return report_path

    # Decide where to write the HTML file
    if report_path:
        base     = os.path.splitext(report_path)[0]
        html_out = base + "_report.html"
    else:
        os.makedirs("reports", exist_ok=True)
        stamp    = scan_dt.strftime("%Y%m%d_%H%M%S") if hasattr(scan_dt, "strftime") else "report"
        html_out = os.path.join("reports", f"pulse_{stamp}.html")

    # Late import avoids any circular-import risk at module load time
    from pulse.reports.reporter import generate_report
    generate_report(findings, output_path=html_out, fmt="html")
    return html_out


# ---------------------------------------------------------------------------
# Subject line
# ---------------------------------------------------------------------------

def _build_subject(severity_counts, total_findings):
    """Builds the email subject line based on the scan results."""
    critical = severity_counts.get("CRITICAL", 0)
    high     = severity_counts.get("HIGH", 0)

    if critical > 0:
        return f"[PULSE] CRITICAL - {total_findings} findings ({critical} critical)"
    elif high > 0:
        return f"[PULSE] HIGH - {total_findings} findings ({high} high severity)"
    elif total_findings > 0:
        return f"[PULSE] {total_findings} finding(s) detected"
    else:
        return "[PULSE] Scan complete - no findings"


# ---------------------------------------------------------------------------
# Plain-text body (fallback for clients that cannot render HTML)
# ---------------------------------------------------------------------------

def _build_plain_body(severity_counts, total_findings, pdf_failed=False):
    """Builds the plain-text email body with a brief summary."""
    lines = [
        "Pulse - Windows Event Log Analyzer",
        "=" * 38,
        "",
        f"Scan complete. {total_findings} finding(s) detected.",
        "",
        _context_summary(severity_counts),
        "",
        "Severity Breakdown:",
        f"  CRITICAL : {severity_counts.get('CRITICAL', 0)}",
        f"  HIGH     : {severity_counts.get('HIGH', 0)}",
        f"  MEDIUM   : {severity_counts.get('MEDIUM', 0)}",
        f"  LOW      : {severity_counts.get('LOW', 0)}",
        "",
        "Full report saved to your reports/ folder.",
    ]
    if pdf_failed:
        lines += ["", "NOTE: PDF attachment could not be generated."]
    lines += ["", "-- Pulse", "   https://github.com/barrytd/Pulse"]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# HTML body
# ---------------------------------------------------------------------------

def _build_html_body(severity_counts, total_findings, findings,
                     scan_dt=None, hostname=None, report_url=None,
                     pdf_failed=False):
    """
    Builds a table-based HTML email body with inline CSS.

    Layout (GitHub Security alert style):
      - Dark navy header: PULSE + Windows Event Log Analyzer subtitle
      - Amber alert bar with severity-coloured left border
      - Metadata row: scan date/time · findings count · hostname
      - Horizontal divider
      - Top 3 findings (severity badge + rule name + description)
      - Overflow note if more than 3 findings exist
      - "Review findings" dark button
      - Footer: reports folder note + GitHub link
    """
    if scan_dt is None:
        scan_dt = datetime.now()
    if hostname is None:
        hostname = _get_hostname()

    accent      = _header_color(severity_counts)
    alert_title = _alert_title(severity_counts)
    scan_str    = scan_dt.strftime("%b %d, %Y %H:%M").replace(" 0", " ") if hasattr(scan_dt, "strftime") else str(scan_dt)

    # Build the report path string for the footer.
    # file:// URLs are stripped by Gmail/Outlook, so we show the path as
    # plain text instead — the user can copy it and open it in their browser.
    report_path_display = os.path.abspath(report_url.replace("file:///", "").replace("/", os.sep)) if report_url and report_url.startswith("file:///") else None

    # --- Header ---
    header = f"""
    <table width="100%" cellpadding="0" cellspacing="0" border="0"
           style="background:#1a1a2e;">
      <tr>
        <td style="padding:24px 32px 20px 32px;">
          <div style="font-family:Arial,sans-serif; font-size:20px;
                      font-weight:bold; color:#ffffff; letter-spacing:3px;">
            PULSE
          </div>
          <div style="font-family:Arial,sans-serif; font-size:12px;
                      color:#8888aa; margin-top:4px; letter-spacing:0.5px;">
            Windows Event Log Analyzer
          </div>
        </td>
      </tr>
    </table>"""

    # --- Alert bar ---
    alert = f"""
    <table width="100%" cellpadding="0" cellspacing="0" border="0"
           style="background:#ffffff;">
      <tr>
        <td style="padding:20px 32px;">
          <table width="100%" cellpadding="0" cellspacing="0" border="0"
                 style="background:#fffbf0; border-left:4px solid {accent};
                        border-radius:0 4px 4px 0;">
            <tr>
              <td style="padding:14px 20px;">
                <div style="font-family:Arial,sans-serif; font-size:15px;
                            font-weight:bold; color:#333333;">
                  {alert_title}
                </div>
                <div style="font-family:Arial,sans-serif; font-size:13px;
                            color:#666666; margin-top:4px;">
                  Pulse detected suspicious activity requiring your attention
                </div>
              </td>
            </tr>
          </table>
        </td>
      </tr>
    </table>"""

    # --- Metadata row ---
    meta = f"""
    <table width="100%" cellpadding="0" cellspacing="0" border="0"
           style="background:#ffffff;">
      <tr>
        <td style="padding:0 32px 20px 32px;">
          <table cellpadding="0" cellspacing="0" border="0">
            <tr>
              <td style="font-family:Arial,sans-serif; font-size:12px;
                         color:#888888; padding-right:20px; white-space:nowrap;">
                Scanned&nbsp;&nbsp;<span style="color:#333333; font-weight:bold;">{scan_str}</span>
              </td>
              <td style="font-family:Arial,sans-serif; font-size:12px;
                         color:#888888; padding-right:20px; white-space:nowrap;
                         border-left:1px solid #dddddd; padding-left:20px;">
                Findings&nbsp;&nbsp;<span style="color:#333333; font-weight:bold;">{total_findings}</span>
              </td>
              <td style="font-family:Arial,sans-serif; font-size:12px;
                         color:#888888; white-space:nowrap;
                         border-left:1px solid #dddddd; padding-left:20px;">
                Host&nbsp;&nbsp;<span style="color:#333333; font-weight:bold;">{hostname}</span>
              </td>
            </tr>
          </table>
        </td>
      </tr>
    </table>"""

    # --- Divider ---
    divider = """
    <table width="100%" cellpadding="0" cellspacing="0" border="0"
           style="background:#ffffff;">
      <tr>
        <td style="padding:0 32px;">
          <hr style="border:none; border-top:1px solid #eeeeee; margin:0;">
        </td>
      </tr>
    </table>"""

    # --- Findings list (top 3 sorted by severity) ---
    if findings:
        sorted_findings = sorted(
            findings,
            key=lambda f: _SEVERITY_ORDER.get(f.get("severity", "LOW"), 3)
        )
        shown    = sorted_findings[:_MAX_FINDINGS_SHOWN]
        overflow = len(sorted_findings) - len(shown)

        rows = ""
        for i, f in enumerate(shown, start=1):
            sev      = f.get("severity", "LOW")
            colors   = SEVERITY_COLORS.get(sev, SEVERITY_COLORS["LOW"])
            badge_bg = colors["bg"]
            badge_fg = colors["text"]
            rule     = f.get("rule", "Unknown")
            detail   = f.get("description", "")
            if len(detail) > 120:
                detail = detail[:117] + "..."

            border = "border-bottom:1px solid #eeeeee;" if i < len(shown) or overflow > 0 else ""
            rows += f"""
            <tr>
              <td style="padding:14px 0; {border}">
                <table width="100%" cellpadding="0" cellspacing="0" border="0">
                  <tr>
                    <td style="width:80px; vertical-align:top; padding-top:2px;">
                      <span style="background:{badge_bg}; color:{badge_fg};
                                   font-family:Arial,sans-serif; font-size:10px;
                                   font-weight:bold; letter-spacing:1px;
                                   padding:3px 8px; border-radius:4px;
                                   display:inline-block;">
                        {sev}
                      </span>
                    </td>
                    <td style="vertical-align:top;">
                      <div style="font-family:Arial,sans-serif; font-size:13px;
                                  font-weight:bold; color:#222222;">{rule}</div>
                      <div style="font-family:Arial,sans-serif; font-size:12px;
                                  color:#666666; margin-top:3px;">{detail}</div>
                    </td>
                  </tr>
                </table>
              </td>
            </tr>"""

        overflow_row = ""
        if overflow > 0:
            overflow_row = f"""
            <tr>
              <td style="padding:12px 0 4px 0; text-align:center;">
                <span style="font-family:Arial,sans-serif; font-size:12px;
                             color:#888888; font-style:italic;">
                  ...and {overflow} more finding{"s" if overflow != 1 else ""} in the full report
                </span>
              </td>
            </tr>"""

        findings_section = f"""
        <table width="100%" cellpadding="0" cellspacing="0" border="0"
               style="background:#ffffff;">
          <tr>
            <td style="padding:20px 32px 8px 32px;">
              <table width="100%" cellpadding="0" cellspacing="0" border="0">
                {rows}
                {overflow_row}
              </table>
            </td>
          </tr>
        </table>"""
    else:
        findings_section = """
        <table width="100%" cellpadding="0" cellspacing="0" border="0"
               style="background:#ffffff;">
          <tr>
            <td style="padding:20px 32px; font-family:Arial,sans-serif;
                       font-size:13px; color:#888888; font-style:italic;">
              No findings detected.
            </td>
          </tr>
        </table>"""

    # --- Footer ---
    # Show the absolute path to the HTML report so the user can copy it and
    # open it directly. file:// URLs are stripped by Gmail and Outlook.
    if report_path_display:
        path_line = f"""
          <div style="margin-top:6px; font-family:'Courier New',monospace;
                      font-size:11px; color:#555555; word-break:break-all;">
            {report_path_display}
          </div>"""
    else:
        path_line = ""

    pdf_note = (
        '<div style="margin-top:8px; color:#c0392b; font-weight:bold;">'
        'PDF attachment could not be generated.</div>'
        if pdf_failed else ""
    )
    footer = f"""
    <table width="100%" cellpadding="0" cellspacing="0" border="0"
           style="background:#f6f8fa; border-top:1px solid #e1e4e8;">
      <tr>
        <td style="padding:16px 32px; font-family:Arial,sans-serif;
                   font-size:11px; color:#999999; text-align:center;">
          Full report saved to:{path_line}
          {pdf_note}
          <div style="margin-top:8px;">
            <a href="https://github.com/barrytd/Pulse"
               style="color:#777777; text-decoration:none;">github.com/barrytd/Pulse</a>
          </div>
        </td>
      </tr>
    </table>"""

    # --- Assemble ---
    html = f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin:0; padding:0; background:#f0f0f0;">
  <table width="100%" cellpadding="0" cellspacing="0" border="0"
         style="background:#f0f0f0; padding:32px 0;">
    <tr>
      <td align="center">
        <table width="580" cellpadding="0" cellspacing="0" border="0"
               style="background:#ffffff; border-radius:6px;
                      overflow:hidden; border:1px solid #e1e4e8;">
          <tr><td>{header}</td></tr>
          <tr><td>{alert}</td></tr>
          <tr><td>{meta}</td></tr>
          <tr><td>{divider}</td></tr>
          <tr><td>{findings_section}</td></tr>
          <tr><td>{footer}</td></tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>"""

    return html
