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
#   1. Build a MIMEMultipart message (a container for text + attachments)
#   2. Add a plain-text body
#   3. Attach the report file
#   4. Connect to the SMTP server with TLS encryption
#   5. Log in and send
#
# WHAT IS SMTP?
# SMTP (Simple Mail Transfer Protocol) is the standard protocol for sending
# email. Every email provider (Gmail, Outlook, etc.) runs an SMTP server
# that accepts outgoing mail. Port 587 + STARTTLS is the modern standard.


import os
import smtplib
from email.mime.multipart import MIMEMultipart  # Container: holds text + attachments
from email.mime.text import MIMEText            # Plain text / HTML body parts
from email.mime.base import MIMEBase            # Base class for file attachments
from email import encoders                      # Base64 encodes binary attachments


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


def send_report(report_path, email_config, severity_counts, total_findings):
    """
    Sends the finished report as an email attachment.

    Connects to the SMTP server using TLS, authenticates, and sends the
    report file as an attachment with a summary in the email body.

    Parameters:
        report_path (str):       Path to the saved report file.
        email_config (dict):     The "email" section from pulse.yaml.
        severity_counts (dict):  How many findings per severity level.
        total_findings (int):    Total number of findings in the report.

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

    # --- BUILD THE MESSAGE ---
    # MIMEMultipart("mixed") is the standard container for messages
    # that have both a text body and file attachments.
    msg = MIMEMultipart("mixed")
    msg["From"]    = sender
    msg["To"]      = recipient
    msg["Subject"] = _build_subject(severity_counts, total_findings)

    # Attach the plain-text body.
    body = _build_body(report_path, severity_counts, total_findings)
    msg.attach(MIMEText(body, "plain"))

    # Attach the report file.
    attachment = _build_attachment(report_path)
    if attachment:
        msg.attach(attachment)

    # --- SEND ---
    try:
        # smtplib.SMTP opens a connection to the mail server.
        # "with" ensures the connection is closed even if an error occurs.
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            # STARTTLS upgrades the connection to encrypted TLS.
            # This is required by most modern email providers.
            server.starttls()
            # Log in with the sender's credentials.
            server.login(sender, password)
            # sendmail() does the actual delivery.
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


def _build_body(report_path, severity_counts, total_findings):
    """Builds the plain-text email body with a brief summary."""
    filename = os.path.basename(report_path)
    lines = [
        "Pulse - Windows Event Log Analyzer",
        "=" * 38,
        "",
        f"Scan complete. {total_findings} finding(s) detected.",
        "",
        "Severity Breakdown:",
        f"  CRITICAL : {severity_counts.get('CRITICAL', 0)}",
        f"  HIGH     : {severity_counts.get('HIGH', 0)}",
        f"  MEDIUM   : {severity_counts.get('MEDIUM', 0)}",
        f"  LOW      : {severity_counts.get('LOW', 0)}",
        "",
        f"Report attached: {filename}",
        "",
        "-- Pulse",
    ]
    return "\n".join(lines)


def _build_attachment(report_path):
    """
    Reads the report file and wraps it as a MIME attachment.

    Returns None if the file can't be read (so the email still sends
    with just the body, rather than crashing entirely).
    """
    try:
        with open(report_path, "rb") as f:
            data = f.read()

        # MIMEBase("application", "octet-stream") is the generic binary type.
        # It tells the email client "this is a file, download it."
        attachment = MIMEBase("application", "octet-stream")
        attachment.set_payload(data)

        # Base64 encodes the binary data so it can travel safely through
        # email systems that only handle plain text.
        encoders.encode_base64(attachment)

        filename = os.path.basename(report_path)
        attachment.add_header(
            "Content-Disposition",
            f'attachment; filename="{filename}"',
        )
        return attachment

    except Exception as e:
        print(f"  [!] Could not attach report file: {e}")
        return None
