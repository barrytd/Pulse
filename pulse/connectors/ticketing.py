# pulse/connectors/ticketing.py
# -----------------------------
# Response connector: open a ticket in ClickUp or Jira.
#
# Bring-your-own everything, set by an admin under Settings (pulse.yaml
# `ticketing`): which provider, its API token, and where tickets go.
#   ClickUp: personal API token (`pk_...`) + list ID.
#            POST https://api.clickup.com/api/v2/list/{list_id}/task
#   Jira:    site URL + account email + API token (basic auth) + project
#            key (+ issue type, default Task).
#            POST {site}/rest/api/2/issue   (v2 takes a plain-text description)
#
# kind="response": every ticket waits for a person to approve it. The
# ticket contains only what the playbook step's inputs say (title,
# description, priority); nothing about the finding is added on its own.
# Nothing is cached. Any failure returns {"ok": False, "message": ...}.
# Requests go through base.request_guarded, so a Jira URL can't point
# Pulse at loopback / metadata addresses (private ones only when the
# admin allows them, for Jira Data Center on the LAN).

from __future__ import annotations

import base64
import urllib.error
import urllib.parse

from .base import Connector, DestinationRefused, register, request_guarded

CLICKUP_API = "https://api.clickup.com/api/v2"
MAX_TITLE = 250
MAX_BODY = 8000

# Playbook priority words -> ClickUp priority (1 urgent ... 4 low).
_CLICKUP_PRIORITY = {"urgent": 1, "high": 2, "normal": 3, "medium": 3, "low": 4}


def _settings(pulse_config):
    block = (pulse_config or {}).get("ticketing") or {}
    get = lambda k: str(block.get(k) or "").strip()  # noqa: E731
    return {
        "provider":        get("provider").lower(),
        "clickup_token":   get("clickup_token"),
        "clickup_list_id": get("clickup_list_id"),
        "jira_url":        get("jira_url").rstrip("/"),
        "jira_email":      get("jira_email"),
        "jira_token":      get("jira_token"),
        "jira_project":    get("jira_project"),
        "jira_issue_type": get("jira_issue_type") or "Task",
        "allow_private":   bool(block.get("allow_private")),
    }


def configured(cfg):
    if cfg.get("provider") == "clickup":
        return bool(cfg.get("clickup_token") and cfg.get("clickup_list_id"))
    if cfg.get("provider") == "jira":
        return bool(cfg.get("jira_url") and cfg.get("jira_email")
                    and cfg.get("jira_token") and cfg.get("jira_project"))
    return False


def _fail(message):
    return {"ok": False, "message": message}


def _http_error_message(e, provider):
    if e.code in (401, 403):
        return f"{provider} rejected the credentials (HTTP {e.code}). Check them in Settings."
    if e.code == 404:
        return f"{provider} couldn't find the list / project (HTTP 404). Check it in Settings."
    if 300 <= e.code < 400:
        return f"{provider} answered with a redirect, which Pulse doesn't follow. Check the URL."
    return f"{provider} returned HTTP {e.code}."


def create_clickup(cfg, title, description, priority):
    body = {"name": title}
    if description:
        body["description"] = description
    p = _CLICKUP_PRIORITY.get((priority or "").strip().lower())
    if p:
        body["priority"] = p
    url = f"{CLICKUP_API}/list/{urllib.parse.quote(cfg['clickup_list_id'], safe='')}/task"
    status, data = request_guarded(url, payload=body,
                                   headers={"Authorization": cfg["clickup_token"]})
    data = data or {}
    return {"ok": True, "provider": "clickup", "ticket_id": data.get("id"),
            "url": data.get("url"),
            "message": "Created ClickUp task" + (f": {data['url']}" if data.get("url") else ".")}


def _jira_auth(cfg):
    raw = f"{cfg['jira_email']}:{cfg['jira_token']}".encode("utf-8")
    return "Basic " + base64.b64encode(raw).decode("ascii")


def create_jira(cfg, title, description, priority):
    fields = {"project": {"key": cfg["jira_project"]}, "summary": title,
              "issuetype": {"name": cfg["jira_issue_type"]}}
    if description:
        fields["description"] = description
    status, data = request_guarded(cfg["jira_url"] + "/rest/api/2/issue",
                                   payload={"fields": fields},
                                   headers={"Authorization": _jira_auth(cfg)},
                                   allow_private=cfg["allow_private"])
    key = (data or {}).get("key")
    link = f"{cfg['jira_url']}/browse/{key}" if key else None
    return {"ok": True, "provider": "jira", "ticket_id": key, "url": link,
            "message": f"Created Jira issue {key}" + (f": {link}" if link else ".")}


def check_credentials(pulse_config):
    """Read-only check used by the Settings "Test" button:
    ClickUp GET /list/{id}, Jira GET /rest/api/2/myself. Creates nothing."""
    cfg = _settings(pulse_config)
    if not configured(cfg):
        return _fail("Ticketing isn't fully set up yet.")
    try:
        if cfg["provider"] == "clickup":
            request_guarded(f"{CLICKUP_API}/list/{urllib.parse.quote(cfg['clickup_list_id'], safe='')}",
                            method="GET", headers={"Authorization": cfg["clickup_token"]})
            return {"ok": True, "message": "ClickUp accepted the token and found the list."}
        request_guarded(cfg["jira_url"] + "/rest/api/2/myself", method="GET",
                        headers={"Authorization": _jira_auth(cfg)},
                        allow_private=cfg["allow_private"])
        return {"ok": True, "message": "Jira accepted the credentials."}
    except DestinationRefused as e:
        return _fail(str(e))
    except urllib.error.HTTPError as e:
        return _fail(_http_error_message(e, cfg["provider"].capitalize()))
    except (urllib.error.URLError, TimeoutError, OSError):
        return _fail("Couldn't reach the ticketing service.")


@register
class TicketConnector(Connector):
    key = "ticket"
    name = "Ticket (ClickUp / Jira)"
    kind = "response"
    config_fields = []
    result_fields = {}

    def actions(self):
        return ["create_ticket"]

    def action_label(self, action):
        return "Open a ticket"

    def action_inputs(self, action):
        return [
            {"name": "title", "label": "Ticket title", "required": True, "multiline": False},
            {"name": "description", "label": "Description", "required": False, "multiline": True},
            {"name": "priority", "label": "Priority (urgent, high, normal or low; ClickUp only)",
             "required": False, "multiline": False},
        ]

    def config_from_pulse(self, pulse_config):
        return _settings(pulse_config)

    def health_check(self, config):
        return configured(config)

    def run(self, action, inputs, config):
        if action != "create_ticket":
            return None
        if not configured(config):
            return _fail("Ticketing isn't set up. Choose ClickUp or Jira under Settings.")
        title = str(inputs.get("title") or "").strip()[:MAX_TITLE]
        if not title:
            return _fail("The ticket has no title.")
        description = str(inputs.get("description") or "").strip()[:MAX_BODY]
        priority = str(inputs.get("priority") or "")
        provider = "ClickUp" if config["provider"] == "clickup" else "Jira"
        try:
            if config["provider"] == "clickup":
                return create_clickup(config, title, description, priority)
            return create_jira(config, title, description, priority)
        except DestinationRefused as e:
            return _fail(str(e))
        except urllib.error.HTTPError as e:
            return _fail(_http_error_message(e, provider))
        except (urllib.error.URLError, TimeoutError, OSError):
            return _fail(f"Couldn't reach {provider}.")
