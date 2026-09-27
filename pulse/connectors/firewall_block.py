# pulse/connectors/firewall_block.py
# ----------------------------------
# Response connector: block an IP in Windows Firewall.
#
# A thin adapter over pulse/firewall/blocker.py, so a playbook block goes
# through exactly the same safety checks as the dashboard's Block button:
# loopback / link-local / multicast / self-block are always refused, and
# private (RFC 1918) addresses are refused too (playbooks never pass
# force). Every stage and push is written to the audit log by the blocker.
#
# Being kind="response", every use in a playbook waits for a person to
# approve it (with their security PIN, when they have one set). The
# approver's email is what the blocker records as the user.

from __future__ import annotations

from .base import Connector, register


@register
class FirewallBlockConnector(Connector):
    key = "firewall"
    name = "Firewall block"
    kind = "response"
    config_fields = []

    def actions(self):
        return ["block_ip"]

    def health_check(self, config):
        return True

    def action_inputs(self, action):
        return [{"name": "ip", "label": "IP address to block", "required": True, "multiline": False},
                {"name": "comment", "label": "Comment (shown on the Firewall page)",
                 "required": False, "multiline": False}]

    def run(self, action, inputs, config):
        if action != "block_ip":
            return None
        from ..firewall import blocker

        ip = str(inputs.get("ip") or "").strip()
        if not ip:
            return {"ok": False, "message": "No IP to block (the finding had no source IP)."}
        db_path = config.get("db_path")
        actor = config.get("actor")
        comment = (inputs.get("comment") or config.get("comment") or "Blocked by playbook")[:200]

        staged = blocker.stage_ip(db_path, ip, comment=comment,
                                  finding_id=config.get("finding_id"),
                                  source="playbook", user=actor)
        if not staged.get("ok"):
            return {"ok": False, "ip": ip, "message": staged.get("message") or "Could not stage the block."}

        pushed = blocker.push_pending(db_path, source="playbook", user=actor, only_ips=[ip])
        if pushed.get("pushed"):
            return {"ok": True, "ip": ip, "message": f"Blocked {ip} in Windows Firewall."}
        return {"ok": False, "ip": ip,
                "message": "Staged but not pushed: " + (pushed.get("message") or "push failed")
                           + " Push it from the Firewall page."}
