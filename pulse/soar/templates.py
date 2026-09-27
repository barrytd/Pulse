# pulse/soar/templates.py
# -----------------------
# Built-in example playbooks. They're offered on the Automations page as
# templates an admin adds to their organization with one click; nothing
# is installed or enabled automatically, so upgrading Pulse never starts
# automating anything on its own. Each one is validated by
# pulse/soar/recipe.py like any imported playbook (tests enforce it).

TEMPLATES = [
    {
        "key": "enrich-external-ip",
        "summary": "Look up every critical or high finding's public source IP on "
                   "AbuseIPDB and VirusTotal. Lookups only; nothing is changed.",
        "recipe": {
            "name": "Enrich critical external IPs",
            "description": "Runs threat-intel lookups the moment a critical or high "
                           "finding with a public source IP fires, so the verdicts are "
                           "already there when an analyst opens it.",
            "enabled": True,
            "trigger": {"on": "finding_created"},
            "conditions": [
                {"field": "severity", "op": "severity_at_least", "value": "HIGH"},
                {"field": "source_ip", "op": "is_public", "value": True},
            ],
            "steps": [
                {"connector": "abuseipdb", "action": "lookup_ip",
                 "with": {"ip": "{{ finding.source_ip }}"}, "save_as": "abuse"},
                {"connector": "virustotal", "action": "lookup_ip",
                 "with": {"ip": "{{ finding.source_ip }}"}, "save_as": "vt"},
            ],
        },
    },
    {
        "key": "contain-malicious-ip",
        "summary": "Look the source IP up, and if AbuseIPDB or VirusTotal says it's "
                   "malicious, ask a person to approve blocking it and alerting the team.",
        "recipe": {
            "name": "Enrich and contain a malicious IP",
            "description": "When a critical or high finding comes from a public IP that "
                           "AbuseIPDB scores 80+ or 3+ VirusTotal engines flag, it proposes "
                           "a firewall block and a team alert. Both wait for approval.",
            "enabled": True,
            "trigger": {"on": "finding_created"},
            "conditions": [
                {"field": "severity", "op": "severity_at_least", "value": "HIGH"},
                {"field": "source_ip", "op": "is_public", "value": True},
            ],
            "steps": [
                {"connector": "abuseipdb", "action": "lookup_ip",
                 "with": {"ip": "{{ finding.source_ip }}"}, "save_as": "abuse"},
                {"connector": "virustotal", "action": "lookup_ip",
                 "with": {"ip": "{{ finding.source_ip }}"}, "save_as": "vt"},
                {"if": "{{ abuse.score >= 80 or vt.malicious >= 3 }}", "then": [
                    {"connector": "firewall", "action": "block_ip",
                     "with": {"ip": "{{ finding.source_ip }}",
                              "comment": "{{ finding.rule }} on {{ finding.hostname }}"},
                     "requires_approval": True},
                    {"connector": "webhook", "action": "post_message",
                     "with": {"text": "Pulse blocked {{ finding.source_ip }} after "
                                      "{{ finding.rule }} on {{ finding.hostname }}. "
                                      "AbuseIPDB score {{ abuse.score }}, "
                                      "{{ vt.malicious }} VirusTotal engines flagged it."},
                     "requires_approval": True},
                ]},
            ],
        },
    },
    {
        "key": "alert-credential-theft",
        "summary": "When Pulse sees credential theft (dumping, Golden Ticket, "
                   "pass-the-hash, Kerberoasting), propose an alert to the team.",
        "recipe": {
            "name": "Alert the team on credential theft",
            "description": "Credential theft usually means an attacker is already "
                           "inside. This proposes a Slack/Discord alert for a person "
                           "to approve.",
            "enabled": True,
            "trigger": {"on": "finding_created"},
            "conditions": [
                {"field": "rule", "op": "in", "value": [
                    "Credential Dumping", "Golden Ticket", "Pass-the-Hash Attempt",
                    "Kerberoasting", "DCSync Attempt"]},
            ],
            "steps": [
                {"connector": "webhook", "action": "post_message",
                 "with": {"text": "Credential theft on {{ finding.hostname }}: "
                                  "{{ finding.rule }} ({{ finding.severity }}). "
                                  "Open Pulse to investigate."},
                 "requires_approval": True},
            ],
        },
    },
]


def get(key):
    for t in TEMPLATES:
        if t["key"] == key:
            return t
    return None
