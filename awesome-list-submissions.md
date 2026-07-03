# Awesome-list submissions

Planned submissions of Pulse to two curated "awesome" lists. Both target
sections are alphabetically ordered — slot Pulse among the existing "P"
entries, and re-check the live section for the exact neighbor + current style
before opening each PR.

## awesome-cybersecurity-blueteam

- **Repo:** https://github.com/fabacab/awesome-cybersecurity-blueteam
- **Section:** Security monitoring → Threat hunting (alongside DeepBlueCLI, the closest analog)
- **Entry to add:**

  ```
  [Pulse](https://github.com/barrytd/Pulse) - Windows event log threat detection mapped to MITRE ATT&CK, with posture scoring, a triage dashboard, and PDF/HTML reporting.
  ```

- **PR description:**

  > Add Pulse — an open-source (MIT) Windows event-log (.evtx) threat-detection tool. Runs detection rules mapped to MITRE ATT&CK, scores security posture, and provides a triage dashboard plus PDF/HTML/JSON/CSV reporting. Placed alphabetically in Security monitoring → Threat hunting, alongside similar Windows event-log tools like DeepBlueCLI.

## awesome-incident-response

- **Repo:** https://github.com/meirwah/awesome-incident-response
- **Section:** Log Analysis Tools (alongside Chainsaw, Hayabusa, Sigma)
- **Entry to add** (bullet-prefixed to match the section):

  ```
  * [Pulse](https://github.com/barrytd/Pulse) - Open-source Windows event log (.evtx) threat detection and incident reporting, with detections mapped to MITRE ATT&CK, posture scoring, and a triage dashboard.
  ```

- **PR description:**

  > Add Pulse to Log Analysis Tools — an open-source (MIT) tool that parses Windows event logs (.evtx) to detect attacks mapped to MITRE ATT&CK and generate incident-investigation reports (with a chain-of-custody SHA-256 manifest). Fits alongside Chainsaw and Hayabusa; placed alphabetically.
