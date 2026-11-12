# Day 26 – SOC Investigation Simulation

## Overview

A practical SOC Tier 1 investigation simulation using
synthetic security telemetry from a fictional organisation,
NEXORA Technologies.

The investigation covers suspicious SSH authentication,
post-login activity, event correlation, incident assessment,
escalation and incident reporting.

## Scenario

- Incident ID: SOC-2026-026
- Host: nexora-linux-01
- Account: svc-backup
- Dataset: Synthetic training evidence
- Priority: HIGH
- Classification: UNDER_INVESTIGATION
- Confirmed compromise: NO

## Investigation Workflow

1. Preserve and verify original evidence.
2. Normalize and review security events.
3. Triage suspicious authentication activity.
4. Build an incident timeline.
5. Correlate post-login events.
6. Identify investigation hypotheses and evidence gaps.
7. Assess severity and escalation requirements.
8. Document recommended containment actions.
9. Prepare the final SOC investigation report.

## Detection Findings

- Five failed SSH authentication events.
- One successful SSH login.
- One session-open event.
- One privileged command event.
- One Python process execution event.
- One outbound TLS connection.
- One account configuration activity event.

## Scripts

| Script | Purpose |
|---|---|
| alert_triage.py | Alert triage and timeline generation |
| event_correlation.py | Post-login event correlation |
| incident_assessment.py | Severity and escalation assessment |

## Outputs

- triage-summary.json
- incident-timeline.json
- event-correlation-report.json
- incident-assessment.json

## Documentation

- notes/evidence-register.md
- notes/investigation-hypotheses.md
- notes/additional-evidence-request.md
- reports/Day26-SOC-Investigation-Report.md

## Key Learning Outcomes

- Evidence preservation and integrity verification.
- SSH authentication investigation.
- Event correlation and timeline reconstruction.
- Incident severity assessment.
- Evidence-gap identification.
- Tier 1 to Tier 2 escalation.
- Professional incident reporting.

## Important Limitations

All evidence is synthetic and intended for educational use.

The observed event sequence does not independently prove
unauthorised access, malware execution or data exfiltration.

Event correlation is based on host, account and timestamps.
Session-level and process-level attribution remains unverified.

No real containment or remediation actions were performed.

## Environment

- Kali Linux
- Python 3
- JSON
- Git

## Status

Day 26 investigation simulation completed.
