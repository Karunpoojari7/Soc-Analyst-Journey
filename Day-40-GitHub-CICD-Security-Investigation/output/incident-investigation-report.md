# SOC Incident Investigation Report

## 1. Case Overview

- **Case:** Day 40 — GitHub CI/CD Security Investigation
- **Dataset:** Synthetic training audit events
- **Detection:** Ordered GitHub event correlation
- **Assessment:** Suspicious activity requiring analyst validation

## 2. Detection Summary

- Correlated alerts: 1
- Timeline events: 4

### D40-V2-001

- **Severity:** HIGH
- **Actor:** unknown-user
- **Repository:** training-app
- **Source IP:** 198.51.100.25
- **Duration:** 480.0 seconds
- **Event IDs:** EVT003, EVT004, EVT005, EVT006

Ordered suspicious activity sequence detected. Analyst validation required; not proof of compromise.

## 3. Event Timeline

| Timestamp (UTC) | Event ID | Actor | Action | Source IP |
|---|---|---|---|---|
| 2026-11-26T09:10:00Z | EVT003 | unknown-user | token.created | 198.51.100.25 |
| 2026-11-26T09:12:00Z | EVT004 | unknown-user | repo.permission.changed | 198.51.100.25 |
| 2026-11-26T09:15:00Z | EVT005 | unknown-user | workflow.modified | 198.51.100.25 |
| 2026-11-26T09:18:00Z | EVT006 | unknown-user | workflow.run | 198.51.100.25 |

## 4. Analyst Assessment

The synthetic dataset contains a correlated sequence of token creation, repository permission modification, workflow modification, and workflow execution. The sequence is a detection lead, not proof of unauthorized access or compromise.

## 5. Recommended Defensive Actions

1. Verify the identity and authorization of the actor.
2. Review token creation details, scopes, and subsequent use.
3. Validate repository permission changes against approved change records.
4. Inspect workflow changes and compare them with trusted versions.
5. Review workflow execution logs and any resulting deployments.
6. Revoke suspicious credentials and contain affected workflows if unauthorized activity is confirmed.

## 6. Evidence and Limitations

- Evidence is synthetic and generated for this training lab.
- No real 1Password, GitHub customer, or production telemetry was analysed.
- The source IP addresses belong to documentation ranges used in examples.
- No conclusion about a real-world compromise can be drawn from this lab.

## 7. Conclusion

The correlation rule successfully identified the configured suspicious event sequence in the synthetic dataset. Further identity, authorization, and workflow evidence would be required to confirm an actual incident.
