# Day 37 — SOC Alert Triage Worksheet

## Investigation scope
Synthetic NCIC-inspired training environment.
No real FBI systems or records were accessed.

| Alert | Evidence to inspect | Analyst question | Initial disposition |
|---|---|---|---|
| NCIC-001 | Identity logs | Did failed logins precede a successful login? | Pending |
| NCIC-002 | Identity logs | Was the privilege change authorized? | Pending |
| NCIC-003 | Database logs | Was the volume of records read expected? | Pending |
| NCIC-004 | Database logs | Were UPDATE or DELETE operations approved? | Pending |
| NCIC-005 | API and database logs | Was the export requested and authorized? | Pending |
| NCIC-006 | Network logs | Was the outbound transfer expected? | Pending |
| NCIC-007 | Endpoint logs | Were the flagged processes legitimate? | Pending |

## Triage principles

- An alert is an investigative lead, not proof of compromise.
- Confirm timestamps and correlate events across log sources.
- Verify account ownership, role and authorization.
- Record evidence supporting and contradicting each hypothesis.
- Escalate when evidence indicates unauthorized access or data exposure.

## Analyst conclusion
Pending evidence review.
