# Day 37 — Severity Assessment and Escalation

## Case classification
Case: NCIC-inspired synthetic intrusion investigation
Environment: Local Termux lab
Evidence: Synthetic CSV logs

## Alert assessment

| Detection | Initial severity | Evidence required |
|---|---|---|
| NCIC-001 Authentication anomaly | Medium | Failed and successful login sequence |
| NCIC-002 Privilege modification | High | Account role change and authorization records |
| NCIC-003 High database read volume | Medium | Query volume and user baseline |
| NCIC-004 Database modification | High | UPDATE/DELETE activity and approval records |
| NCIC-005 Data export | High | Export request, authorization and destination |
| NCIC-006 Outbound transfer | High | Transfer volume, destination and business justification |
| NCIC-007 Endpoint process review | Medium | Process command line, parent process and user context |

These are provisional training priorities, not confirmed incident severity ratings.

## Escalation criteria

Escalate to Tier 2 when:
- Multiple independent sources corroborate suspicious activity.
- A privileged account performs unexplained actions.
- Sensitive records may have been accessed or exported.
- Evidence suggests unauthorized database modification.
- A suspicious transfer has no legitimate explanation.

## Immediate analyst actions

1. Preserve relevant logs.
2. Record timestamps and affected accounts.
3. Validate account and activity ownership.
4. Notify the incident response lead according to policy.
5. Avoid destructive remediation before evidence preservation.
6. Document every action taken.

## Final assessment
Pending review of actual synthetic evidence.
