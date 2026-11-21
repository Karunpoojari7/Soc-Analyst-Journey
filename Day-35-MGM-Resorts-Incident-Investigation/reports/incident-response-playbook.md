# Day 35 — Identity Compromise Response Playbook

## Incident classification
High-priority suspicious identity activity.

## Trigger
Multiple failed authentication attempts followed by:
- Successful login from a different source IP
- MFA registration
- Privilege change

## Immediate containment
1. Contact the account owner through a verified channel.
2. Validate the MFA registration request.
3. Revoke suspicious active sessions.
4. Temporarily disable the affected account if compromise is confirmed.
5. Review privileged access and remove unauthorized changes.
6. Preserve identity-provider and endpoint evidence.

## Investigation
1. Review authentication history.
2. Examine MFA enrollment records.
3. Inspect helpdesk tickets and account recovery events.
4. Review endpoint process telemetry.
5. Correlate network and identity events.
6. Determine whether sensitive systems or data were accessed.

## Recovery
1. Reset credentials using a verified process.
2. Re-enrol MFA securely.
3. Restore appropriate account permissions.
4. Monitor the account for recurring suspicious activity.
5. Document recovery actions.

## Communication
Notify the incident response lead and relevant system owners.
Escalate confirmed data exposure according to organisational
incident response and legal requirements.

## Evidence limitation
This playbook was developed using synthetic training data.
No real MGM internal evidence was examined.
