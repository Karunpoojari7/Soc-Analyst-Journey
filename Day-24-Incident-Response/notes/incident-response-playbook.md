# Day 24 – SSH Incident Response Playbook

## Case
IR-2026-001 – Suspected SSH Brute-Force Activity

## Classification
Synthetic training scenario
Provisional severity: HIGH
Status: Investigation required

## 1. Detection and Analysis

Observed:
- Seven failed authentication attempts.
- One successful password authentication.
- One session opened.
- Same synthetic source IP observed in failed and successful events.
- Target account: svc-backup.

Required validation:
- Confirm account ownership.
- Confirm whether the login was expected.
- Determine account privileges.
- Review session commands and process activity.
- Check for other affected accounts and systems.

## 2. Containment

Recommended actions, subject to organisational approval:
1. Preserve original authentication and endpoint evidence.
2. Notify the incident response lead.
3. Validate whether the account owner recognises the login.
4. If compromise is suspected, revoke active sessions through authorised procedures.
5. Consider temporarily disabling or restricting the account.
6. Review access from the source across other systems.
7. Document each action, timestamp, owner, and approval.

Do not perform destructive actions before evidence preservation.

## 3. Eradication

If compromise is confirmed:
1. Identify the initial access method.
2. Review and remove unauthorised SSH keys.
3. Investigate suspicious account and privilege changes.
4. Remove confirmed persistence mechanisms.
5. Patch the exploited weakness.
6. Rotate affected credentials using approved procedures.
7. Verify that unauthorised access has been removed.

## 4. Recovery

1. Restore legitimate account access.
2. Validate system and service integrity.
3. Confirm that approved authentication controls are working.
4. Monitor authentication and session activity.
5. Check for recurring indicators.
6. Obtain system-owner approval before closing recovery.

## 5. Communication

Notify:
- SOC lead
- Incident response team
- System owner
- IT/security administrator
- Other stakeholders according to organisational policy

## 6. Closure Criteria

- Scope of the incident is documented.
- Evidence is preserved.
- Root cause is understood or explicitly marked unknown.
- Unauthorised access is removed if confirmed.
- Recovery is validated.
- Monitoring is in place.
- Lessons learned are recorded.

## 7. Limitations

This playbook is applied to a synthetic training scenario.
No real account compromise or containment action has been established.
