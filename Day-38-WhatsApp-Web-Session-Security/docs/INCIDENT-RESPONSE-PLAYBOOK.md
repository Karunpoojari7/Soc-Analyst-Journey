# Day 38 — WhatsApp Web Incident Response Playbook

## Case ID
SOC-D38-WWA-001

## Incident category
Suspected authenticated browser session misuse.

## Scope
Synthetic educational investigation.

## 1. Identification

- Obtain the user's incident report.
- Establish the suspected access window.
- Identify the affected account and device.
- Review linked-device information.
- Identify unexpected messaging activity.

## 2. Evidence Preservation

- Record incident timestamps.
- Preserve relevant endpoint and browser logs.
- Record linked-device information where available.
- Preserve user-reported suspicious messages.
- Calculate SHA-256 hashes of collected evidence.
- Maintain an evidence handling record.

## 3. Containment

With account-owner authorization:

- Revoke unfamiliar linked devices.
- Terminate suspicious authenticated sessions.
- Secure the primary WhatsApp account.
- Prevent further access from untrusted devices.
- Notify the appropriate incident response team.

## 4. Eradication

- Investigate the suspected access method.
- Remove unauthorized linked-device access.
- Review device security.
- Address compromised email or phone access if applicable.
- Remove identified malicious software if evidence supports it.

## 5. Recovery

- Verify account ownership.
- Review linked devices again.
- Enable two-step verification.
- Monitor unexpected account activity.
- Notify affected contacts if impersonation occurred.

## 6. Lessons Learned

- Never rely on browser-tab closure as logout.
- Explicitly terminate sessions on shared computers.
- Avoid linking accounts on public computers.
- Review linked devices regularly.
- Train employees on session security.

## Investigation limitations

This is a synthetic training exercise.
No actual WhatsApp account or internal platform logs
were accessed.

## Final incident determination

Pending evidence review.
