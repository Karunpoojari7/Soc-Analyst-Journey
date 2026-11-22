# Day 36 — Third-Party Security Incident Response Playbook

## 1. Purpose

Define a repeatable response process for suspected compromise of a
third-party vendor account and possible exposure of customer data.

This playbook is designed for a SOC training simulation. It does not
describe confirmed actions taken during the real JPMorgan incident.

## 2. Incident classification

Incident type:
- Suspected third-party account compromise
- Suspicious privilege modification
- Unusual customer-data export
- Potential unauthorized outbound data transfer

Suggested severity: High — pending validation.

Severity must be reassessed using the actual business impact,
sensitivity of affected data, scope, and confidence in the evidence.

## 3. Phase 1 — Identification

SOC analyst responsibilities:

1. Review authentication failures followed by successful login.
2. Identify the account, source IP, timestamp, and authentication method.
3. Investigate unexpected role or privilege changes.
4. Review customer-data access and export records.
5. Identify unusual network transfer volumes.
6. Correlate endpoint process events with identity and data-access logs.
7. Preserve original logs and record evidence hashes.

Evidence to collect:
- Identity and authentication logs
- Vendor application audit logs
- Customer-data access logs
- Network flow and firewall logs
- Endpoint process and security logs
- Relevant cloud audit events

## 4. Phase 2 — Containment

Subject to incident-response authority and business approval:

1. Revoke suspicious vendor sessions and access tokens.
2. Temporarily disable accounts confirmed or strongly suspected to be compromised.
3. Restrict unexpected vendor access paths.
4. Remove unauthorized privileges.
5. Apply temporary export restrictions where appropriate.
6. Coordinate containment with the vendor's security team.

Do not delete logs, wipe systems, or destroy evidence during containment.

## 5. Phase 3 — Investigation

Determine:

- Was the account legitimately used?
- Was MFA completed by the authorized user?
- Was the privilege change approved?
- Which customer records were accessed or exported?
- Were exports followed by unusual network transfers?
- Which endpoints and sessions were involved?
- Is there evidence of persistence or additional compromised accounts?
- Can the organization establish whether data left its control?

Maintain a timestamped incident timeline and record the source
of every finding.

## 6. Phase 4 — Eradication

After confirming the incident scope:

1. Remove unauthorized accounts, tokens, keys, and permissions.
2. Reset affected credentials.
3. Review and remediate endpoint compromise.
4. Remove unauthorized scheduled tasks or persistence mechanisms
   if discovered.
5. Patch the exploited weakness if one is identified.
6. Validate the vendor environment before restoring access.

## 7. Phase 5 — Recovery

1. Restore vendor access using approved least-privilege permissions.
2. Require MFA and appropriate access restrictions.
3. Monitor authentication and export activity closely.
4. Validate business applications and integrations.
5. Confirm that security controls are functioning.
6. Obtain approval before returning to normal operations.

## 8. Phase 6 — Lessons learned

Document:

- Root cause, if established
- Affected systems and accounts
- Confirmed data exposure
- Detection gaps
- Response delays
- Vendor control weaknesses
- Corrective actions and owners
- Dates for remediation verification

## 9. Communication and escalation

Escalate to:
- SOC lead
- Incident response team
- Vendor security contact
- IT and identity administrators
- Privacy and legal teams, where applicable
- Senior management, according to organizational policy

Any external notification must follow applicable legal,
regulatory, contractual, and organizational requirements.

## 10. Closure criteria

The incident may be closed only after:

- Scope has been assessed and documented.
- Unauthorized access has been removed.
- Required recovery checks are complete.
- Evidence is preserved.
- Data exposure assessment is documented.
- Corrective actions have owners and deadlines.
- Incident leadership approves closure.
