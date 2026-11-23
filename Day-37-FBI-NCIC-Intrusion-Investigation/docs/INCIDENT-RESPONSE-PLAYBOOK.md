# Day 37 — Incident Response Playbook

## Case
NCIC-inspired synthetic intrusion investigation.

## Scope
This playbook is for the training environment only.
All evidence is synthetic. No real government system was accessed.

---

## Phase 1: Preparation

- Enable centralized identity and database logging.
- Enforce MFA for privileged accounts.
- Maintain an inventory of authorized accounts.
- Protect audit logs from unauthorized modification.
- Establish incident escalation contacts.
- Maintain tested backups and recovery procedures.

## Phase 2: Detection and Analysis

- Review repeated authentication failures.
- Investigate successful logins following failures.
- Verify privilege modifications.
- Examine unusual database reads and exports.
- Correlate API, network and endpoint activity.
- Record timestamps, account identifiers and evidence references.
- Distinguish confirmed observations from hypotheses.

## Phase 3: Containment

Subject to incident-response authorization:

- Suspend or restrict confirmed compromised accounts.
- Revoke suspicious active sessions and tokens.
- Restrict affected systems or network paths where necessary.
- Preserve relevant logs and forensic evidence.
- Record every containment action and its approval.

Do not isolate or disable production systems without authorization.

## Phase 4: Eradication

- Identify and remove confirmed unauthorized access.
- Rotate affected credentials and secrets.
- Remove confirmed persistence mechanisms.
- Correct exploited security weaknesses.
- Validate system configurations.

## Phase 5: Recovery

- Restore systems from trusted sources where necessary.
- Validate application and database integrity.
- Re-enable access under controlled conditions.
- Monitor authentication, database and network activity.
- Obtain service-owner confirmation before closing recovery.

## Phase 6: Lessons Learned

- Document the incident timeline.
- Identify root cause when evidence supports it.
- Record detection and response gaps.
- Improve logging and alert rules.
- Assign owners and deadlines to corrective actions.

---

## Evidence preservation checklist

- [ ] Original evidence preserved
- [ ] Evidence hashes recorded
- [ ] Timestamps and timezone documented
- [ ] Account and system identifiers recorded
- [ ] Analyst actions documented
- [ ] Access to evidence restricted
- [ ] Evidence chain of custody maintained

## Final incident status

Pending investigation and evidence validation.
