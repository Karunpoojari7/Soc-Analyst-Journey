# SOC Incident Investigation Report — Day 37

## 1. Case Information

Case ID: SOC-D37-NCIC-001
Case Type: Suspected database and identity compromise simulation
Investigation Type: Blue Team / SOC Investigation
Environment: Android Termux
Evidence Type: Synthetic training data
Case Status: Training investigation

## 2. Executive Summary

This investigation simulates a suspected intrusion involving a
sensitive government information system.

The exercise examines authentication activity, privilege changes,
API requests, database operations, network transfers and endpoint
process activity.

All evidence in this exercise is synthetic. It is not evidence
collected from FBI infrastructure and does not establish what
happened in the real NCIC incident.

## 3. Investigation Objectives

- Examine authentication anomalies.
- Investigate account privilege modifications.
- Identify unusual database operations.
- Review API export activity.
- Examine outbound network transfers.
- Investigate suspicious endpoint processes.
- Correlate events across multiple log sources.

## 4. Evidence Sources

| Evidence source | File | Validation status |
|---|---|---|
| Identity | identity-events.csv | Pending final review |
| API | api-events.csv | Pending final review |
| Database | database-events.csv | Pending final review |
| Network | network-events.csv | Pending final review |
| Endpoint | endpoint-events.csv | Pending final review |

## 5. Detection Findings

Record each detection with:
- Alert ID
- Timestamp
- Affected account or asset
- Evidence source
- Observed behaviour
- Severity
- Analyst confidence
- Recommended action

Actual findings: Pending evidence review.

## 6. Event Correlation

Review the correlated timeline and determine whether the events
are related.

Do not infer causation from timestamps alone.

Confirmed relationships: Pending review.
Unconfirmed hypotheses: Pending review.

## 7. Impact Assessment

Potential areas requiring investigation:
- Unauthorized account access
- Privilege misuse
- Sensitive database access
- Unauthorized data exports
- Data exposure
- Service availability

Confirmed impact: Not established by this training exercise.

## 8. MITRE ATT&CK Mapping

Refer to MITRE-ATTACK-MAPPING.md.

Technique mappings are investigative hypotheses based on synthetic
behaviour, not confirmed techniques from the real incident.

## 9. Response Recommendations

1. Enforce MFA for privileged accounts.
2. Apply least-privilege access controls.
3. Monitor privileged account changes.
4. Audit sensitive database queries.
5. Correlate API exports with database activity.
6. Monitor unusual outbound transfers.
7. Protect audit logs against tampering.
8. Improve endpoint process monitoring.

## 10. Detection Validation

Current status:
- Synthetic suspicious dataset: Generated.
- Detection alerts: Generated.
- SHA-256 evidence integrity checks: To be verified.
- Benign dataset testing: Pending.
- False-positive evaluation: Pending.
- Missing audit-event detection: Pending.
- Automated unit tests: Pending.

## 11. Limitations

- Evidence is synthetic.
- No real FBI systems were accessed.
- No real user accounts or government records were involved.
- The simulated events cannot establish the actual attack path.
- Detection rules require additional validation.

## 12. Final Analyst Conclusion

This exercise demonstrates a multi-source SOC investigation workflow.

A real incident conclusion would require verified evidence, system
owner confirmation, forensic analysis and appropriate authorization.

Final compromise determination: Not established.

## 13. Evidence Integrity

Evidence hash manifest:
output/evidence-sha256.txt

Investigation timeline:
timeline/correlated-timeline.csv

Detection output:
output/detection-alerts.json
