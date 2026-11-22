# Day 36 — Lessons Learned

## 1. Investigation lessons

### Identity telemetry
Authentication events become more useful when failures, successes,
MFA events, and privilege changes are correlated.

### Vendor access
Third-party accounts should have limited permissions, strong
authentication, and regular access reviews.

### Data access monitoring
Large exports should be investigated against normal business
activity and approved export workflows.

### Network monitoring
Network transfer volume should be correlated with application
and data-access activity.

### Endpoint investigation
Process names alone are insufficient. Analysts should examine
process paths, hashes, parent processes, users, and command lines.

## 2. Detection engineering lessons

- Detection rules require measurable conditions.
- Thresholds must be tuned against normal activity.
- Benign datasets are important for testing false positives.
- Alerts should include supporting evidence.
- Multiple telemetry sources improve investigation quality.

## 3. Evidence handling lessons

- Preserve original evidence files.
- Generate and verify SHA-256 hashes.
- Maintain a timestamped incident timeline.
- Record the source of every finding.
- Keep synthetic training evidence separate from real incident data.

## 4. Areas for improvement

1. Add session identifiers to improve cross-source correlation.
2. Add device identifiers to identity and endpoint logs.
3. Include approved export baselines.
4. Enrich network events with firewall and proxy context.
5. Add process hashes and parent-process information.
6. Test detection rules against more benign scenarios.
7. Document detection performance and false-positive rates.

## 5. Learning outcome

This exercise demonstrates a structured SOC workflow:

Evidence collection
→ Evidence validation
→ Log analysis
→ Event correlation
→ Detection engineering
→ MITRE ATT&CK mapping
→ Incident response
→ SOC handover

The central lesson is that suspicious indicators must be correlated
and validated before drawing conclusions.
