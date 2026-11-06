# Day 13 Authentication Investigation Report

## 1. Objective
Build and test basic authentication-hunting detections using a labelled synthetic dataset.

## 2. Method
Imported CSV events into PowerShell, parsed timestamps, grouped events by account and source IP, and tested:
- Repeated authentication failures followed by success within five minutes.
- Multiple accounts experiencing failures from one source within five minutes.

## 3. Findings

### Finding A — Failure-to-success sequence
- Account: `alex`
- Source IP: `192.0.2.10`
- Failed logons: 5
- Subsequent successful logons: 1
- Window: five minutes
- Assessment: Investigate the sequence if observed in real telemetry.

### Finding B — Possible password spraying
- Source IP: `192.0.2.20`
- Failed attempts: 3
- Unique accounts: 3
- Window: five minutes
- Assessment: Review as a possible password-spraying pattern.

## 4. Interpretation
Finding A could represent repeated password guessing followed by a successful authentication, but the pattern alone does not establish that the success was caused by an attacker. Finding B is consistent with a possible spraying pattern, but three accounts alone are not sufficient to confirm an attack.

## 5. Evidence and scope
All events used for these two findings came from `data/training-auth-events.csv`, a synthetic dataset created for this exercise. These results are not findings from the host's Windows Security log. No real user credentials or raw Windows event exports are included in this report.

## 6. Limitations
- The dataset is small and artificial.
- The rules do not incorporate account baselines, lockouts, network reputation, or other telemetry.
- The implementation is a learning prototype and may need deduplication and performance improvements.
- Real-world investigations require validation against authorized log sources and a broader timeline.

## 7. Recommended analyst actions
If a similar alert appears in a real environment:
1. Verify the event timestamps, account, source, and logon type.
2. Check whether the successful logon was expected and whether it was followed by unusual activity.
3. Correlate with endpoint, VPN, identity-provider, and other available logs.
4. Escalate according to organizational procedures if evidence supports suspicious activity.

## 8. Conclusion
Both detection tests returned the expected results against synthetic training data. The exercise demonstrates basic event correlation and cautious, evidence-based assessment. It does not establish a real security incident.
