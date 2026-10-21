# Day 5 — Linux Authentication Log Analysis

## 1. Objective
Analyze SSH authentication events to identify failed logins, successful logins, and patterns that may warrant further investigation.

## 2. Scope and Data Source
- Data source: `evidence/authentication-sample.log`
- Data type: Synthetic training data
- Analysis: Failed authentication, successful authentication, source IP counts, and event sequence.

## 3. Findings

### Finding 1 — Failed attempts against invalid usernames
Four failed-password events were recorded from `198.51.100.23`, targeting invalid usernames.

### Finding 2 — Failed attempts followed by successful authentication
Two failed-password events for `kali` were followed by an accepted password login from `203.0.113.44`.

This sequence is suspicious enough to investigate further, but does not independently establish account compromise.

### Finding 3 — Public-key authentication
An accepted public-key login for `kali` was recorded from `192.0.2.55`.

## 4. Limitations
The dataset is synthetic. No account-owner confirmation, endpoint telemetry, network investigation, or post-login activity was available.

## 5. Conclusion
The analysis identified repeated authentication failures and a failure-followed-by-success sequence. These patterns demonstrate useful investigation leads, but there is insufficient evidence to conclude that a compromise occurred.

## 6. Recommended Next Steps
- Correlate authentication events with other available logs.
- Verify whether the successful login was expected.
- Review activity following successful authentication.
- Escalate according to the incident-response process if additional evidence supports compromise.

## 7. Evidence Integrity
Record the hash of the training log and retain the original sample unchanged.
