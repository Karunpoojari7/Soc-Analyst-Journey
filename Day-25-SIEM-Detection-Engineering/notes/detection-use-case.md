# DET-SSH-001 – SSH Multiple Authentication Failures

## Objective
Identify repeated SSH password authentication failures from a
single source IP within a ten-minute rolling window.

## Detection Specification
- Detection ID: DET-SSH-001
- Data source: Linux SSH authentication logs
- Event: Failed password authentication
- Threshold: 5 or more failures
- Time window: 600 seconds
- Grouping field: Source IP
- Severity: High
- ATT&CK tactic: Credential Access
- ATT&CK technique: T1110 – Brute Force
- Sub-technique: T1110.001 – Password Guessing

## Correlation
A successful SSH login from the same source after the
threshold is reached increases investigation priority.

## False Positive Scenarios
- Legitimate users entering incorrect passwords.
- Multiple users sharing a NAT gateway.
- Misconfigured automation.
- Expired service-account credentials.

## Recommended Analyst Actions
1. Review the source IP and authentication timeline.
2. Identify the affected account and its owner.
3. Check whether the successful login was expected.
4. Correlate with endpoint, identity, and network telemetry.
5. Escalate according to organisational incident response policy.

## Limitations
- Source IP alone cannot identify an individual user.
- Synthetic evidence does not establish real compromise.
- The threshold requires validation against production baselines.
- The Sigma event-level rule does not independently implement
  the Python engine's threshold correlation.
