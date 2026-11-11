# Day 25 – SIEM Detection Engineering Report

## 1. Executive Summary

This project developed two Python-based SSH authentication
detections using synthetic Linux authentication events.

DET-SSH-001 identifies repeated SSH authentication failures.
DET-SSH-002 identifies repeated failures involving multiple
distinct usernames.

Both detection engines were executed and tested successfully
against controlled synthetic scenarios.

No actual compromise was established.

## 2. Detection Use Cases

### DET-SSH-001 – SSH Multiple Authentication Failures

- Threshold: 5 failed attempts
- Window: 10 minutes
- Grouping: Source IP
- Severity: High
- MITRE ATT&CK: T1110
- Successful-login correlation: Implemented

### DET-SSH-002 – SSH Multiple Username Attempts

- Threshold: 5 failed attempts
- Distinct usernames: 3 or more
- Window: 10 minutes
- Grouping: Source IP
- Severity: Medium
- MITRE ATT&CK: T1110

## 3. Evidence

Dataset: evidence/raw/ssh-auth-events.log

SHA-256:
a81dc116c11db6664b7aae952d858335bc76337204cc3087d9a418d08e6c823c

The original synthetic dataset contains nine events:
- Six failed authentication events.
- Two successful authentication events.
- One session-open event.

## 4. Detection Findings

### DET-SSH-001

- Source: 198.51.100.23
- Failed attempts: 5
- Threshold reached: 2026-11-10 02:04:40 UTC (assumed)
- Successful login: 2026-11-10 02:05:50 UTC (assumed)
- Account: svc-backup
- Assessment: REVIEW_REQUIRED

### DET-SSH-002

- Source: 198.51.100.23
- Failed attempts: 5
- Distinct usernames: 3
- Usernames: admin, test, svc-backup
- First failure: 2026-11-10 02:00:01 UTC (assumed)
- Last failure: 2026-11-10 02:04:40 UTC (assumed)
- Assessment: REVIEW_REQUIRED

Both detections identified the intended patterns in the
synthetic training evidence.

## 5. Detection Engineering Components

- Python SSH log normalizer.
- Python SSH brute-force detection engine.
- Python SSH username enumeration detection engine.
- Sigma event-level detection rule.
- Structured JSON detection outputs.
- Automated positive and negative test suites.

## 6. Automated Detection Testing

### DET-SSH-001

| Test | Scenario | Result |
|---|---|---|
| TC-01 | Five failures within ten minutes | PASS |
| TC-02 | Four failures below threshold | PASS |
| TC-03 | Five failures across fifteen minutes | PASS |
| TC-04 | Failures followed by successful login | PASS |

### DET-SSH-002

| Test | Scenario | Result |
|---|---|---|
| TC-05 | Five failures and three usernames | PASS |
| TC-06 | Four failures and three usernames | PASS |
| TC-07 | Five failures and two usernames | PASS |
| TC-08 | Five failures across fifteen minutes | PASS |

Total tests: 8
Passed: 8
Failed: 0

These results apply only to the eight controlled synthetic
test cases. They do not establish production detection accuracy.

## 7. False Positive Considerations

- Legitimate users entering incorrect passwords.
- Shared public IP addresses and NAT gateways.
- Misconfigured automation.
- Expired service-account credentials.
- Legitimate administrative testing.
- Password management systems retrying authentication.

## 8. Recommended SOC Analyst Actions

1. Review the authentication timeline.
2. Identify the account owner.
3. Validate whether the successful login was expected.
4. Correlate identity, endpoint and network telemetry.
5. Review the affected account's subsequent activity.
6. Escalate according to organisational incident response policy.

## 9. Limitations

- All attack events are synthetic.
- Source IP addresses belong to documentation-only ranges.
- The year 2026 and UTC timezone are assumptions.
- Event ordering is assumed by the detection implementations.
- The Sigma rule detects individual failures; threshold
  correlation is implemented in Python.
- No actual compromise was established.
- Production detection quality has not been measured.
- Eight controlled tests do not represent all possible behaviours.

## 10. Conclusion

The project successfully implemented two SSH authentication
detection use cases.

Both engines generated the expected findings, and all eight
controlled test cases passed.

The work demonstrates log normalization, threshold detection,
username-based detection, event correlation, Sigma rule creation
and automated validation.

Further testing against representative production telemetry
and an aggregation-capable SIEM is required before deployment.
