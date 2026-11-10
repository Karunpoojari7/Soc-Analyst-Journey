# Day 25 – SIEM Detection Engineering Report

## 1. Executive Summary

This exercise developed and tested a detection for repeated SSH
password authentication failures using synthetic Linux authentication
events.

A Python-based detection engine identified five failed authentication
attempts from one source within a ten-minute window, followed by a
successful password login.

The resulting finding was classified as REVIEW_REQUIRED.

No actual compromise was established.

## 2. Detection Use Case

- Detection ID: DET-SSH-001
- Name: SSH Multiple Authentication Failures
- Data source: Linux SSH authentication logs
- Threshold: 5 failed attempts
- Time window: 10 minutes
- Grouping: Source IP
- Severity: High
- MITRE ATT&CK: T1110 – Brute Force
- Sub-technique: T1110.001 – Password Guessing

## 3. Evidence

Dataset: evidence/raw/ssh-auth-events.log

Dataset SHA-256:
a81dc116c11db6664b7aae952d858335bc76337204cc3087d9a418d08e6c823c

The dataset contains nine synthetic events:
- Six failed authentication events.
- Two successful authentication events.
- One session-open event.

## 4. Detection Findings

The detection engine identified:
- Source: 198.51.100.23
- Failed authentication attempts: 5
- First failure: Nov 10 02:00:01
- Threshold reached: Nov 10 02:04:40
- Successful login afterward: Nov 10 02:05:50
- Assessment: REVIEW_REQUIRED

The source address belongs to a documentation-only IP range.

## 5. Detection Engineering Components

- Python SSH log normalizer.
- Python threshold-based detection engine.
- Sigma event-level detection rule.
- Structured JSON detection output.
- Controlled detection test suite.

## 6. Detection Testing

| Test | Scenario | Result |
|---|---|---|
| TC-01 | Five failures within ten minutes | PASS |
| TC-02 | Four failures within ten minutes | PASS |
| TC-03 | Five failures across fifteen minutes | PASS |
| TC-04 | Five failures followed by successful login | PASS |

Total tests: 4
Passed: 4
Failed: 0

These results apply only to the four controlled synthetic test cases.

## 7. False Positive Considerations

- Legitimate users entering incorrect passwords.
- Shared public IP addresses and NAT gateways.
- Misconfigured automation.
- Expired service-account credentials.

## 8. Recommended SOC Analyst Actions

1. Review the authentication timeline.
2. Identify the affected account owner.
3. Validate whether the successful login was expected.
4. Correlate identity, endpoint, and network telemetry.
5. Escalate according to organisational incident response policy.

## 9. Limitations

- All attack events are synthetic.
- The source IPs are reserved documentation addresses.
- The dataset does not contain verified year or timezone metadata.
- The assumed year and UTC interpretation are lab assumptions.
- The Sigma rule detects individual failure events; it does not
  independently implement the Python engine's threshold correlation.
- Production detection quality has not been established.
- A detection finding does not prove account compromise.

## 10. Conclusion

The exercise successfully demonstrated the development and testing
of a basic SSH brute-force detection use case.

The Python engine identified the intended pattern and passed all
four controlled test cases.

Further validation against real production telemetry, baseline
authentication behaviour, and an aggregation-capable SIEM is
required before operational deployment.
