# DET-SSH-001 – Detection Test Results

Dataset: Synthetic training evidence
Threshold: 5 failed logins
Window: 10 minutes
Grouping: Source IP

| Test | Scenario | Expected | Actual |
|---|---|---|---|
| TC-01 | 5 failures within window | Alert | Pass |
| TC-02 | 4 failures within window | No alert | Pass |
| TC-03 | 5 failures across 15 minutes | No alert | Pass |
| TC-04 | 5 failures followed by success | Alert and correlation | Pass |

Total test cases: 4
Passed: 4
Failed: 0

## Assessment
All four controlled test cases passed.

This result validates the tested scenarios only. It does not
establish production detection accuracy, precision, or recall.

## Analyst Conclusion
The detection successfully identifies the intended synthetic
SSH authentication pattern. Further validation against real
production logs and legitimate authentication behaviour is
required before deployment.
