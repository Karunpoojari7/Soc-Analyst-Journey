# DET-SSH-002 — SSH Multiple Username Attempts

## 1. Objective

Identify a source IP attempting SSH password authentication
against multiple usernames within a short time window.

## 2. Detection Specification

- Detection ID: DET-SSH-002
- Detection name: SSH Multiple Username Attempts
- Data source: Linux SSH authentication logs
- Failed authentication threshold: 5
- Distinct username threshold: 3
- Time window: 10 minutes
- Grouping field: Source IP
- Severity: Medium
- MITRE ATT&CK: T1110 - Brute Force
- Assessment: REVIEW_REQUIRED

## 3. Detection Logic

Generate a finding when a source IP produces at least five
failed SSH authentication events involving at least three
distinct usernames within a ten-minute window.

## 4. Investigation Findings

The synthetic training dataset produced one finding:

- Source IP: 198.51.100.23
- Failed attempts: 5
- Distinct usernames: 3
- Target usernames: admin, test, svc-backup
- First failure: 2026-11-10 02:00:01 UTC (assumed)
- Last failure: 2026-11-10 02:04:40 UTC (assumed)
- Assessment: REVIEW_REQUIRED

The source address is documentation-only and does not
represent a real attacker.

## 5. Automated Testing

| Test | Scenario | Expected result | Result |
|---|---|---|---|
| TC-05 | 5 failures, 3 usernames | Alert | PASS |
| TC-06 | 4 failures, 3 usernames | No alert | PASS |
| TC-07 | 5 failures, 2 usernames | No alert | PASS |
| TC-08 | 5 failures across 15 minutes | No alert | PASS |

Total tests: 4
Passed: 4
Failed: 0

## 6. SOC Investigation Recommendations

1. Review the authentication timeline.
2. Identify whether attempted usernames are valid accounts.
3. Check whether the targeted account owners recognise the activity.
4. Correlate successful logins with the suspicious source.
5. Review endpoint and network telemetry.
6. Escalate according to organisational incident response policy.

## 7. Limitations

- Evidence is synthetic.
- Source IP addresses are documentation-only.
- The year 2026 and UTC timezone are assumptions.
- The detector assumes chronological event ordering.
- The detection does not establish malicious intent.
- A finding does not prove account compromise.
- Production accuracy has not been measured.

## 8. Conclusion

DET-SSH-002 successfully identified the intended
multiple-username authentication pattern in the synthetic
training dataset.

All four controlled test cases passed.

The detection is suitable as a learning implementation
and requires further validation before production deployment.
