# Day 25 – SIEM Detection Engineering

## Objective

Develop, implement, test and document SSH authentication
detections using Python, Sigma and synthetic Linux SSH logs.

## Detection Use Cases

### DET-SSH-001 – SSH Multiple Authentication Failures

- Threshold: 5 failed authentication attempts
- Time window: 10 minutes
- Grouping: Source IP
- Severity: High
- MITRE ATT&CK: T1110
- Correlates successful login after the threshold.

### DET-SSH-002 – SSH Multiple Username Attempts

- Threshold: 5 failed authentication attempts
- Distinct usernames: 3 or more
- Time window: 10 minutes
- Grouping: Source IP
- Severity: Medium
- MITRE ATT&CK: T1110

## Project Structure

- evidence/raw/ – Synthetic SSH authentication evidence
- evidence/working/ – Normalized JSON events
- notes/ – Detection use case documentation
- scripts/ – Python normalization and detection engines
- rules/sigma/ – Sigma event-level detection rule
- tests/ – Automated detection test scripts
- output/ – Detection findings and test results
- reports/ – Final investigation report

## Detection Engineering Workflow

1. Prepare synthetic SSH authentication evidence.
2. Normalize raw authentication events.
3. Develop threshold-based detection logic.
4. Implement SSH brute-force detection.
5. Implement multiple-username detection.
6. Create a Sigma event-level rule.
7. Execute positive and negative detection tests.
8. Analyse false positives and detection limitations.
9. Document findings and recommendations.

## Run the Lab

Normalize evidence:

    python3 -B scripts/normalize_ssh_logs.py

Run DET-SSH-001:

    python3 -B scripts/ssh_bruteforce_detector.py

Run DET-SSH-002:

    python3 -B scripts/ssh_username_enum_detector.py

Run DET-SSH-001 tests:

    python3 -B tests/test_ssh_detection.py

Run DET-SSH-002 tests:

    python3 -B tests/test_ssh_username_enum.py

## Automated Test Results

### DET-SSH-001

- TC-01: Five failures within ten minutes – PASS
- TC-02: Four failures below threshold – PASS
- TC-03: Five failures across fifteen minutes – PASS
- TC-04: Failures followed by successful login – PASS

### DET-SSH-002

- TC-05: Five failures and three usernames – PASS
- TC-06: Four failures and three usernames – PASS
- TC-07: Five failures and two usernames – PASS
- TC-08: Five failures across fifteen minutes – PASS

Total: 8 passed, 0 failed.

## Safety and Limitations

- All attack events are synthetic.
- IP addresses are documentation-only addresses.
- Year and UTC interpretation are lab assumptions.
- Detection engines assume chronologically ordered events.
- Sigma rule detects individual failures; threshold correlation
  is implemented by Python.
- Detection findings do not prove account compromise.
- Production detection accuracy has not been measured.

## Documentation

- reports/Day25-SIEM-Detection-Engineering-Report.md
- notes/detection-use-case.md
- notes/ssh-username-enumeration.md
