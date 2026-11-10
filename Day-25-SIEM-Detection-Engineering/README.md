# Day 25 – SIEM Detection Engineering

## Objective
Build, test, and document a Python-based SSH brute-force detection
use case using synthetic Linux authentication events.

## Detection Use Case
- Detection ID: DET-SSH-001
- Detection: SSH Multiple Authentication Failures
- Threshold: 5 failed authentication attempts
- Time window: 10 minutes
- Grouping: Source IP
- Severity: High
- MITRE ATT&CK: T1110 – Brute Force
- Sub-technique: T1110.001 – Password Guessing

## Investigation Workflow
1. Prepare synthetic SSH authentication evidence.
2. Normalize raw authentication logs into JSON.
3. Build a threshold-based Python detection engine.
4. Create a Sigma event-level detection rule.
5. Correlate failed and successful authentication events.
6. Test positive and negative detection scenarios.
7. Document false positives and detection limitations.
8. Generate a final detection engineering report.

## Project Structure
- evidence/raw/ – Synthetic SSH authentication dataset
- evidence/working/ – Normalized JSON events
- notes/ – Detection use case documentation
- scripts/ – Log normalizer and detection engine
- rules/sigma/ – Sigma detection rule
- tests/ – Detection test cases
- output/ – Detection findings and test results
- reports/ – Final investigation report

## Run the Lab

Normalize the evidence:

    python3 -B scripts/normalize_ssh_logs.py

Run the detection engine:

    python3 -B scripts/ssh_bruteforce_detector.py

Run detection tests:

    python3 -B tests/test_ssh_detection.py

## Test Results
- TC-01: Five failures within ten minutes – PASS
- TC-02: Four failures within ten minutes – PASS
- TC-03: Five failures across fifteen minutes – PASS
- TC-04: Five failures followed by successful login – PASS

Total: 4 passed, 0 failed.

## Safety and Limitations
- All attack events are synthetic.
- IP addresses are documentation-only addresses.
- Year and UTC interpretation are lab assumptions.
- The Sigma rule detects individual failures; threshold correlation
  is implemented by the Python engine.
- No actual compromise was established.
- Production detection accuracy has not been measured.

See reports/Day25-SIEM-Detection-Engineering-Report.md
for the full investigation.
