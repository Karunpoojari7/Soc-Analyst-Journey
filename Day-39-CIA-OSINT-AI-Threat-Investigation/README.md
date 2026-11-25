Day 39 — CIA / OSINT AI Threat Investigation

Project Overview

A defensive Security Operations Center (SOC) investigation simulation focused on identifying suspicious activity across identity, API, cloud, endpoint and network telemetry.

This project demonstrates a multi-source security investigation workflow using Python, synthetic security evidence, detection rules, event correlation and evidence integrity verification.

Investigation Objectives

- Analyse authentication activity and identify suspicious login patterns.
- Investigate unusual API requests and export operations.
- Detect cloud IAM modifications and storage export activity.
- Examine suspicious endpoint process relationships.
- Identify unusually large outbound network transfers.
- Consolidate alerts and construct a chronological investigation timeline.
- Document findings, limitations and recommended SOC responses.

Technology Stack

- Python
- CSV-based security telemetry
- JSON detection outputs
- SHA-256 evidence hashing
- MITRE ATT&CK framework
- Termux / Linux environment
- Git and GitHub

Project Structure

Day-39-CIA-OSINT-AI-Threat-Investigation/
├── detection-rules/
├── docs/
├── evidence/
│   ├── api-logs/
│   ├── cloud-logs/
│   ├── endpoint-logs/
│   ├── identity-logs/
│   └── network-logs/
├── output/
├── scripts/
├── tests/
└── timeline/

Investigation Workflow

1. Generate synthetic multi-source evidence.
2. Analyse security events.
3. Implement authentication and API detection.
4. Investigate cloud, endpoint and network activity.
5. Consolidate detection alerts.
6. Correlate events into an investigation timeline.
7. Perform benign-event testing and document detection limitations.
8. Generate the final SOC investigation report.
9. Calculate SHA-256 hashes for evidence files.

Important Detection Areas

- Repeated authentication failures followed by successful login.
- Privilege and IAM role modifications.
- Rapid API requests and large export operations.
- Cloud storage export activity.
- Suspicious process execution relationships.
- Large outbound network transfers.

Evidence and Validation

The evidence datasets are synthetic and intended for defensive training.

Detection outputs and test results must be validated by executing the corresponding scripts. The presence of an alert or detection rule does not independently establish a successful compromise.

Investigation Limitations

- No actual CIA or ODNI infrastructure was accessed.
- No real intelligence telemetry was collected.
- The simulation does not reconstruct a confirmed real-world intrusion.
- The synthetic evidence does not establish attacker identity or attribution.
- Large outbound transfers do not independently prove data exfiltration.
- The reported association with ARTEX is not demonstrated by this simulation.

Learning Outcomes

- Multi-source security log analysis.
- Python-based detection engineering.
- SOC alert triage and correlation.
- Evidence integrity verification.
- False-positive analysis.
- MITRE ATT&CK mapping.
- Professional incident reporting.

Project classification: Educational defensive cybersecurity simulation.

