# Day 40 — GitHub CI/CD Security Investigation

## Project Overview

A hands-on SOC analyst training project exploring GitHub account security,
repository permissions, CI/CD workflow risks, audit-event correlation,
detection validation, and incident investigation.

This project uses synthetic training data. It does not access or investigate
real 1Password infrastructure, GitHub customer accounts, or production systems.

## Investigation Objectives

- Identify risky GitHub Actions workflow configurations.
- Detect suspicious sequences in GitHub audit events.
- Correlate events by actor, repository, and source IP.
- Validate detections against benign and adversarial test cases.
- Reconstruct an incident timeline.
- Document findings and evidence integrity.

## Labs and Implementations

| Lab | Activity | Status |
|---|---|---|
| 3 | Compare weak and hardened CI/CD workflows | Implemented |
| 4 | Detect risky workflow configurations | Implemented |
| 5 | Correlate synthetic GitHub audit events | Implemented |
| 6 | Test benign events for false positives | Implemented |
| 7 | Build an improved ordered correlation engine | Implemented |
| 8 | Validate correlation logic with four test cases | Passed |
| 9 | Reconstruct incident timeline | Verify output |
| 10 | Generate SOC investigation report | Verify output |
| 11 | Generate and verify SHA-256 evidence hashes | Verify output |
| 12 | Final review and portfolio preparation | In progress |

## Detection Scenario

The synthetic suspicious sequence is:

1. `token.created`
2. `repo.permission.changed`
3. `workflow.modified`
4. `workflow.run`

The improved detector correlates events using actor, repository, and source IP,
and checks their chronological order and time window.

A detection alert is an investigation lead, not proof of compromise.

## Key Training Evidence

- Synthetic GitHub audit events
- Workflow risk detector output
- Correlation-engine alerts
- Correlation validation tests
- Incident timeline and report, when generated and verified
- SHA-256 evidence manifest, when generated and verified

## Security Lessons

- Apply least-privilege permissions to GitHub Actions workflows.
- Pin third-party actions to verified full commit SHAs.
- Avoid persisting checkout credentials when they are not needed.
- Monitor token creation and repository permission changes.
- Review workflow modifications and executions.
- Validate detections against benign activity to reduce false positives.

## Limitations

- All audit events are synthetic.
- Documentation-range IP addresses are used in the training dataset.
- No real customer data, credentials, or production logs were analysed.
- The scenario does not establish that the simulated sequence occurred
  during the real-world 1Password incident.

## Tools

- Kali Linux (WSL)
- Python 3
- Bash
- Git
- SHA-256 utilities

## Analyst Note

This project demonstrates detection engineering and investigation methods
using a controlled dataset. Real incident attribution requires verified
identity, authorization, endpoint, repository, and workflow evidence.
