# Day 24 – Incident Response Investigation Report

## 1. Executive Summary

A synthetic Linux SSH authentication dataset was investigated to practise
incident detection, correlation, severity assessment, and response planning.

Seven failed authentication attempts were followed by a successful
password authentication and session creation for the account svc-backup.

The investigation identified suspicious authentication behaviour requiring
escalation. Account compromise is not confirmed.

## 2. Case Information

- Case ID: IR-2026-001
- Investigation: Suspected SSH brute-force activity
- Evidence classification: Synthetic training evidence
- Provisional severity: HIGH
- Assessment: REVIEW REQUIRED
- Environment: Kali Linux Persistent Live USB

## 3. Evidence Sources

### E-001: Real host SSH baseline

File: evidence/raw/host-ssh-baseline.txt

- SSH service active.
- SSH listening on TCP port 2222.
- Four SSH service journal records observed.
- No authentication events observed in the examined current-boot records.

This evidence describes the actual Kali host and does not establish an attack.

### E-002: Synthetic authentication log

File: evidence/raw/simulated-auth.log

- Seven failed authentication attempts.
- One successful password authentication.
- One session-open event.
- Same synthetic source IP in failed and successful authentication events.

SHA-256:
5a936f1aaab8344f01ea9d5cdf4c2e39887169099a28286dfcbaffd9149fe393

The source IP 198.51.100.23 is reserved for documentation and training.

### E-003: Automated investigation output

File: output/ir-auth-investigation.json

- Nine parsed events.
- Seven failed logins.
- One successful login.
- One session opened.
- Two investigation indicators.
- Assessment: REVIEW REQUIRED.

### E-004: Incident timeline

File: output/incident-timeline.csv

Contains nine chronological events from the synthetic dataset.

## 4. Incident Timeline

| Time | Event |
|---|---|
| 06:10:02 | Failed login: invalid user admin |
| 06:10:18 | Failed login: invalid user test |
| 06:10:35 | Failed login: svc-backup |
| 06:10:52 | Failed login: svc-backup |
| 06:11:09 | Failed login: svc-backup |
| 06:11:26 | Failed login: svc-backup |
| 06:11:43 | Failed login: svc-backup |
| 06:12:01 | Successful password authentication |
| 06:12:15 | Session opened |

Timestamps are reproduced from the synthetic training dataset.
The year and timezone were not independently verified.

## 5. Detection and Analysis

The Python analyzer identified:

1. Five or more failed login events.
2. Successful authentication following failures from the same source.

The successful authentication was associated with svc-backup.

The session-open event indicates that a session was created in the
synthetic scenario. It does not establish which commands were executed
or whether data was accessed.

## 6. Severity Assessment

Provisional severity: HIGH.

Reasoning:
- Repeated failed authentication attempts.
- Subsequent successful password authentication.
- Session creation for the targeted account.
- Account privileges and login legitimacy remain unknown.

This severity is a training assessment and should be adjusted according
to an organisation's incident classification policy.

## 7. Containment Recommendations

Subject to organisational approval:

1. Preserve authentication and endpoint evidence.
2. Notify the incident response lead.
3. Validate account ownership and login legitimacy.
4. Review session activity.
5. Consider revoking active sessions if compromise is suspected.
6. Consider restricting the account through authorised procedures.
7. Investigate whether other systems were targeted.

No real containment action was performed in this lab.

## 8. Eradication Recommendations

If compromise is confirmed:

- Investigate unauthorised SSH keys.
- Review account and privilege modifications.
- Identify persistence mechanisms.
- Remove confirmed unauthorised access.
- Address the initial access weakness.
- Rotate affected credentials.

## 9. Recovery Recommendations

- Restore legitimate account access.
- Validate system integrity.
- Confirm authentication controls.
- Monitor for recurring suspicious events.
- Obtain system-owner approval before closure.

## 10. Final Analyst Conclusion

The synthetic dataset demonstrates repeated SSH authentication failures
followed by successful authentication and session creation.

The activity is suspicious and warrants escalation and further investigation.

The available evidence does not prove account compromise, unauthorised
command execution, or data exfiltration.

The real Kali host baseline and synthetic training evidence were kept
separate throughout the exercise.

## 11. Skills Demonstrated

- Linux systemd journal investigation.
- SSH service and listener verification.
- Authentication log analysis.
- Python event parsing and correlation.
- SHA-256 evidence integrity checks.
- Incident severity assessment.
- Incident timeline creation.
- Containment, eradication, and recovery planning.
- SOC incident reporting.

## 12. Limitations

- Synthetic authentication evidence.
- No real attacker or compromise established.
- No session command history available.
- No endpoint or network telemetry correlated.
- Account privileges and ownership not verified.
- No real containment or recovery action performed.

Project: SOC Analyst Learning Journey
Training Day: 24
Classification: Synthetic incident response training
