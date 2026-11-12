# Day 26 – SOC Investigation Simulation Report

## 1. Executive Summary

A synthetic SOC alert was investigated involving repeated
SSH authentication failures followed by successful access
to the svc-backup account.

Subsequent events included a session opening, privileged
command activity, Python process execution, outbound TLS
communication and account configuration activity.

The evidence supports a high-priority investigation and
escalation to Tier 2 SOC.

No actual compromise was confirmed.

## 2. Incident Identification

- Incident ID: SOC-2026-026
- Organisation: NEXORA Technologies (fictional)
- Host: nexora-linux-01
- Account: svc-backup
- Source IP: 198.51.100.23
- Dataset: Synthetic training evidence
- Classification: UNDER_INVESTIGATION
- Priority: HIGH
- Escalation: Tier 2 SOC

## 3. Investigation Timeline

| Time | Event |
|---|---|
| 09:00:01 | First failed SSH login |
| 09:01:10 | Second failed SSH login |
| 09:02:20 | Third failed SSH login |
| 09:03:30 | Fourth failed SSH login |
| 09:04:40 | Fifth failed SSH login |
| 09:05:50 | Successful SSH login |
| 09:06:00 | Session opened |
| 09:08:12 | Privileged command event |
| 09:10:30 | Python process execution |
| 09:12:15 | Outbound TLS connection |
| 09:15:00 | Account activity |

All timestamps originate from synthetic UTC evidence.

## 4. Technical Findings

- Five failed SSH authentication events.
- One successful password authentication.
- One session-open event.
- One privileged command event.
- One Python process execution event.
- One outbound TLS connection to port 443.
- One account configuration activity event.

## 5. Evidence Integrity

Original evidence:
evidence/raw/incident-events.json

SHA-256:
19c6bc2e79ab86d4561fc848e6906724900d62f9b47d2e7918e9a5a1a84cad9b

A working copy was created and its hash matched the
original evidence at the time of verification.

## 6. Investigation Assessment

The sequence of authentication failures and successful
login warrants further investigation.

Post-login activity is temporally associated with the
same host and account.

However, session identifiers, complete process information,
command details and network-transfer metadata are unavailable.

## 7. Severity and Classification

- Investigation priority: HIGH
- Classification: UNDER_INVESTIGATION
- Confirmed compromise: NO
- Escalation: REQUIRED

The priority is provisional and based on the combination
of suspicious authentication and post-login indicators.

## 8. Recommended Actions

1. Validate the account owner and expected login activity.
2. Review authentication and session records.
3. Obtain the exact sudo command and exit status.
4. Collect process command lines and parent process details.
5. Investigate outbound network traffic and destination.
6. Review account configuration changes.
7. Preserve evidence before any remediation.
8. Escalate to Tier 2 SOC.

## 9. Limitations

- All evidence is synthetic.
- Source IP addresses are documentation-only addresses.
- Successful login does not independently prove compromise.
- TLS communication does not prove data exfiltration.
- Account modification details are incomplete.
- Process attribution is not fully established.
- No real containment action was performed.

## 10. Conclusion

The investigation identified a suspicious SSH authentication
sequence followed by several potentially sensitive events.

The evidence justifies escalation and additional investigation.

The available data does not establish confirmed compromise.

Further authentication, endpoint, identity and network
telemetry is required to determine the actual impact.
