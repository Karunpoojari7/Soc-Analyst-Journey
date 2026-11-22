# Day 36 — MITRE ATT&CK Mapping

## 1. Purpose

Map observed events from the synthetic third-party incident investigation
to MITRE ATT&CK Enterprise techniques.

This is a training simulation. It is not a reconstruction of the actual
JPMorgan incident.

## 2. Technique mapping

| Technique | ATT&CK ID | Supporting evidence | Confidence |
|---|---|---|---|
| Brute Force | T1110 | Two failed authentication attempts followed by success | Low |
| Valid Accounts | T1078 | Successful authentication using vendor_user01 | Medium |
| Account Manipulation | T1098 | Role-change event granting elevated privileges | Medium |
| PowerShell | T1059.001 | powershell.exe process-start event | Medium |
| Archive Collected Data | T1560.001 | archive-tool.exe file-archive event | Medium |

Confidence describes how strongly the synthetic logs support the
behavioural mapping. It does not establish attacker attribution.

## 3. Data movement assessment

The synthetic network logs show two large outbound connections:

- 8,500,000 bytes at 08:25
- 12,000,000 bytes at 08:27

The customer-data logs also show large export operations.

These events justify investigating possible data exfiltration
(Tactic TA0010), but they do not independently prove that data
was successfully exfiltrated.

The destination addresses are documentation-only IP addresses.
No real external infrastructure is represented.

## 4. Important limitations

- All evidence in this lab is synthetic.
- IP addresses use RFC 5737 documentation ranges.
- Two failed logins are not sufficient to prove brute force.
- A successful login does not prove that an account was compromised.
- A process name alone does not prove malicious execution.
- Large network transfers do not prove successful data theft.
- No actual JPMorgan internal logs or forensic artifacts were used.

## 5. Defensive priorities

1. Review authentication failures followed by successful logins.
2. Enforce MFA and conditional access for vendor accounts.
3. Alert on unexpected role or privilege changes.
4. Monitor PowerShell and archive utility execution.
5. Establish data-export thresholds and vendor-specific baselines.
6. Correlate data exports with network transfer activity.
7. Review third-party access permissions and session lifetimes.

## 6. Reference

MITRE ATT&CK Enterprise:
https://attack.mitre.org/

T1110 — Brute Force:
https://attack.mitre.org/techniques/T1110/

T1078 — Valid Accounts:
https://attack.mitre.org/techniques/T1078/

T1098 — Account Manipulation:
https://attack.mitre.org/techniques/T1098/

T1059.001 — PowerShell:
https://attack.mitre.org/techniques/T1059/001/

T1560.001 — Archive via Utility:
https://attack.mitre.org/techniques/T1560/001/
