# Day 37 — MITRE ATT&CK Investigation Notes

## Scope

This mapping concerns synthetic training evidence only.
It does not describe confirmed techniques used in the real NCIC incident.

| Observed behaviour | Possible ATT&CK technique | ID | Qualification |
|---|---|---|---|
| Repeated login failures | Brute Force | T1110 | Pattern requires investigation |
| Use of a legitimate account | Valid Accounts | T1078 | Does not prove account compromise |
| Privilege modification | Account Manipulation | T1098 | Verify authorization |
| Suspicious PowerShell execution | PowerShell | T1059.001 | Process execution alone is not malicious proof |
| Large data movement | Exfiltration tactic | TA0010 | Transfer does not prove successful theft |

## Investigation questions

1. Was the login activity authorized?
2. Was the privilege modification approved?
3. Were database queries consistent with the user's role?
4. Was the export legitimate?
5. Was the network destination authorized?
6. Can endpoint activity be explained by normal administration?

## Defensive priorities

- Enforce least privilege.
- Require strong MFA.
- Monitor privileged account changes.
- Audit sensitive database queries.
- Alert on unusual exports.
- Correlate application, identity and network telemetry.
- Preserve tamper-resistant audit records.

Reference:
https://attack.mitre.org/
