# MITRE ATT&CK Mapping — Day 35

## Investigation Context

This mapping uses synthetic training logs inspired by the
publicly reported MGM Resorts 2023 cyber incident.

These records are not MGM's original forensic evidence.

| Observed behaviour | Potential technique | Technique ID | Evidence status |
|---|---|---|---|
| Repeated failed logins | Brute Force | T1110 | Observed; intent unconfirmed |
| Successful account login | Valid Accounts | T1078 | Observed; compromise unconfirmed |
| MFA registration | Modify Authentication Process: MFA | T1556.006 | Registration observed; manipulation unconfirmed |
| Privilege change | Account Manipulation | T1098 | Observed; context required |
| PowerShell execution | PowerShell | T1059.001 | Observed in synthetic endpoint logs |
| Service enumeration | System Service Discovery | T1007 | Observed in synthetic endpoint logs |

## Analyst Assessment

The sequence of failed logins, successful login from a
different source, MFA registration and privilege change
is suspicious and warrants investigation.

The dataset does not establish the attacker's identity,
initial access method, malware execution, data exfiltration
or ransomware deployment.

## Additional Evidence Required

- Identity-provider audit logs
- MFA enrollment and approval history
- Helpdesk ticket records
- Privileged account change records
- Endpoint process command-line telemetry
- Network flow and DNS records
- EDR detection and response events

## Conclusion

ATT&CK mappings are hypotheses based on observed simulated
behaviour. They must be validated against additional
evidence before being treated as confirmed techniques.
