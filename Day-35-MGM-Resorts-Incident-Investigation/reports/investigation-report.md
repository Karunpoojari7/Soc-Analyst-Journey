# SOC Incident Investigation Report
## Day 35 — MGM Resorts Cyberattack Case Study

**Analyst:** Karun H G  
**Investigation:** Identity compromise and suspicious administrative activity  
**Case reference:** DAY35-MGM-001  
**Evidence type:** Synthetic training data

---

## 1. Executive Summary

This exercise investigates suspicious identity activity using a synthetic
dataset inspired by the publicly reported MGM Resorts cyberattack of 2023.

The dataset contains failed authentication attempts, a subsequent
successful login from a different source IP, MFA registration,
a privilege change and administrative activity.

Automated analysis identified a suspicious event sequence associated
with employee01.

The evidence supports a high-priority investigation. It does not prove
that the simulated account was compromised.

## 2. Investigation Scope

Evidence examined:
- Identity authentication events.
- Endpoint process events.
- Network connection metadata.

Tools:
- Python 3.
- CSV parsing.
- SHA-256.
- JSON validation.
- MITRE ATT&CK reference framework.

## 3. Key Findings

### Identity
- Three failed login attempts.
- Successful login from a different source IP.
- MFA registration two minutes after successful login.
- Privilege change five minutes after successful login.
- Administrative access nine minutes after successful login.

### Endpoint
- Administrative console activity.
- PowerShell process activity.
- Service enumeration.

### Network
- Four simulated TCP connections over port 443.
- All originate from the same simulated source IP.

## 4. Detection Result

Alert: DAY35-employee01

Severity: HIGH

Detection conditions:
- At least three failed logins from a different source IP.
- Successful login.
- MFA registration within ten minutes.
- Privilege change within ten minutes.

Assessment:
Suspicious identity activity requiring analyst investigation.

## 5. MITRE ATT&CK

Potential mappings are documented in mitre-attack-mapping.md.

Mappings are hypotheses based on simulated behaviour and are not
confirmed techniques used in the actual MGM incident.

## 6. Evidence Integrity

SHA-256 hashes are stored in:
output/evidence-sha256.txt

Verification must pass before evidence is considered unchanged.

## 7. Incident Response

Recommended actions:
1. Validate the account activity with its owner.
2. Review helpdesk and MFA enrollment records.
3. Revoke suspicious sessions if compromise is confirmed.
4. Review privilege changes.
5. Preserve identity and endpoint evidence.
6. Reset credentials and re-enrol MFA through a verified process.
7. Monitor for recurring suspicious activity.

## 8. Limitations

This exercise uses synthetic logs.
No access was obtained to MGM internal systems, original logs,
customer records or forensic evidence.

The dataset cannot establish the real attacker's identity,
initial access method, data exfiltration or ransomware execution.

## 9. Conclusion

The exercise demonstrates how a SOC analyst can correlate identity,
endpoint and network events to identify suspicious account activity.

The investigation produced an automated detection candidate,
a correlated timeline, evidence hashes and response recommendations.

The next step is to validate detection logic against broader datasets
and integrate it into a SIEM environment.
