# Day 35 — Incident Impact Assessment

## Case
MGM Resorts 2023 Cyberattack — SOC Training Investigation

## Evidence Classification
Synthetic training dataset inspired by publicly reported incident details.
These are not original MGM forensic logs.

## 1. Identity Security
Observed:
- Three failed authentication attempts for employee01.
- Successful login from a different source IP.
- MFA registration after successful login.
- Privilege change after MFA registration.
- Subsequent administrative access.

Assessment:
The sequence is suspicious and warrants identity compromise investigation.

## 2. Endpoint Security
Observed in synthetic endpoint records:
- User session started.
- Administrative console access.
- PowerShell process activity.
- Service enumeration activity.

Assessment:
Additional endpoint telemetry is required to determine whether these
activities were authorised or malicious.

## 3. Network Security
Observed in synthetic network records:
- Four TCP connections over destination port 443.
- Connections originated from the same simulated source IP.
- Destinations include simulated administrative and internal API services.

Assessment:
Connection metadata alone does not establish data exfiltration or command
and control activity. DNS, proxy, firewall and packet-level evidence
would be required.

## 4. Business Impact
Potential impact in the simulated environment:
- Unauthorised account access.
- Privilege misuse.
- Exposure of administrative functions.

Actual MGM business impact must be described separately using public
company disclosures and reliable reporting.

## 5. Severity
Training assessment: HIGH PRIORITY

Rationale:
Multiple suspicious identity events occur in a short sequence,
including MFA registration and privilege change.

This is an investigation priority, not proof of a confirmed breach.

## 6. Evidence Gaps
- Original identity-provider audit logs.
- Helpdesk verification records.
- MFA approval and enrollment history.
- Endpoint detection telemetry.
- Privileged access audit records.
- Network flow and proxy logs.
- Data access and exfiltration evidence.

## Conclusion
The synthetic evidence supports escalation for identity compromise
investigation. It does not establish the real MGM attack timeline,
attacker identity, data exfiltration path or ransomware execution.
