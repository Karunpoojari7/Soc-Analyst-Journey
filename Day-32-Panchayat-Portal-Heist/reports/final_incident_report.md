# SOC Incident Investigation Report

## 1. Incident Information

| Field | Details |
|---|---|
| Incident ID | INC-DAY32-001 |
| Investigation | Panchayat Portal Financial Fraud Simulation |
| Severity | CRITICAL |
| Investigation Type | Synthetic SOC Investigation |
| Environment | Kali Linux WSL2 |
| Investigation Date | 18 November 2026 |
| Analyst | SOC Analyst Trainee |
| Data Classification | Fictional Training Data |

## 2. Executive Summary

A simulated financial fraud scenario was investigated using synthetic
authentication, multi-factor authentication (MFA), and transaction logs.

The investigation identified repeated authentication failures followed
by a successful login, unusual MFA activity, authentication involving
multiple accounts from a common source IP, and high-value payments to
new beneficiaries.

Session-based correlation linked four transactions to one suspicious
synthetic session.

The investigation identified a simulated financial exposure of
INR 9,500,000 (INR 95 lakh).

These findings demonstrate suspicious activity within the training
dataset. They do not establish the root cause of any real-world incident.

## 3. Investigation Scope

The investigation examined:

- Authentication events
- MFA requests and approvals
- Financial transaction records
- Source IP addresses
- Device identifiers
- Session identifiers
- Transaction beneficiaries
- Maker-checker relationships

All records, users, IP addresses, devices, beneficiaries and
transactions were fictional.

## 4. Detection Results

| Detection Category | Alerts |
|---|---:|
| Authentication | 3 |
| MFA | 4 |
| Financial Fraud | 10 |
| Total | 17 |

## 5. Key Findings

### 5.1 Authentication Activity

Four failed authentication attempts were followed by a successful
login for the synthetic account bdo_mandapam_01 from
198.51.100.25.

A second account, finance_checker_01, also authenticated from the
same synthetic source IP.

### 5.2 MFA Activity

Repeated MFA requests were observed for bdo_mandapam_01.

An MFA approval followed the repeated requests. The same synthetic
source IP and device were also associated with MFA approvals for
multiple accounts.

### 5.3 Financial Activity

Four high-value transactions were made to newly introduced
beneficiaries.

| Transaction | Amount |
|---|---:|
| TXN-003 | INR 25,00,000 |
| TXN-004 | INR 30,00,000 |
| TXN-005 | INR 18,00,000 |
| TXN-007 | INR 22,00,000 |
| Total | INR 95,00,000 |

### 5.4 Session Correlation

The four transactions were associated with the suspicious synthetic
session SESSION-SIM-777.

This session provided the strongest link between the authentication
and financial activity in the generated dataset.

## 6. Incident Indicators

| Indicator | Value |
|---|---|
| Synthetic source IP | 198.51.100.25 |
| Synthetic device | UNKNOWN-DEVICE-77 |
| Suspicious session | SESSION-SIM-777 |
| Accounts involved | bdo_mandapam_01, finance_checker_01 |
| New beneficiaries | 4 |
| Correlated transactions | 4 |

The IP address belongs to a documentation-only address range and
must not be interpreted as a real attacker address.

## 7. Evidence Integrity

SHA-256 hashes of the three raw synthetic log files were recorded in:

data/evidence/evidence-manifest.json

The manifest supports subsequent integrity verification of the
preserved training evidence.

## 8. Analyst Assessment

The synthetic event sequence is consistent with a possible
account-compromise and unauthorized transaction scenario.

However, the logs do not establish how credentials were obtained,
whether an OTP was intercepted, or whether any real person or system
was compromised.

Additional evidence would be needed to establish root cause.

## 9. Recommended Defensive Actions

1. Temporarily suspend suspicious sessions in a real incident,
   subject to the organization's incident response procedures.
2. Verify account ownership and recent authentication history.
3. Review MFA enrollment, approval history and recovery mechanisms.
4. Validate beneficiary creation and payment authorization records.
5. Review maker-checker segregation and approval controls.
6. Preserve authentication, application, database and audit logs.
7. Implement transaction velocity and new-beneficiary detection.
8. Investigate overlapping alerts and improve alert deduplication.
9. Rotate potentially compromised credentials after proper validation.
10. Escalate confirmed financial irregularities through authorized
    incident response and financial investigation channels.

## 10. Conclusion

The Day 32 synthetic investigation successfully demonstrated
multi-source log analysis, detection engineering, session-based
correlation, financial exposure analysis and evidence hashing.

The simulated suspicious session was linked to four high-value
transactions representing INR 95 lakh in synthetic financial exposure.

The investigation is a defensive training exercise and does not
constitute a forensic finding about an actual government portal.

---
End of Report
