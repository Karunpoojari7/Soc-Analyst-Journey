\# Day 20 — Windows Authentication \& Privileged Account Investigation



\## 1. Investigation Overview



\*\*Investigation type:\*\* Windows Authentication Security Investigation  

\*\*Platform:\*\* Windows 11 standalone workstation  

\*\*Evidence source:\*\* Windows Security Event Log  

\*\*Observation period:\*\* Seven days  

\*\*Tools:\*\* PowerShell 5.1, Windows Security Logs



\### Objective



Investigate authentication activity, identify repeated failed logons, examine privileged sessions, and assess potential account-related security risks.



\## 2. Authentication Baseline



| Event | Observed count |

|---|---:|

| Successful logons (4624) | 429 |

| Failed logons (4625) | 1 during the initial 24-hour check |



Three failed logon events were subsequently identified across the seven-day investigation period.



\## 3. Failed Authentication Investigation



\*\*Event ID:\*\* 4625



Three failed logons were identified against the same local account.



All three events showed:

\- Logon Type 2 — Interactive

\- Status `0xC000006D`

\- SubStatus `0xC000006A` — Incorrect password



Two events showed a local loopback source. One event did not provide a source address.



\### Time-window analysis



\*\*Detection window:\*\* Five minutes  

\*\*Illustrative threshold:\*\* Five failures



| Event date | Failures in five minutes |

|---|---:|

| 2 November 2026 | 1 |

| 3 November 2026 | 1 |

| 5 November 2026 | 1 |



No rapid failed-logon burst was detected.



\## 4. Detection Engineering



A PowerShell hunting script was developed to:

\- Retrieve Event ID 4625.

\- Extract authentication fields.

\- Group failed logons by account.

\- Identify accounts reaching a configurable threshold.



The script identified one account with three failures.



\*\*Limitation:\*\* The initial detector uses an observation-period account count. It is not a complete brute-force or password-spraying detection system.



\## 5. Privileged Account Investigation



Event ID 4672 was examined.



One privileged interactive session was correlated with Event ID 4624 using the same Logon ID.



The account was confirmed as a member of the local Administrators group.



The observed session is consistent with an existing local administrator account receiving special privileges.



\### Account and group changes



| Event ID | Investigation | Result |

|---|---|---|

| 4720 | User account creation | 0 events |

| 4728 | Global group additions | 0 events |

| 4732 | Local group additions | 0 events |



No matching events were found in the examined seven-day period.



\## 6. Kerberos and NTLM Investigation



The workstation was confirmed to be standalone and part of WORKGROUP rather than an Active Directory domain.



\- Event ID 4776: No matching events found.

\- Domain-controller Kerberos events 4768, 4769 and 4771: Not available from this workstation's local investigation.

\- Local authentication package configuration was inspected.



The absence of Event ID 4776 does not prove NTLM is unused.



\## 7. Authentication Correlation



The latest 30 authentication events were examined.



Most displayed successful logons were Type 5 service logons associated with SYSTEM.



Interactive Type 2 logons were also observed.



No confirmed malicious authentication sequence was established from the displayed timeline.



\## 8. Final SOC Assessment



\*\*Disposition:\*\* No confirmed malicious activity identified.



\### Evidence supporting the assessment



\- Three failed logons were distributed across several days.

\- No five-minute burst was detected.

\- The failed events showed incorrect-password status.

\- The examined privileged session correlated with a successful local administrator logon.

\- No matching account-creation or privileged-group-addition events were found in the seven-day window.



\### Investigation limitations



\- Analysis was restricted to locally retained Windows Security events.

\- The workstation was not domain joined.

\- No domain-controller telemetry was available.

\- Historical process attribution could not be established for the failed logon.

\- Absence of an event does not prove the corresponding activity never occurred.



\## 9. Recommended Follow-up



1\. Monitor repeated failed logons using time-based thresholds.

2\. Review local administrator membership periodically.

3\. Investigate unexpected privileged logons.

4\. Enable suitable centralized authentication monitoring.

5\. Use a separate Active Directory lab to practise domain authentication investigations.



\## 10. Conclusion



This investigation demonstrated practical Windows authentication analysis, failed-logon detection, privileged session correlation, local account investigation, and evidence-based incident assessment.



No confirmed malicious activity was identified in the evidence examined.



The findings are limited to the available endpoint telemetry and should not be interpreted as proof that the workstation has never experienced an attack.

