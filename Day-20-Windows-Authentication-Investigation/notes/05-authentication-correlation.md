\# Authentication Event Correlation



\## Objective



Correlate successful and failed Windows authentication events to understand local authentication activity.



\## Evidence Reviewed



\- Event ID 4624 — Successful logon

\- Event ID 4625 — Failed logon

\- Event ID 4672 — Special privileges assigned to a new logon



\## Findings



1\. The latest 30-event timeline was dominated by successful Type 5 service logons associated with SYSTEM.

2\. Interactive Type 2 logons were observed for the local user account.

3\. Two interactive logon events were recorded at the same timestamp with a local loopback source.

4\. Three failed authentication events were identified in the seven-day investigation period.

5\. No five-minute failed-logon burst was identified.

6\. One Event ID 4672 was correlated with Event ID 4624 using the same Logon ID.



\## Assessment



The observed activity is consistent with normal Windows service and local interactive authentication patterns.



No confirmed malicious authentication activity or unauthorized privilege escalation was established from the available evidence.



\## Limitations



\- The investigation covers locally retained Windows Security events.

\- The workstation is not joined to an Active Directory domain.

\- Domain-controller Kerberos ticket events were not available.

\- No Event ID 4776 records were found in the examined period.

\- Event correlation alone does not establish whether an action was authorized.



\## Conclusion



No confirmed malicious activity was identified in the authentication evidence examined. Further investigation would require broader endpoint and domain authentication telemetry.

