\# Privileged Account Investigation



\## Objective



Investigate Windows privileged logon activity and local account group membership.



\## Evidence Reviewed



\- Event ID 4672 — Special privileges assigned to a new logon.

\- Event ID 4624 — Successful logon.

\- Event ID 4720 — User account created.

\- Event ID 4728 — Member added to a global security group.

\- Event ID 4732 — Member added to a local security group.



\## Privileged Session Correlation



One Event ID 4672 was correlated with Event ID 4624 using the same Logon ID.



Observed characteristics:



\- Logon Type: 2 — Interactive.

\- Account: Local user account.

\- Special privileges were assigned to the session.

\- The account was a member of the local Administrators group.



\## Account and Group Membership Changes



| Event ID | Description | Events found |

|---|---|---:|

| 4720 | User account creation | 0 |

| 4728 | Global group additions | 0 |

| 4732 | Local group additions | 0 |



No matching events were found in the examined seven-day period.



\## SOC Assessment



The privileged session examined was consistent with an existing local administrator account receiving special privileges.



No unauthorized privilege escalation was established from the available evidence.



\## Investigation Limitations



\- Group membership alone does not establish whether a specific session was authorized.

\- Event ID 4672 indicates privilege assignment, not proof that privileges were abused.

\- The investigation was limited to locally retained Windows Security events.

\- Absence of matching events does not establish that account or group changes never occurred historically.



\## Conclusion



The examined privileged session had a plausible explanation based on the account's existing local administrator membership. No confirmed malicious privilege escalation was identified.

