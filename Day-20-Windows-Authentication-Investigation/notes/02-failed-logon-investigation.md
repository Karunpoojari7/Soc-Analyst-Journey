\# Failed Authentication Investigation



\## Objective



Investigate Windows failed authentication events using Security Event ID 4625.



\## Evidence



\- Observation period: 7 days

\- Failed logon events identified: 3

\- Target: Same local account

\- Logon Type: 2 — Interactive

\- Status: `0xC000006D`

\- SubStatus: `0xC000006A` — Incorrect password



\## Source Analysis



\- Two events recorded the local loopback address.

\- One event did not provide a source address.

\- The historical caller process was associated with `svchost.exe`.

\- The original process instance could not be retrieved during the later investigation.



\## Time-Window Analysis



Detection window: 5 minutes.



| Event date | Failures within 5 minutes |

|---|---:|

| 2 November 2026 | 1 |

| 3 November 2026 | 1 |

| 5 November 2026 | 1 |



No rapid failed-logon burst was identified.



\## Detection Development



A PowerShell script was created to retrieve Event ID 4625 and group failures by account.



The configured threshold was three failures per account over seven days. One account matched this threshold.



\## SOC Assessment



Repeated incorrect-password failures were identified. However, the events were distributed across multiple days.



No confirmed brute-force or password-spraying activity was established.



\## Limitations



\- The detector initially groups events by account.

\- It does not establish attacker intent.

\- The available data is limited to locally retained Windows Security events.

\- A threshold match is an investigation trigger, not proof of an attack.

