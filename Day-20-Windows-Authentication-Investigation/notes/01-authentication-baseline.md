\# Windows Authentication Baseline



\## Objective



Establish a baseline of successful and failed Windows authentication activity using Security Event Logs.



\## Environment



\- Platform: Windows 11

\- Environment: Standalone WORKGROUP workstation

\- Tool: PowerShell 5.1

\- Log source: Windows Security



\## Findings



\- Security auditing log was enabled.

\- Log mode: Circular.

\- Maximum log size: 20 MiB.

\- Successful logons (4624) during the initial 24-hour check: 429.

\- Failed logons (4625) during the initial 24-hour check: 1.



\## Logon Types Observed



\- Type 2: Interactive logon.

\- Type 5: Service logon.



Repeated SYSTEM Type 5 events were observed and were consistent with normal Windows service activity.



\## Assessment



The initial authentication baseline showed predominantly successful logon activity. A failed authentication event was identified for further investigation.



\## Limitations



The initial counts represent events retained in the local Security log, not unique user sessions or a complete enterprise authentication dataset.

