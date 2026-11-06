# Day 12 — Endpoint Threat Hunting with Sysmon

## Objective
Investigate Windows process-creation telemetry using Sysmon Event ID 1.

## Environment
- Windows: Windows 10 Home Single Language (reported by initial check)
- Sysmon: Version 15.22
- Log: Microsoft-Windows-Sysmon/Operational
- Event: ID 1 — Process Create

## Controlled Activity
- Started Notepad using PowerShell.
- Started a separate PowerShell process with a harmless lab marker.
- Queried process-creation events.

## Findings
1. The PowerShell command line contained the marker
   DAY12-SOC-LAB benign process test.
2. Notepad process-creation events were recorded.
3. Events included executable paths, command lines, parent process
   information, user context, and SHA-256 hashes.
4. One Notepad event listed PowerShell as its parent. Another
   listed Notepad as its parent; the relationship needs further
   investigation before drawing a definitive conclusion.
5. Windows service and PostgreSQL process events were also observed.

## Assessment
The controlled PowerShell test was recorded as expected.
Notepad activity was also observed. The collected evidence does
not establish malicious activity.

## Limitations
- This was a small, controlled investigation.
- Only selected process-creation events were reviewed.
- A file hash alone does not establish maliciousness.
- The overall security of the endpoint was not assessed.

## Next Steps
- Correlate process GUIDs and timestamps.
- Validate file metadata and hashes where appropriate.
- Correlate endpoint activity with other telemetry sources.
