# Day 14 – Windows Persistence Detection

## Overview

Practical Windows endpoint persistence investigation using PowerShell, Sysmon and Windows Task Scheduler.

## Objectives

- Understand Windows persistence mechanisms.
- Investigate registry Run and RunOnce locations.
- Enumerate and analyse scheduled tasks.
- Configure Sysmon registry monitoring.
- Investigate Windows services and service DLLs.
- Verify file integrity and digital signatures.

## Tools

- Windows PowerShell
- Sysmon
- Windows Task Scheduler
- Event Viewer
- Get-WinEvent
- Get-AuthenticodeSignature
- Get-FileHash

## Practical Activities

1. Enumerated Windows scheduled tasks.
2. Reviewed task actions, execution accounts and privilege levels.
3. Configured Sysmon registry monitoring for selected persistence locations.
4. Tested registry creation, modification and deletion using a controlled lab key.
5. Investigated the Windows Hotpatch Monitoring scheduled task.
6. Inspected the associated service and DLL.
7. Verified the DLL's Microsoft digital signature.
8. Developed a PowerShell registry hunting script.

## Key Findings

- Sysmon successfully recorded controlled registry activity.
- Scheduled task configurations were reviewed.
- The Hotpatch service DLL returned a valid Microsoft digital signature.
- No confirmed malicious persistence was established from the evidence examined.

## Limitations

Monitoring covered selected registry paths and a limited event collection window. Other persistence mechanisms were not comprehensively investigated.

## Repository Structure

- config/: Sysmon configuration
- scripts/: PowerShell detection script
- notes/: Technical references
- report/: Investigation report
- evidence/: Integrity checksums

## Skills Practised

Windows persistence analysis, endpoint threat hunting, Sysmon configuration, PowerShell scripting, scheduled task investigation, service analysis and evidence-based reporting.

## Disclaimer

Performed in a personally controlled Windows lab environment. Private event logs and raw host inventory data are excluded from this public repository.

---

Day 14 – SOC Analyst Learning Journey
