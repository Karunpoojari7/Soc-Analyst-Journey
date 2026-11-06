# Day 14 – Windows Persistence Investigation

## 1. Objective

Investigate Windows persistence mechanisms using PowerShell, Windows Task Scheduler and Sysmon registry telemetry.

The investigation focused on scheduled tasks, registry persistence locations, service configuration and Windows Hotpatch components.

## 2. Lab Environment

- Operating System: Windows
- Telemetry: Sysmon Operational log
- Sysmon Event IDs: 12, 13 and 14
- Investigation tools: PowerShell, Get-ScheduledTask, Get-WinEvent and Get-AuthenticodeSignature

## 3. Investigation Activities

### 3.1 Scheduled Task Inventory

Enumerated scheduled tasks and reviewed their:

- Names and task paths
- Executable actions and arguments
- Execution accounts
- Privilege levels
- Enabled or disabled state

Windows maintenance, Microsoft Defender, application maintenance and firmware-related tasks were identified.

Task names and SYSTEM privileges were treated as investigation context, not evidence of maliciousness.

### 3.2 Registry Monitoring

Configured Sysmon RegistryEvent monitoring for selected locations:

- CurrentVersion Run
- CurrentVersion RunOnce
- CurrentControlSet Services
- Winlogon
- TaskCache
- Controlled VIGILYX lab test key

### 3.3 Controlled Registry Test

Created a benign test registry key and value under:

HKCU\Software\VIGILYX-Sysmon-Lab

Observed:
- Event ID 12 – Registry object creation
- Event ID 13 – Registry value modification
- Event ID 12 – Registry key deletion

The test key was subsequently removed.

This verified that the configured Sysmon registry monitoring could capture the controlled test activity.

### 3.4 Hotpatch Scheduled Task Investigation

Investigated the Windows task:

\Microsoft\Windows\Hotpatch\Monitoring

Reviewed its action, which launches a Windows command interpreter and the hpatchmonTask.cmd script.

The script checks Hotpatch registration, Virtualization-Based Security status and the hpatchmon service configuration.

### 3.5 Service and DLL Verification

Investigated the hpatchmon service.

Observed:
- Service account: LocalSystem
- Startup type: Manual
- Host executable: svchost.exe
- Service DLL: hpatchmon.dll

The DLL was located in the Windows System32 directory.

Authenticode verification returned Valid.

Publisher: Microsoft Corporation

File description: Hotpatch Monitoring Service

The signature and file metadata support the assessment that this is a genuine Microsoft Windows component.

## 4. Detection Script

Created a PowerShell detection script to:

- Collect Sysmon registry events 12, 13 and 14.
- Extract registry target, event type and process metadata.
- Identify candidate persistence registry paths.
- Display investigation results.

Candidate path matches require manual investigation and do not establish malicious activity.

## 5. Findings

1. Scheduled task inventory revealed multiple Windows and application maintenance tasks.
2. Selected registry persistence locations were configured for Sysmon monitoring.
3. Controlled registry creation, modification and deletion were successfully observed.
4. The Windows Hotpatch monitoring task and associated script were inspected.
5. The hpatchmon service configuration and DLL were investigated.
6. The DLL returned a valid Microsoft digital signature.
7. No confirmed malicious persistence was established from the evidence examined.

## 6. Limitations

- Registry monitoring covers selected paths, not every possible persistence mechanism.
- The event collection is limited by the configured lookback period and maximum event count.
- No comprehensive review of every service, scheduled task, WMI subscription or startup location was performed.
- SFC verification could not complete because Windows reported a pending repair requiring a restart.
- A valid digital signature supports publisher identity but does not independently establish that all system activity is benign.

## 7. Conclusion

This exercise demonstrated a practical Windows persistence investigation workflow using scheduled task inventory, registry telemetry, process metadata and digital signature verification.

The investigation emphasized evidence-based triage rather than classifying system components as malicious solely because they execute with elevated privileges.

## 8. Skills Practised

- Windows persistence analysis
- Scheduled task investigation
- Sysmon configuration
- Registry event analysis
- PowerShell threat hunting
- Windows service investigation
- Digital signature verification
- Evidence-based SOC reporting
