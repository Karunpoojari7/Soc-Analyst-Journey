# Process and Network Investigation

## 1. Process Investigation

### Objective
Investigate running processes, parent-child relationships, executable paths and process creation telemetry.

### Evidence Sources
- Windows process inventory
- CIM process information
- Sysmon Event ID 1
- Executable paths
- Authenticode signature verification

### Observations
- MySQL and PostgreSQL processes were associated with installed database environments.
- PowerShell execution from Windows Explorer was observed.
- Windows rundll32.exe executions were associated with Windows maintenance activity.
- A scheduled task executed a Windows Hotpatch monitoring script.
- The inspected Hotpatch script passed Windows Resource Protection file-integrity verification.
- The associated Hotpatch DLL had a valid Microsoft Windows signature.

### Assessment
The investigated processes had plausible Windows or application-related explanations.

No confirmed malicious process execution was identified in the collected evidence.

A legitimate executable path or valid signature is useful provenance evidence but does not independently prove that a process is harmless.

## 2. Process-to-Network Correlation

### Objective
Correlate active TCP connections with owning processes and investigate selected application activity.

### Evidence Sources
- Get-NetTCPConnection
- Get-Process
- CIM process information
- Windows service inventory
- Authenticode signature verification
- Background Intelligent Transfer Service job metadata

### Applications and Components Investigated
- Microsoft Edge
- Windows Start Menu Experience Host
- Background Intelligent Transfer Service
- Dell Client Management Service
- Spotify Launcher
- MySQL

### Observations
- Investigated browser connections used HTTPS.
- A connection owned by svchost.exe was associated with Background Intelligent Transfer Service.
- A BITS job contained Edge Component Updater metadata and a completed transferred-byte count.
- The corresponding local artifact was unavailable for independent signature verification.
- Dell ServiceShell.exe had a valid Dell Technologies signature and was associated with Dell Client Management Service.
- MySQL connections were observed over loopback.

### Assessment
The investigated connections had plausible Windows or application-related explanations.

The BITS artifact could not be validated because the local file was unavailable. An earlier Dell connection could not be conclusively attributed to a later-observed process instance.

No confirmed malicious network activity was identified in the investigated evidence.

## 3. Investigation Limitations
- Network connections were point-in-time observations.
- A process name does not establish executable authenticity.
- A valid digital signature does not guarantee that a file is safe.
- A network connection alone does not establish malicious intent.
- Not every endpoint connection was independently investigated.
