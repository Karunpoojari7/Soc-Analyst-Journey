# Windows Persistence Techniques

## 1. What Is Persistence?

Persistence allows a program, script or component to execute again after a reboot, login or another configured trigger.

## 2. Registry Run Keys

Common locations:

- HKCU\Software\Microsoft\Windows\CurrentVersion\Run
- HKLM\Software\Microsoft\Windows\CurrentVersion\Run
- HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
- HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce

HKCU applies to the current user. HKLM applies at machine level.

## 3. Scheduled Tasks

Scheduled tasks can execute programs or scripts based on:
- User logon
- System startup
- Time-based schedules
- System events

Investigate task paths, actions, arguments, triggers and execution privileges.

## 4. Windows Services

Investigate:
- Service name
- Startup type
- Service account
- Executable path
- Service DLL
- Digital signature and file hash

## 5. Startup Folders

- shell:startup
- shell:common startup

## 6. Investigation Principles

- Verify file paths and publishers.
- Examine command-line arguments.
- Correlate endpoint events.
- Distinguish suspicious indicators from confirmed malicious activity.
- Document findings and limitations.
