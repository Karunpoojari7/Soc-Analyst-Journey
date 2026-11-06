\# Day 18 — Windows PowerShell Logging Configuration



\## 1. Objective



This document records the logging configuration used during the Day 18 PowerShell threat-hunting investigation.



The objective was to enable visibility into PowerShell script execution and command activity.



\## 2. Logging components



| Component | Event ID | Purpose |

|---|---:|---|

| PowerShell Script Block Logging | 4104 | Records processed script block content |

| PowerShell Module Logging | 4103 | Records command invocation and parameter details |

| Sysmon Process Creation | 1 | Records process creation |

| Sysmon Network Connection | 3 | Records network connections |



\## 3. Script Block Logging configuration



Registry path:



`HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging`



Value:



\- Name: `EnableScriptBlockLogging`

\- Type: DWORD

\- Data: `1`



Result: Enabled and verified during the lab.



\## 4. Module Logging configuration



Registry path:



`HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging`



Value:



\- Name: `EnableModuleLogging`

\- Type: DWORD

\- Data: `1`



Module selection subkey:



`HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging\\ModuleNames`



Value:



\- Name: `\*`

\- Type: String

\- Data: `\*`



Result: Enabled for all modules during the controlled lab.



\## 5. Event log



Log name:



`Microsoft-Windows-PowerShell/Operational`



The log was enabled and its event records were queried during the investigation.



\## 6. Sysmon configuration



Sysmon was running as a Windows service during the investigation.



The existing configuration provided:



\- Event ID 1: Process creation.

\- Event ID 3: Network connection.



The Day 18 investigation used the existing Sysmon configuration. No new Sysmon configuration was installed as part of this exercise.



\## 7. Verification procedure



The following commands can be used to verify PowerShell logging policy values.



\### Script Block Logging



```powershell

Get-ItemProperty `

&#x20; -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging" `

&#x20; -Name EnableScriptBlockLogging

```



\### Module Logging



```powershell

Get-ItemProperty `

&#x20; -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging" `

&#x20; -Name EnableModuleLogging

```



\### Module selection



```powershell

Get-ItemProperty `

&#x20; -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging\\ModuleNames"

```



\### Operational log status



```powershell

Get-WinEvent -ListLog "Microsoft-Windows-PowerShell/Operational" |

Select-Object LogName, IsEnabled, RecordCount, MaximumSizeInBytes

```



\## 8. Security and operational considerations



\- Script Block Logging may capture sensitive script content.

\- Module Logging configured for all modules can produce substantial log volume.

\- Logs should be protected against unauthorized access.

\- Retention and storage should be planned.

\- Production environments should select logging scope based on operational and security requirements.

\- Avoid publishing raw event exports containing usernames, paths, IP addresses, or command-line information.



\## 9. Lab status



| Configuration | Status |

|---|---|

| Script Block Logging | Enabled and verified |

| Module Logging | Enabled and verified |

| PowerShell Operational log | Enabled |

| Sysmon Event ID 1 | Observed |

| Sysmon Event ID 3 | Observed |



\*\*Conclusion:\*\* PowerShell Script Block Logging and Module Logging provided complementary visibility during the Day 18 investigation.

