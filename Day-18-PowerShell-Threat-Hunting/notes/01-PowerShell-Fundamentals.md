\# Day 18 — PowerShell Fundamentals for Threat Hunting



\## 1. Introduction



Windows PowerShell is a command-line shell and scripting environment built on the .NET platform. It is widely used by system administrators, developers, and security professionals to automate Windows administration and investigation tasks.



PowerShell is also relevant to security monitoring because attackers may abuse legitimate PowerShell functionality to execute commands, discover system information, modify configurations, or communicate with remote systems.



MITRE ATT\&CK classifies PowerShell abuse under \*\*T1059.001 — Command and Scripting Interpreter: PowerShell\*\*.



\## 2. PowerShell architecture



Important components:



\- \*\*PowerShell Engine:\*\* Executes commands, scripts, pipelines, and functions.

\- \*\*PowerShell Host:\*\* Provides the interface through which users interact with the engine.

\- \*\*Cmdlets:\*\* Built-in commands following a Verb-Noun naming convention.

\- \*\*Modules:\*\* Packages containing cmdlets, functions, and related resources.

\- \*\*Scripts:\*\* Files containing PowerShell instructions, commonly using the `.ps1` extension.

\- \*\*Pipeline:\*\* Passes objects from one command to another.



\### PowerShell versions



| Version | Description |

|---|---|

| Windows PowerShell 5.1 | Windows-integrated PowerShell based on .NET Framework |

| PowerShell 7.x | Modern, cross-platform PowerShell based on modern .NET |



Both versions can exist on the same Windows system. Their logging and execution environments should be investigated separately where necessary.



\## 3. Common PowerShell commands



| Command | Purpose |

|---|---|

| `Get-Process` | Lists running processes |

| `Get-Service` | Lists Windows services |

| `Get-WinEvent` | Retrieves Windows event logs |

| `Get-ChildItem` | Lists files and directories |

| `Get-ExecutionPolicy` | Displays PowerShell execution policy |

| `Get-Module` | Lists loaded or available modules |

| `Get-Command` | Finds available commands |

| `Resolve-DnsName` | Performs DNS resolution |

| `Test-NetConnection` | Tests network connectivity |



\## 4. Why PowerShell matters in threat hunting



PowerShell is a legitimate administrative tool, but its flexibility makes it attractive to attackers.



Investigators should look for:



\- Encoded or obfuscated commands.

\- Unexpected PowerShell process creation.

\- Unusual parent-child process relationships.

\- Remote script execution.

\- Unexpected outbound network connections.

\- Suspicious use of download or execution functions.

\- Script execution from temporary or unusual directories.



These indicators require investigation and should not automatically be treated as proof of compromise.



\## 5. Important security concepts



\### Execution Policy



PowerShell execution policy controls conditions under which scripts are loaded and executed. It is not a complete security boundary and should not be treated as an antivirus or malware prevention mechanism.



\### AMSI



The Antimalware Scan Interface allows applications and scripting environments to integrate with antimalware scanning capabilities.



\### Encoded commands



PowerShell supports encoded command-line input. Encoded commands can be used for legitimate automation but may also be used to obscure command content.



\### Living-off-the-land techniques



Attackers may misuse legitimate Windows tools and scripting capabilities instead of introducing unfamiliar executables. This is commonly associated with living-off-the-land activity.



\## 6. SOC analyst investigation approach



When investigating PowerShell activity:



1\. Identify the PowerShell process and executable path.

2\. Inspect process creation telemetry.

3\. Review the parent process and command-line context.

4\. Examine PowerShell Script Block Logging.

5\. Review Module Logging for command invocation and parameter details.

6\. Correlate process activity with network and endpoint events.

7\. Determine whether the activity is expected, suspicious, or confirmed malicious based on multiple sources.



\## 7. Day 18 practical environment



The controlled investigation used:



\- Windows PowerShell 5.1.

\- Sysmon.

\- Windows PowerShell Operational event log.

\- Script Block Logging.

\- Module Logging.

\- Sysmon Event IDs 1 and 3.

\- PowerShell Event IDs 4103 and 4104.



The practical objective was to investigate PowerShell script execution and correlate it with endpoint network activity.



\## 8. Key learning outcome



PowerShell should not be classified as malicious simply because it executes scripts or makes network connections. A SOC analyst must examine the script content, execution context, process ancestry, command parameters, and network evidence before drawing conclusions.



\*\*Day 18 focus:\*\* PowerShell execution visibility, logging, process investigation, and network threat hunting.

