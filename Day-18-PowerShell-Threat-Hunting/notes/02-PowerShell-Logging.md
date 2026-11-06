\# Day 18 — PowerShell Logging and Windows Event IDs



\## 1. Introduction



PowerShell logging provides visibility into script execution and command activity. A SOC analyst can use these logs to investigate suspicious scripts, administrative activity, and potential PowerShell abuse.



In this lab, Script Block Logging and Module Logging were enabled and verified.



\## 2. PowerShell Operational Log



Log name:



`Microsoft-Windows-PowerShell/Operational`



Important event IDs:



| Event ID | Description | Investigation value |

|---|---|---|

| 400 | PowerShell engine started | Identifies engine startup |

| 403 | PowerShell engine stopped | Identifies engine shutdown |

| 4103 | Module Logging | Records command invocation and parameter details |

| 4104 | Script Block Logging | Records processed script block content |



Event availability and detail depend on the PowerShell version, logging configuration, and execution context.



\## 3. Script Block Logging — Event ID 4104



Script Block Logging records the contents of PowerShell script blocks processed by the engine.



It can help investigators identify:



\- Commands executed by scripts.

\- Suspicious functions and parameters.

\- Encoded or obfuscated script content.

\- Download and execution patterns.

\- Script activity that needs further investigation.



\### Configuration



Registry policy path:



`HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging`



Policy value:



`EnableScriptBlockLogging = 1`



\### Lab verification



A controlled script containing the marker:



`DAY18-FILE-TEST-2026`



was executed and captured in Event ID 4104.



The network test script was also captured.



Observed network-test evidence:



\- Event ID: 4104

\- Record ID: 34512

\- Marker: `DAY18-NETWORK-TEST-2026`

\- Script: `Day18-Network-Test.ps1`



This confirmed that Script Block Logging captured the test script content.



\## 4. Module Logging — Event ID 4103



Module Logging records command invocation and parameter-binding information for configured modules.



It helps analysts understand which commands were invoked and which parameters were supplied.



\### Configuration



Registry policy path:



`HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging`



Policy value:



`EnableModuleLogging = 1`



Module selection:



`ModuleNames = \*`



The wildcard enabled logging for all modules in this lab.



\### Lab verification



The controlled module test produced Event ID 4103 records.



The network test produced these important observations:



| Record ID | Command | Evidence |

|---|---|---|

| 34562 | Resolve-DnsName | A-record lookup for example.com |

| 34665 | Resolve-DnsName | DNS processing and record objects |

| 35153 | Test-NetConnection | HTTPS port 443 connectivity test |

| 35152 | ResolveRoutingandAdapterWMIObjects | Network routing and adapter activity |



A DNS resolution timeout was also recorded during the test. A later connectivity test succeeded.



\## 5. Sysmon correlation



Sysmon provides additional endpoint telemetry.



| Sysmon Event ID | Description | SOC use |

|---|---|---|

| 1 | Process Create | Investigate process execution and parent-child relationships |

| 3 | Network connection | Investigate process-associated network activity |



\### Event ID 1



The controlled `Day18-Network-Test.ps1` execution was recorded as a PowerShell process creation event.



This provided:



\- Process image.

\- Process ID.

\- Process GUID.

\- Parent process information.

\- Execution timestamp.



\### Event ID 3



The controlled network test generated a TCP connection event associated with the PowerShell process.



Observed:



\- Protocol: TCP

\- Destination port: 443

\- Initiated: True

\- Process image: powershell.exe



The ProcessGuid matched the corresponding Sysmon Event ID 1 record, establishing process-to-network correlation.



\## 6. Combining the telemetry



The four event sources provide complementary evidence:



| Source | Question answered |

|---|---|

| PowerShell 4104 | What script content was processed? |

| PowerShell 4103 | Which commands and parameters were recorded? |

| Sysmon 1 | Which process was created and by whom? |

| Sysmon 3 | What network connection did the process initiate? |



\### Important correlation limitation



The lab established a direct ProcessGuid match between Sysmon Event IDs 1 and 3.



PowerShell Event IDs 4103 and 4104 provide script and command context, but the collected evidence did not establish a direct ProcessGuid link from those events to the Sysmon records.



The correlation should therefore be described using the available timestamps, script name, process information, and command context rather than claiming a direct GUID match across all four sources.



\## 7. Logging considerations



\- Script Block Logging can expose sensitive script content.

\- Module Logging can generate substantial event volume.

\- Wildcard module logging may create high log volume.

\- Log retention and storage capacity must be considered.

\- Access to collected logs should be restricted.

\- Production environments should select appropriate modules and logging policies.



\## 8. Day 18 learning outcome



The investigation demonstrated how PowerShell logging and Sysmon can be combined to improve visibility into script execution and network activity.



Logging provides evidence for investigation; it does not independently prove malicious intent.

