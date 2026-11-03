\# Day 18 — PowerShell Threat Hunting Investigation Report



\## 1. Executive Summary



This investigation examined Windows PowerShell script execution, command activity, process creation, and network connections using PowerShell logging and Sysmon telemetry.



The objective was to understand how PowerShell activity can be monitored and correlated during endpoint threat hunting.



A controlled network-test script was executed to generate observable endpoint telemetry.



\*\*Assessment:\*\* No confirmed malicious activity was established during this controlled investigation.



\## 2. Investigation Environment



| Component | Configuration |

|---|---|

| Operating system | Windows |

| PowerShell | Windows PowerShell 5.1 |

| Endpoint monitoring | Sysmon |

| Script Block Logging | Enabled |

| Module Logging | Enabled |

| PowerShell Event Log | Operational |

| Investigation duration | 60-minute lookback |

| Test activity | Controlled DNS and HTTPS connectivity |



\## 3. Logging Configuration



The following logging capabilities were enabled:



\### Script Block Logging



\- Event ID: 4104

\- Purpose: Record PowerShell script block content.

\- Verification: Controlled script content was captured.



\### Module Logging



\- Event ID: 4103

\- Purpose: Record command invocations and parameter details.

\- Verification: DNS and connectivity command activity was captured.



\### Sysmon



\- Event ID 1: Process creation.

\- Event ID 3: Network connection.



\## 4. Controlled Test Activity



A controlled PowerShell script performed:



1\. DNS resolution for example.com.

2\. TCP connectivity testing to port 443.

3\. Output of a unique test marker.



The script was executed through a separate PowerShell process.



\## 5. Evidence and Findings



\### 5.1 PowerShell Script Block Logging



Event ID 4104 captured the controlled network-test script.



Observed:

\- Record ID: 34512

\- Marker: DAY18-NETWORK-TEST-2026

\- Script: Day18-Network-Test.ps1



\### 5.2 PowerShell Module Logging



Event ID 4103 captured command activity.



Relevant records:



| Record ID | Command | Observation |

|---|---|---|

| 34562 | Resolve-DnsName | DNS A-record lookup |

| 34665 | Resolve-DnsName | DNS record processing |

| 35153 | Test-NetConnection | TCP port 443 test |

| 35152 | ResolveRoutingandAdapterWMIObjects | Routing and adapter activity |



A DNS resolution timeout was recorded during one attempt. A later connectivity test successfully resolved the hostname and established TCP connectivity.



\### 5.3 Sysmon Process Creation



Sysmon Event ID 1 captured the controlled PowerShell process creation.



The event included process identity, timestamp, parent process information, and ProcessGuid.



\### 5.4 Sysmon Network Connection



Sysmon Event ID 3 recorded a TCP connection initiated by the controlled PowerShell process.



Observed:

\- Protocol: TCP

\- Destination port: 443

\- Initiated: True

\- Process image: PowerShell



The ProcessGuid matched the corresponding Sysmon Event ID 1 record.



\### 5.5 Connectivity Verification



The later Test-NetConnection result showed:



| Field | Result |

|---|---|

| Hostname | example.com |

| DNS resolution | Successful |

| TCP port | 443 |

| TCP connectivity | Successful |



The destination IP observed in this connectivity test differed from the IP in the earlier Sysmon network event. These observations should not be treated as the same connection.



\## 6. Automated Threat-Hunting Script Results



The custom PowerShell hunting script examined a 60-minute event window.



| Metric | Result |

|---|---:|

| PowerShell events | 756 |

| PowerShell processes | 8 |

| PowerShell network events | 2 |

| Process/network GUID correlations | 2 |

| Review indicators | 10 |



The ten review indicators consisted of:

\- 8 Sysmon Event ID 1 PowerShell process records.

\- 2 Sysmon Event ID 3 PowerShell network records.



Both network records matched a process record through ProcessGuid.



The review indicators are investigation records, not confirmed threats.



\## 7. Correlation Methodology



The investigation combined:



\- PowerShell Event ID 4103 for command-level context.

\- PowerShell Event ID 4104 for script content.

\- Sysmon Event ID 1 for process creation.

\- Sysmon Event ID 3 for network connections.



ProcessGuid was used to establish process-to-network correlation between Sysmon Events 1 and 3.



The collected evidence did not establish a direct ProcessGuid relationship between PowerShell Events 4103/4104 and Sysmon events.



\## 8. Security Assessment



\*\*Final assessment: No confirmed malicious activity identified in the examined controlled test.\*\*



The investigation demonstrated successful collection of PowerShell and Sysmon telemetry.



A DNS timeout was observed, followed by successful DNS resolution and TCP connectivity.



The HTTPS connection alone does not establish malicious

