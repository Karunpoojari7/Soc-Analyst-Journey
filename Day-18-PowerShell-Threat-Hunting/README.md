\# Day 18 — Windows PowerShell Threat Hunting



!\[Platform](https://img.shields.io/badge/Platform-Windows-blue)

!\[PowerShell](https://img.shields.io/badge/PowerShell-5.1-blue)

!\[Sysmon](https://img.shields.io/badge/Telemetry-Sysmon-informational)

!\[Focus](https://img.shields.io/badge/Focus-Endpoint%20Threat%20Hunting-red)



\## Overview



Day 18 focuses on Windows PowerShell threat hunting and script execution detection.



The investigation combines PowerShell logging with Sysmon telemetry to examine script execution, command invocation, process creation, and network connections.



A controlled PowerShell script was used to generate DNS and HTTPS connectivity activity for investigation.



\## Objectives



\- Understand PowerShell execution architecture.

\- Enable and verify Script Block Logging.

\- Enable and verify Module Logging.

\- Investigate PowerShell Event IDs 4103 and 4104.

\- Analyze Sysmon Event IDs 1 and 3.

\- Correlate process creation with network activity.

\- Develop a reusable PowerShell threat-hunting script.

\- Document findings without exposing sensitive endpoint information.



\## Tools and Technologies



| Tool | Purpose |

|---|---|

| Windows PowerShell 5.1 | Script execution and investigation |

| Sysmon | Endpoint process and network telemetry |

| Windows Event Viewer | Event log investigation |

| PowerShell Operational Log | Script and command logging |

| PowerShell scripting | Automated hunting and reporting |

| Git and GitHub | Portfolio documentation and version control |



\## Architecture and Investigation Workflow



```text

Controlled PowerShell Script

&#x20;         |

&#x20;         v

PowerShell Execution

&#x20;         |

&#x20;         +----------------------+

&#x20;         |                      |

&#x20;         v                      v

Script Block Logging       Module Logging

Event ID 4104              Event ID 4103

&#x20;         |                      |

&#x20;         +----------+-----------+

&#x20;                    |

&#x20;                    v

&#x20;              Sysmon Telemetry

&#x20;                    |

&#x20;            +-------+-------+

&#x20;            |               |

&#x20;            v               v

&#x20;       Event ID 1       Event ID 3

&#x20;    Process Creation   Network Events

&#x20;            |               |

&#x20;            +-------+-------+

&#x20;                    |

&#x20;                    v

&#x20;            ProcessGuid Matching

&#x20;                    |

&#x20;                    v

&#x20;            Threat Hunting Script

&#x20;                    |

&#x20;                    v

&#x20;            Investigation Results

```



\## Event IDs Investigated



| Event ID | Source | Purpose |

|---|---|---|

| 4103 | PowerShell | Module Logging |

| 4104 | PowerShell | Script Block Logging |

| 1 | Sysmon | Process Creation |

| 3 | Sysmon | Network Connection |



\## Practical Investigation



The controlled test performed:



1\. DNS resolution for `example.com`.

2\. TCP connectivity testing to port 443.

3\. Script execution with a unique test marker.

4\. Collection of PowerShell and Sysmon events.

5\. Process-to-network correlation using ProcessGuid.



\### Key Findings



| Metric | Observed result |

|---|---:|

| PowerShell events | 756 |

| PowerShell processes | 8 |

| PowerShell network events | 2 |

| Process/network GUID correlations | 2 |

| Review indicators | 10 |



Both observed network records matched process records through ProcessGuid.



The ten review indicators represented eight process records and two network records. They were not confirmed threats.



\### Important Observations



\- Script Block Logging captured the controlled network-test script.

\- Module Logging captured DNS and connectivity command activity.

\- A DNS timeout occurred during one resolution attempt.

\- A later DNS and TCP connectivity test succeeded.

\- Sysmon captured PowerShell process creation and network activity.

\- A direct ProcessGuid correlation was established between Sysmon Events 1 and 3.



No confirmed malicious activity was established during this controlled investigation.



\## Custom Threat-Hunting Script



Location:



` scripts/Invoke-Day18ThreatHunt.ps1 `



The script:



\- Collects PowerShell Events 4103 and 4104.

\- Collects Sysmon Events 1 and 3.

\- Identifies PowerShell processes.

\- Extracts PowerShell-associated network events.

\- Matches process and network records through ProcessGuid.

\- Generates investigation summaries and CSV output.



\### Execution



Run PowerShell with appropriate permissions:



```powershell

.\\scripts\\Invoke-Day18ThreatHunt.ps1 -LookbackMinutes 60

```



The script generates CSV files in the reports directory. These exports may contain sensitive endpoint information and must remain local.



\## Repository Structure



```text

Day-18-PowerShell-Threat-Hunting/

│

├── README.md

│

├── notes/

│   ├── 01-PowerShell-Fundamentals.md

│   ├── 02-PowerShell-Logging.md

│   └── 03-PowerShell-Threat-Hunting.md

│

├── scripts/

│   └── Invoke-Day18ThreatHunt.ps1

│

├── reports/

│   └── Day18-Investigation-Report.md

│

├── config/

│   └── Logging-Configuration.md

│

└── evidence/

&#x20;   └── SHA256SUMS.txt

```



\## MITRE ATT\&CK Relevance



| Technique | ID |

|---|---|

| Command and Scripting Interpreter: PowerShell | T1059.001 |

| Ingress Tool Transfer | T1105 |

| Obfuscated Files or Information | T1027 |

| System Information Discovery | T1082 |

| System Network Configuration Discovery | T1016 |



These are relevant hunting references, not confirmed techniques observed in this controlled lab.



\## Security and Privacy



\- No raw event exports are included in the public repository.

\- No raw PCAP files are included.

\- Private endpoint paths, usernames, and network details are excluded.

\- Generated CSV files must be reviewed and sanitized before sharing.

\- Findings distinguish observed activity from malicious conclusions.



\## Investigation Limitations



\- This was a controlled defensive investigation.

\- No malicious payload was used.

\- Network destination reputation was not independently evaluated.

\- No direct ProcessGuid link was established between PowerShell Events 4103/4104 and Sysmon.

\- The findings do not establish that the endpoint is malware-free.



\## Learning Outcomes



\- Windows PowerShell logging configuration.

\- Script Block and Module Logging analysis.

\- Windows endpoint event investigation.

\- Sysmon process and network correlation.

\- PowerShell threat-hunting automation.

\- Evidence-based security reporting.

\- Safe handling of endpoint investigation data.



\## Conclusion



Day 18 demonstrated a practical workflow for investigating PowerShell script execution and associated network activity using native Windows logging and Sysmon.



The exercise strengthened endpoint threat-hunting skills through real event collection, process correlation, automated investigation, and sanitized reporting.



\*\*Learning Journey: SOC Analyst Practical Investigation — Day 18.\*\*

