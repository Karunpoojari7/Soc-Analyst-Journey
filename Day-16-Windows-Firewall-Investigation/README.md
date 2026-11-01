Set-Location "$HOME\\soc-analyst-journey"



$base = ".\\Day-16-Windows-Firewall-Investigation"



$readmeContent = @'

\# Day 16 — Windows Firewall \& Network Threat Investigation



\## Overview

A practical Windows SOC investigation covering firewall configuration, network endpoints, process correlation, Windows services and Windows Filtering Platform telemetry.



\*\*Platform:\*\* Windows 11  

\*\*Tools:\*\* PowerShell, NetSecurity, NetTCPIP, Get-WinEvent, auditpol  

\*\*Approach:\*\* Read-only investigation



\## Objectives

\- Inspect Windows Firewall profiles and effective policies.

\- Review enabled inbound and outbound rules.

\- Investigate TCP and UDP endpoints.

\- Correlate endpoints with processes and services.

\- Examine WFP audit policies and Security events.

\- Identify firewall logging limitations.



\## Investigation Findings



| Area | Finding |

|---|---|

| Firewall profiles | All three enabled |

| Default inbound | Block |

| Default outbound | Allow |

| Firewall text logging | Disabled |

| WFP connection auditing | No Auditing |

| WFP packet-drop auditing | No Auditing |

| Matching Security events | 0 returned in 24-hour query |

| Firewall text log | Not present |

| MySQL80 | Running |

| PostgreSQL 14 | Running |



\## Important Observations

\- Windows networking and discovery rules were observed.

\- Browser and application connections were investigated.

\- MySQL and PostgreSQL services were confirmed running.

\- An earlier PostgreSQL IPv6 wildcard endpoint requires fresh validation.

\- The `agy` process requires executable provenance validation.

\- Disabled logging and auditing limit historical visibility.



\## SOC Assessment



No confirmed malicious activity was established by the collected evidence.



This is a scoped investigation conclusion, not a guarantee that the workstation is free of malware or unauthorized activity.



\## Run the Investigation Script



From the repository root:



```powershell

\& ".\\Day-16-Windows-Firewall-Investigation\\scripts\\firewall-investigation.ps1"

