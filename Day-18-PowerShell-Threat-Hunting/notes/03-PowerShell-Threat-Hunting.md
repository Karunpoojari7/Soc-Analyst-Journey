\# Day 18 — PowerShell Threat Hunting Techniques



\## 1. Objective



PowerShell threat hunting involves investigating suspicious script execution, command activity, process relationships, and network connections.



The goal is to identify abnormal behavior using endpoint telemetry rather than treating every PowerShell execution as malicious.



\## 2. MITRE ATT\&CK mapping



| Technique ID | Technique | Investigation focus |

|---|---|---|

| T1059.001 | Command and Scripting Interpreter: PowerShell | Suspicious PowerShell execution |

| T1059 | Command and Scripting Interpreter | Abuse of command interpreters |

| T1105 | Ingress Tool Transfer | Possible payload downloads |

| T1027 | Obfuscated Files or Information | Encoded or concealed script content |

| T1082 | System Information Discovery | Host information collection |

| T1016 | System Network Configuration Discovery | Network configuration discovery |



These are hunting references, not findings from the controlled lab. A technique should only be attributed when the observed behavior supports it.



\## 3. PowerShell indicators to investigate



\### Encoded commands



Encoded PowerShell commands may hide their actual instructions.



Investigation considerations:



\- Look for encoded-command arguments in process creation telemetry.

\- Decode suspicious content safely in an isolated analysis environment.

\- Review the decoded script for network, file, and execution behavior.

\- Consider the parent process and user context.



Encoded content alone is not proof of malicious activity.



\### Download and execution behavior



Investigate suspicious combinations of:



\- Web requests.

\- File downloads.

\- Temporary file creation.

\- Script execution immediately after download.

\- Unexpected outbound connections.



Correlate PowerShell logs with Sysmon process and network events.



\### Suspicious process ancestry



Investigate unexpected parent-child relationships involving PowerShell.



Examples that may require context:



\- Office applications launching PowerShell.

\- Browsers launching PowerShell.

\- Script hosts spawning PowerShell.

\- Unusual services or scheduled tasks launching scripts.



A parent process alone does not establish malicious activity.



\### Unusual network activity



Investigate PowerShell processes that:



\- Connect to unfamiliar external destinations.

\- Make repeated outbound connections.

\- Contact unusual ports.

\- Communicate with destinations inconsistent with the host's normal role.



Use DNS, proxy, firewall, endpoint, and network telemetry where available.



\## 4. Practical hunting workflow



\### Step 1 — Identify PowerShell execution



Review Sysmon Event ID 1 for:



\- `powershell.exe`

\- `pwsh.exe`



Inspect process creation time, parent process, command-line context, and executable path.



\### Step 2 — Inspect script content



Review PowerShell Event ID 4104.



Look for:



\- Unexpected commands.

\- Encoded or obfuscated content.

\- File and network operations.

\- Suspicious execution chains.



\### Step 3 — Inspect command invocations



Review PowerShell Event ID 4103.



Examine command names and parameter values to understand what operations were recorded.



\### Step 4 — Investigate network connections



Review Sysmon Event ID 3.



Check:



\- Process image.

\- Process GUID.

\- Destination address.

\- Destination port.

\- Protocol.

\- Connection initiation.



\### Step 5 — Correlate the evidence



Use timestamps, process identifiers, ProcessGuid values, script names, and command context.



Prefer ProcessGuid for Sysmon process correlation. Do not assume PowerShell event records have a direct ProcessGuid relationship unless the evidence establishes it.



\### Step 6 — Make an evidence-based assessment



Classify observations carefully:



\- Expected activity.

\- Unusual activity requiring investigation.

\- Suspicious behavior supported by multiple indicators.

\- Confirmed malicious activity supported by sufficient evidence.



Document uncertainty and evidence gaps.



\## 5. False-positive considerations



Legitimate administrative activity can resemble suspicious behavior.



Examples include:



\- PowerShell-based software installation.

\- Developer tools executing scripts.

\- System administration automation.

\- Network troubleshooting.

\- Application update mechanisms.

\- Management agents executing commands.



Always investigate the context before assigning a malicious verdict.



\## 6. Day 18 practical findings



The controlled investigation demonstrated:



1\. Script Block Logging captured the network-test script.

2\. Module Logging recorded DNS and connectivity command invocations.

3\. Sysmon Event ID 1 captured the controlled PowerShell process creation.

4\. Sysmon Event ID 3 captured a TCP connection initiated by that process.

5\. The Sysmon process and network events shared a ProcessGuid.

6\. The controlled connectivity test subsequently succeeded.

7\. An earlier DNS timeout was also recorded.



No confirmed malicious PowerShell activity was established by this controlled test.



\## 7. Investigation limitations



\- The controlled lab did not demonstrate a malicious payload.

\- No malicious verdict can be derived from an HTTPS connection alone.

\- A direct ProcessGuid link between PowerShell events 4103/4104 and Sysmon was not established.

\- DNS timeout and successful connectivity observations occurred at different points in the test.

\- The lab did not establish whether the destination IPs were associated with malicious infrastructure.



\## 8. Key learning outcome



Effective PowerShell threat hunting requires combining script visibility, command-level telemetry, process execution evidence, and network activity.



The strongest investigations distinguish observed facts from hypotheses and avoid declaring benign or malicious activity without adequate supporting evidence.

