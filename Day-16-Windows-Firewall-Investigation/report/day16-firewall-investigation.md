# Day 16 — Windows Firewall and Network Threat Investigation

**Lab:** Windows Firewall and Network Threat Investigation  
**Platform:** Windows 11  
**Investigation type:** Host-based firewall and network endpoint review  
**Approach:** Read-only investigation  
**Tools:** PowerShell, NetSecurity, NetTCPIP, Get-WinEvent, auditpol

---

## 1. Objective

Investigate the Windows Defender Firewall configuration, review enabled firewall rules, identify TCP and UDP endpoints, correlate network activity with processes and services, and assess available Windows Filtering Platform (WFP) telemetry.

The investigation was performed using read-only commands. No firewall rules, audit policies, or logging settings were modified.

## 2. Firewall baseline

All three firewall profiles were enabled:

| Profile | Enabled | Effective inbound | Effective outbound |
|---|---|---|---|
| Domain | True | Block | Allow |
| Private | True | Block | Allow |
| Public | True | Block | Allow |

**Interpretation:** The effective policy blocks inbound traffic by default and allows outbound traffic by default, subject to applicable firewall rules.

## 3. Firewall logging

The configured firewall log path was:

`%systemroot%\system32\LogFiles\Firewall\pfirewall.log`

Observed configuration:

- LogAllowed: False
- LogBlocked: False
- Maximum configured size: 4096 KB
- Expected firewall log file: Not present

**Interpretation:** Windows Firewall text logging for allowed and blocked traffic was disabled across the inspected profiles. Historical traffic cannot be reconstructed from a firewall text log that was not available.

## 4. Firewall rule review

Enabled inbound and outbound rules were reviewed.

Observed rule categories included:

- Windows Core Networking
- DHCP and DHCPv6
- Network Discovery
- Wi-Fi Direct
- Delivery Optimization
- Remote Assistance
- Connected Devices Platform
- mDNS and SSDP

Some rules permitted traffic on the Public profile, including Wi-Fi Direct-related rules.

**Interpretation:** These names are consistent with Windows networking features. Public-profile allow rules deserve contextual review, including application, service, protocol, port and remote-address scope. Their presence alone does not establish malicious activity.

A firewall allow rule represents policy permission, not proof that a connection occurred.

## 5. TCP endpoint investigation

TCP endpoints were reviewed and correlated with owning process names.

Observed process categories included:

- Microsoft Edge
- Microsoft Edge WebView
- Node.js
- Windows service processes
- Database-related processes

Established HTTPS connections were observed for browser and application processes.

The process `agy` also appeared in the endpoint inventory with established connections. Its identity and legitimacy were not established during this investigation.

**Interpretation:** Process names and connection states are useful investigative leads. An unfamiliar process requires executable-path, digital-signature, hash, parent-process and application-provenance validation before a security verdict can be made.

## 6. Database service investigation

The following Windows services were confirmed running with automatic startup:

| Service | Display name | State | Startup |
|---|---|---|---|
| MySQL80 | MySQL80 | Running | Automatic |
| postgresql-x64-14 | PostgreSQL Server 14 | Running | Automatic |

Earlier endpoint observations included:

- MySQL process endpoints associated with ports 3306 and 33060.
- A PostgreSQL IPv6 wildcard TCP endpoint on port 5432.
- A later verification query did not reproduce a TCP listener on port 5432.

The service process IDs and earlier socket-owning process IDs differed.

**Interpretation:** The database services are installed and running. The earlier PostgreSQL wildcard endpoint is an exposure-review lead, not proof of external reachability. A fresh listener and configuration review is required to establish current exposure.

## 7. UDP endpoint and service correlation

Observed UDP endpoint categories included:

| Endpoint category | Associated process or service |
|---|---|
| DNS and local name resolution | DNS Client |
| IPsec key exchange | IKEEXT |
| SSDP discovery | SSDPSRV |
| Connected device functionality | CDPSvc |
| Browser-related mDNS | Microsoft Edge |
| IP Helper functionality | iphlpsvc |

**Interpretation:** The observed endpoints are consistent with Windows networking, discovery, IPsec and browser functionality. Their presence alone does not establish compromise or active VPN usage.

## 8. Windows Filtering Platform telemetry

The following audit policy settings were observed:

| Audit subcategory | Setting |
|---|---|
| Filtering Platform Connection | No Auditing |
| Filtering Platform Packet Drop | No Auditing |

The Security log query for event IDs 5152, 5156, 5157 and 5158 over the preceding 24 hours returned zero matching records.

The expected `pfirewall.log` file was also absent.

**Interpretation:** The available evidence does not provide the expected WFP connection and packet-drop audit trail. Zero returned events must not be interpreted as proof that no network connections or packet drops occurred.

## 9. Key observations

1. All three Windows Firewall profiles were enabled.
2. Effective inbound policy was Block and outbound policy was Allow.
3. Firewall text logging was disabled.
4. WFP connection and packet-drop auditing were disabled.
5. Windows networking and discovery rules were present.
6. Browser and application processes had established network connections.
7. MySQL and PostgreSQL services were running automatically.
8. An earlier PostgreSQL IPv6 wildcard endpoint requires fresh validation.
9. The `agy` process requires identity and provenance validation before classification.

## 10. Security assessment

**Assessment: No confirmed malicious activity established by the evidence collected.**

The investigation identified normal-looking Windows networking components and running database services, but also identified telemetry gaps and endpoints requiring additional validation.

This is a scoped assessment of the evidence examined. It is not a guarantee that the workstation is free of malware or unauthorized network activity.

## 11. Recommended follow-up actions

1. Validate the executable path, publisher, signature and SHA256 hash of the `agy` process.
2. Recheck MySQL and PostgreSQL listening sockets and their bind configurations.
3. Review firewall rules with broad Public-profile permissions.
4. With appropriate authorization, consider enabling WFP auditing and firewall logging for future investigations.
5. Correlate future network observations with Sysmon, Windows Security events and endpoint telemetry.
6. Validate service exposure using authorized testing from another host.

## 12. Evidence handling and privacy

Raw endpoint inventories, private IP addresses, user-specific paths and detailed local network information are intentionally excluded from this public report.

The investigation script is included for reproducibility. Local raw output should be retained privately and sanitized before sharing.

---

**Lab status:** Completed  
**Conclusion:** No confirmed malicious activity identified in the examined evidence.  
**Next learning focus:** Network connection correlation, process provenance and firewall telemetry engineering.
