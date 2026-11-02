# Day 17 — Windows DNS & Network Threat Hunting

## Objective
Collect and investigate Windows DNS and network telemetry with Sysmon. Practise DNS analysis, process attribution, network connection review, and event correlation using controlled activity.

## Environment and tools
- Windows endpoint; Sysmon 15.22; schema 4.91
- `Microsoft-Windows-Sysmon/Operational`
- Event ID 3 (Network connection), Event ID 22 (DNS query), Event ID 1 (Process creation)
- PowerShell, `Resolve-DnsName`, `Test-NetConnection`, `Get-WinEvent`, CIM, Authenticode and SHA256 tools

## Activities
1. Reviewed and preserved the Day 14 Sysmon configuration.
2. Created and applied a separate Day 17 configuration.
3. Enabled NetworkConnect and DnsQuery while retaining registry monitoring.
4. Generated controlled DNS queries for `example.com`, `cloudflare.com`, and `github.com`.
5. Tested HTTPS connectivity to `example.com`.
6. Collected Event ID 3 and Event ID 22.
7. Correlated DNS and network records using ProcessGuid, timestamp, process identity and destination IP.
8. Reviewed selected executable signatures, hashes and historical process lineage.

## Key findings
- Event ID 3 and Event ID 22 collection was confirmed.
- PowerShell resolved `example.com` and connected to a returned address over TCP/443; DNS and network records shared a ProcessGuid.
- `git-remote-https.exe` resolved `github.com` to `20.207.73.82` and connected to that address over TCP/443; records shared a ProcessGuid.
- LLMNR (UDP/5355), mDNS (UDP/5353) and NetBIOS name service (UDP/137) traffic were observed.
- `agy.exe` had a valid Google LLC signature and an observed parent of Antigravity IDE.
- `opushutil.exe` had a valid Microsoft signature and historical parent `svchost.exe` hosting Task Scheduler.

## Conclusion
No confirmed malicious DNS or network activity was established in the examined evidence. This scoped investigation is not proof that the endpoint is malware-free.

## Privacy
Do not publish raw event messages, private/local IP addresses, usernames, session tokens, CSRF tokens, command-line secrets or complete local paths. The Day 14 original configuration remains a separate reference. Recalculate `evidence/SHA256SUMS.txt` after editing files.

## Limitations
The event queries displayed a limited number of recent records. Correlation does not decrypt TLS or reveal application payloads. A valid signature supports publisher identity but does not guarantee benign runtime behaviour.
