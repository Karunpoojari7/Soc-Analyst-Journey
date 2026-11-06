# Day 17 — Windows DNS and Network Investigation Report

## 1. Executive summary
A controlled Windows endpoint investigation used Sysmon 15.22. The Day 17 configuration enabled NetworkConnect (Event ID 3) and DnsQuery (Event ID 22), retaining the existing registry-monitoring rules. Controlled DNS and HTTPS activity generated telemetry, and two process-level DNS-to-network correlations were demonstrated.

**Outcome:** No confirmed malicious DNS or network activity was established in the evidence examined. This is not a guarantee that the endpoint is malware-free.

## 2. Scope and methodology
- Preserved a reference copy of the Day 14 configuration.
- Created and applied a separate Day 17 Sysmon configuration (schema 4.91).
- Confirmed the Sysmon service and Operational log were available.
- Queried `example.com`, `cloudflare.com`, and `github.com`.
- Tested TCP connectivity to `example.com` on port 443.
- Reviewed Event ID 3, Event ID 22 and historical Event ID 1 records.
- Correlated events using ProcessGuid, timestamp, process image and destination address.
- Reviewed selected executable signatures, hashes and process lineage.

## 3. Telemetry validation
The active configuration reported Sysmon 15.22, schema 4.91, NetworkConnect enabled, DNS lookup enabled, NetworkConnect `onmatch="exclude"`, DnsQuery `onmatch="exclude"`, and RegistryEvent `onmatch="include"`. Sysmon reported `Configuration file validated` and `Configuration updated`. The service was Running and the Operational log was enabled.

## 4. Controlled DNS observations
Successful A-record lookups were observed for all three controlled domains. Event ID 22 associated queries with PowerShell. Successful records (`QueryStatus: 0`), a timeout (`1460`) and unsuccessful reverse lookups (`9003`) were observed. A timeout or reverse lookup failure alone is not evidence of malicious behaviour.

## 5. DNS-to-network correlation

### 5.1 PowerShell and example.com
Event ID 22 recorded a successful `example.com` query from PowerShell. Event ID 3 recorded a TCP/443 connection by the same ProcessGuid to an address returned by that query.

**Assessment:** Strong process-level correlation between the observed DNS lookup and outbound HTTPS connection.

### 5.2 Git HTTPS and github.com
Event ID 22 recorded `git-remote-https.exe` resolving `github.com` to `20.207.73.82`. Event ID 3 recorded the same process connecting to that destination over TCP/443, sharing the ProcessGuid.

**Assessment:** Strong process-level correlation between the Git HTTPS DNS lookup and network connection.

These records do not decrypt TLS or reveal application payload contents.

## 6. Other network observations
LLMNR UDP/5355, mDNS UDP/5353, NetBIOS name-service UDP/137 and TCP/443 connections from desktop applications and Windows components were observed. Their presence alone is not evidence of compromise.

## 7. Process provenance and lineage

### 7.1 agy.exe
- Signature: Valid; signer Google LLC.
- SHA256: `B4BBCC9F65D355BC84523D4F43E1EAD34992890BAF60C24E4CCBF605E2DA6858`
- Historical parent: Antigravity IDE.
- Observed command context: IDE hub process.
- Company/version/description metadata was not populated.

The signature and parent relationship are consistent with an IDE-associated helper process. Missing metadata alone is not suspicious.

### 7.2 opushutil.exe
- Product: Office Push Notifications Utility.
- Company: Microsoft Corporation.
- Version: `16.0.20527.20088`.
- Signature: Valid; signer Microsoft Corporation.
- SHA256: `A4D5DD911027D534B3E037C53851F4A4B051FEE6ED10A54A375F448AE253602A`
- Command context: `/pushregistration`.
- Historical parent: `svchost.exe` hosting Task Scheduler.

The metadata, signature, Office installation location, command context and parent service are consistent with Microsoft Office push-registration activity. This is a provenance assessment, not a guarantee of benign behaviour.

## 8. Findings and disposition
| Finding | Evidence-based disposition |
|---|---|
| Controlled DNS lookups | Successful queries observed |
| DNS timeout | Observed; not independently malicious |
| Reverse lookup failures | Observed; require context |
| PowerShell to example.com | Strong DNS/network correlation |
| Git HTTPS to github.com | Strong DNS/network correlation |
| LLMNR, mDNS, NetBIOS | Observed; no malicious conclusion from presence alone |
| agy.exe | Valid Google signature; IDE parent observed |
| opushutil.exe | Valid Microsoft signature; Task Scheduler parent observed |
| Confirmed malicious activity | Not established in examined evidence |

## 9. Limitations
- Queries displayed a limited number of recent records, not a full endpoint history.
- Collection began after the Day 17 configuration was applied.
- DNS/network correlation does not decrypt TLS or reveal payloads.
- CDN/cloud IPs may be shared and change over time.
- Signatures support publisher/integrity assessment but do not guarantee safe runtime behaviour.
- Only selected process lineage was reviewed.

## 10. Recommendations
1. Monitor event volume and retention when collecting broad Event ID 3 and 22 telemetry.
2. Review unusual domains, high-frequency queries, rare processes and unexpected ports.
3. Correlate DNS, network, process creation and endpoint security telemetry.
4. Verify path, signature, hash, parent process and command line before assigning a verdict.
5. Keep public evidence sanitized; exclude private addresses, usernames, local paths, raw endpoint inventories and session tokens.

## 11. Conclusion
The lab demonstrated Windows DNS/network telemetry collection, process attribution and DNS-to-network correlation with Sysmon. The examined evidence did not establish confirmed malicious activity. The investigation distinguishes observations from interpretations and documents its limitations.
