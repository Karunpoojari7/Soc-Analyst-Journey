# Day 11: DNS Threat Hunting and Investigation

## Objective
Capture and analyze DNS traffic to understand queries, responses,
record types, response codes, and returned IP addresses.

## Environment
- Operating system: Kali Linux
- Tool: TShark 4.4.7
- Interface: wlan0
- DNS resolver: 8.8.8.8
- Capture filter: udp port 53 or tcp port 53
- Capture file: day11-dns-capture.pcap

## Capture Summary
- Packets captured: 6
- Capture size: 1,176 bytes
- Capture duration: approximately 143 milliseconds
- DNS transactions observed: 3 query-response pairs

## Findings

### 1. github.com
- Query type: A (IPv4)
- Response code: 0 (NOERROR)
- Returned address: 20.207.73.82

### 2. google.com
- Query type: AAAA (IPv6)
- Response code: 0 (NOERROR)
- Returned address: 2404:6800:4007:816::200e

### 3. cloudflare.com
- Query type: A (IPv4)
- Response code: 0 (NOERROR)
- Returned addresses:
  - 104.16.133.229
  - 104.16.132.229

## Analysis
The capture contains three DNS queries from the local host
172.21.81.155 to resolver 8.8.8.8. Each query has a corresponding
response with response code 0 (NOERROR).

The responses contain IPv4 addresses for github.com and
cloudflare.com, and an IPv6 address for google.com.

## Assessment
The observed DNS exchanges completed successfully. The evidence
does not independently indicate malicious activity.

DNS answers can change over time and may vary by resolver,
location, caching, and service configuration. A successful DNS
response does not establish that a domain or its returned address
is safe.

## Limitations
This was a short capture containing six packets and three DNS
transactions. It is a small training exercise, not a comprehensive
network threat hunt. It cannot establish whether other suspicious
activity occurred outside the capture window.

## Conclusion
This exercise demonstrated how to capture conventional DNS traffic,
identify query types and response codes, and extract returned IP
addresses using TShark.

## Next Steps
- Investigate DNS failures and NXDOMAIN responses.
- Explore unusual query patterns using suitable datasets.
- Correlate DNS evidence with connection and endpoint logs.
- Continue learning Zeek when a compatible installation path is available.
