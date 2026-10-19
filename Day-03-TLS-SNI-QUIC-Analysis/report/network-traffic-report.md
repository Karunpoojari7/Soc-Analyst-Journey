# Day 3 SOC Analyst Lab Report
## Network Traffic Analysis: TLS SNI and QUIC

**Date:** 19 October 2026  
**Environment:** Kali Linux persistent live USB  
**Capture:** `~/cyber-lab/day03/evidence/day03-own-traffic.pcap` (reported size: 3.1 MB)  
**Scope:** Traffic captured from the analyst's own device.

## 1. Objective
Inspect a packet capture for TLS Server Name Indication (SNI) hostnames and QUIC traffic over UDP port 443. Record observed facts without assuming that encrypted or repeated traffic is malicious.

## 2. Tools
- Kali Linux
- TShark
- PCAP analysis

## 3. Findings

### A. SNI for `gmu.ac.in`
The filter for TLS Client Hello packets containing SNI `gmu.ac.in` returned seven displayed packets. The visible endpoints were:
- Local source: `192.168.31.80`
- Remote destination: `117.236.191.67`
- Service port: `443`
- Listed timestamps: approximately `14:34:00.513` to `14:34:00.932 UTC`

The packets occurred within a short interval. This could be consistent with browser activity or multiple flows, but the output does not prove that seven separate connections completed.

### B. Observed SNI hostname counts

| Count | Hostname |
|---:|---|
| 7 | `gmu.ac.in` |
| 6 | `fonts.googleapis.com` |
| 4 | `www.google.com` |
| 4 | `cdn.jsdelivr.net` |
| 4 | `cdnjs.cloudflare.com` |
| 3 | `unpkg.com` |
| 2 | `www.googletagmanager.com` |
| 2 | `www.google.co.in` |
| 2 | `stats.g.doubleclick.net` |
| 2 | `googleads.g.doubleclick.net` |
| 2 | `fonts.gstatic.com` |
| 2 | `analytics.google.com` |
| 2 | `ad.doubleclick.net` |
| 1 | `kit.fontawesome.com` |
| 1 | `github.com` |
| 1 | `ads-img.mozilla.org` |

These hostnames are consistent with a web page and third-party resources such as fonts, JavaScript/CDN assets, analytics, and advertising-related services. SNI counts alone do not establish which page initiated each request or whether each resource loaded successfully.

### C. QUIC traffic to `117.236.191.67`
The filtered command output contained 13 matching packets:
- Source: `192.168.31.80:33130/UDP`
- Destination: `117.236.191.67:443/UDP`
- Protocol stack: `eth:ethertype:ip:udp:quic` (the first listed packet also displayed `tls`)
- Captured frame length: `1399` bytes for each listed packet
- First listed relative time: `35.406713` seconds
- Last listed relative time: `56.835043` seconds

The displayed packets were outgoing from the local host. The same UDP source and destination ports are consistent with packets in the same observed flow, but this output does not prove a completed connection or successful server response.

### D. Frame 200
Frame 200 had:
- Source IP: `192.168.31.80`
- Destination IP: `117.236.191.67`
- UDP source port: `33130`
- UDP destination port: `443`
- Protocol stack: `eth:ethertype:ip:udp:quic:tls`
- Frame length: `1399` bytes

TCP fields were blank because this was UDP/QUIC traffic, not TCP.

## 4. Preliminary assessment
The evidence is consistent with web browsing and encrypted web traffic, including QUIC over UDP port 443 and SNI names for the main site and third-party resources.

**No confirmed malicious activity was established from the evidence reviewed.** The capture does not by itself prove the process responsible for each flow, successful completion of each connection, or the safety of every hostname.

## 5. Limitations and next checks
1. Inspect both directions of the flow to check whether packets from `117.236.191.67` back to `192.168.31.80` are present.
2. Review QUIC packet types and conversation statistics where supported by the capture.
3. Correlate timestamps with browsing activity and other evidence.
4. Do not label traffic malicious based only on encryption, repetition, port number, or hostname.
5. Keep the raw PCAP private; it may contain browsing metadata or other sensitive information.

## 6. Evidence paths
- PCAP: `~/cyber-lab/day03/evidence/day03-own-traffic.pcap`
- SNI summary: `~/cyber-lab/day03/evidence/tls-sni-summary.txt`

## 7. SOC analyst takeaway
Separate observed facts, hypotheses, and conclusions. This capture shows QUIC traffic and multiple SNI hostnames; the evidence currently supports a web-browsing interpretation, not a confirmed security incident.
