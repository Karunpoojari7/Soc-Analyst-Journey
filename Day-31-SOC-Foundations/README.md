# Day 31 — Network Traffic Analysis with TShark

**Date:** 17 November 2026  
**Learning Track:** SOC Analyst & Blue Team  
**Focus:** Network Traffic Analysis and TLS Investigation  
**Environment:** Kali Linux WSL2

## 1. Objective

To understand how SOC analysts investigate network traffic using packet analysis tools. The practical session focused on live packet capture, TCP connection analysis, TLS metadata inspection, and identifying normal network communication patterns.

## 2. Lab Environment

| Component | Details |
|---|---|
| Operating System | Kali Linux WSL2 |
| Kali Release | 2026.3 |
| Kernel | 6.6.87.2-microsoft-standard-WSL2 |
| TShark | 4.6.6 |
| Nmap | 7.99 |
| YARA | 4.5.8 |
| jq | 1.8.2 |
| Network Interface | eth0 |

## 3. Tools Used

- **TShark:** Network packet capture and protocol analysis.
- **curl:** HTTPS connectivity testing.
- **Linux networking utilities:** Network interface and connectivity inspection.
- **Git:** Portfolio version control.

## 4. Practical Activities

### 4.1 Network Interface Inspection

Identified the active network interface in Kali WSL2 and inspected the network configuration.

The `eth0` interface was used for live network traffic monitoring.

### 4.2 Live Packet Capture

Performed live packet capture using TShark.

Observed:
- TCP connection establishment.
- HTTPS traffic over port 443.
- TCP SYN, SYN-ACK and ACK packets.
- Multicast DNS service discovery traffic.

### 4.3 TCP Three-Way Handshake Analysis

Examined the TCP connection establishment process.

The following sequence was identified:

1. SYN — Client initiates a connection.
2. SYN-ACK — Server acknowledges the connection request.
3. ACK — Client completes the handshake.

This exercise demonstrated how packet-level evidence helps analysts understand connection behaviour.

### 4.4 TLS Metadata Investigation

Captured HTTPS traffic and inspected the TLS Client Hello message.

**Observed information:**
- Protocol: HTTPS
- Destination port: 443
- Server Name Indication (SNI): `example.com`
- TLS application data observed after handshake activity.

The SNI field provided visibility into the requested hostname without decrypting the encrypted application traffic.

### 4.5 HTTPS Connectivity Validation

Used `curl` to test connectivity to `example.com`.

**Observed result:** HTTP/2 200 response.

This confirmed successful HTTPS communication with the test endpoint during the exercise.

### 4.6 Multicast DNS Observation

Observed multicast DNS traffic associated with local service discovery.

One observed service query was:

`_googlecast._tcp.local`

This demonstrated how local network service discovery can appear alongside ordinary network traffic.

## 5. Key Findings

- Successfully performed live packet capture using TShark.
- Identified TCP three-way handshake behaviour.
- Extracted TLS SNI metadata from a Client Hello.
- Observed encrypted HTTPS application traffic.
- Identified multicast DNS service discovery activity.
- Observed TCP retransmission and duplicate ACK activity.

**Security interpretation:** TCP retransmissions and duplicate ACKs can occur during normal network communication. Their presence alone does not establish malicious activity.

## 6. Investigation Limitations

- DNS packet visibility was not confirmed in the capture.
- A PCAP capture was created, but offline analysis could not be completed because of a file-permission issue.
- Suricata and Zeek detection were not configured.
- Threat-intelligence correlation was not performed.
- The limited traffic sample was insufficient to establish whether any malicious activity occurred.

## 7. Skills Practised

| Skill | Practical Outcome |
|---|---|
| Network monitoring | Captured live traffic |
| TCP analysis | Examined connection establishment |
| TLS inspection | Identified SNI metadata |
| Protocol identification | Observed HTTPS and mDNS |
| Network investigation | Interpreted packet-level observations |
| Security reporting | Documented evidence and limitations |

## 8. Conclusion

Day 31 focused on practical network traffic analysis using TShark in Kali Linux WSL2.

The session provided hands-on experience with live packet capture, TCP handshake analysis, TLS metadata inspection, and multicast DNS observation.

It also reinforced an important SOC investigation principle: network activity must be interpreted using sufficient evidence rather than classifying unusual-looking packets as malicious without validation.

**Day 31 Status:** Live network traffic analysis completed. Offline PCAP investigation remains incomplete.

---

**Portfolio:** SOC Analyst Learning Journey  
**Principle:** Learn. Investigate. Build.

*This report documents the activities actually performed during the lab. No raw PCAP files, credentials, or sensitive network configuration are included.*
