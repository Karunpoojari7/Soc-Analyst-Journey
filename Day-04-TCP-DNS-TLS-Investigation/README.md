# Day 04 — TCP, DNS & TLS Investigation

## Objective

Investigate a captured network connection by correlating DNS resolution, TCP connection establishment, TLS Server Name Indication (SNI), and connection termination.

## Investigation Findings

### 1. TCP Stream Analysis

- Client: `192.168.31.80:50924`
- Remote endpoint: `20.207.73.82:443`
- TCP handshake completed in frames 117–119.
- TLS SNI identified `github.com` in frame 120.
- Later TLS application-data packets and TCP termination packets were observed.

### 2. DNS-to-TLS Correlation

- DNS query for `github.com`: frame 115.
- DNS response containing `20.207.73.82`: frame 116.
- TCP connection and TLS SNI were consistent with the DNS observation.

### 3. TCP Termination

- Client TCP reset: frame 373.
- Server FIN-ACK: frame 374.
- Client TCP reset: frame 375.

## Assessment

The observed DNS, TCP, and TLS details are consistent with a connection to `github.com`. The available packet evidence does not establish malicious activity or explain the reason for the TCP resets.

## Evidence and Report

- Detailed report: `report/tcp-dns-tls-investigation.md`
- Day 2: [Network Traffic Analysis](../Day-02-Network-Traffic-Analysis/README.md)
- Day 3: [TLS, SNI & QUIC Analysis](../Day-03-TLS-SNI-QUIC-Analysis/README.md)

## Skills Practiced

- TCP stream inspection
- DNS and TLS correlation
- TLS SNI analysis
- Connection lifecycle analysis
- Evidence-based security assessment

## Limitations

Packet captures alone may not explain the application-level cause of a connection reset. Endpoint or application logs would be needed for further investigation.
