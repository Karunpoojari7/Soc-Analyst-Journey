# Day 4 — Network Traffic Analysis & Threat Detection

## Objective
Investigate authorized packet-capture evidence using TShark and practice TCP, DNS, and TLS correlation.

## Tools
- Kali Linux
- TShark
- Git

## Tasks Completed
- Inspected packet-capture metadata and protocol hierarchy.
- Examined TCP handshake packets and connection streams.
- Identified retransmissions and TCP resets.
- Correlated a DNS query and response with TLS SNI for github.com.
- Documented observed connection termination behavior.
- Recorded limitations and avoided unsupported security conclusions.

## Key Learning
Network indicators must be interpreted in context. TCP resets and retransmissions alone do not prove malicious activity.

## Evidence
See `day04-network-analysis.md` for the investigation findings.

Raw PCAP files and sensitive network information remain in the private lab.

## Next Steps
- Investigate additional TCP streams.
- Practice DNS response analysis and TLS metadata interpretation.
- Learn to correlate network evidence with endpoint and firewall logs.
