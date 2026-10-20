# SOC Analyst Learning Journey

Hands-on cybersecurity portfolio documenting SOC fundamentals, network traffic analysis, protocol investigations, and evidence-based security assessments.

## Learning Labs

| Day | Investigation | Skills Practiced | Documentation |
|---|---|---|---|
| 01 | SOC Fundamentals | Authentication logs, SSH investigation, incident documentation | [Day 1](Day-01-SOC-Fundamentals/README.md) |
| 02 | Network Traffic Analysis | PCAPs, DNS, TCP, interfaces, sockets and routes | [Day 2](Day-02-Network-Traffic-Analysis/README.md) |
| 03 | TLS, SNI & QUIC Analysis | TLS Client Hello, SNI inspection and QUIC over UDP | [Day 3](Day-03-TLS-SNI-QUIC-Analysis/README.md) |
| 04 | TCP, DNS & TLS Investigation | TCP stream analysis, DNS-to-TLS correlation and connection termination | [Day 4](Day-04-TCP-DNS-TLS-Investigation/README.md) |

## Repository Structure

- `Day-01-SOC-Fundamentals/` — authentication logs and investigation fundamentals
- `Day-02-Network-Traffic-Analysis/` — packet evidence, commands and report
- `Day-03-TLS-SNI-QUIC-Analysis/` — TLS/SNI and QUIC analysis
- `Day-04-TCP-DNS-TLS-Investigation/` — TCP stream and DNS/TLS correlation
- `detections/` — reusable detection content
- `scripts/` — reusable scripts and automation

## Tools and Techniques

- Kali Linux and Linux command-line tools
- TShark and packet capture analysis
- DNS query and response inspection
- TCP connection lifecycle analysis
- TLS SNI and QUIC traffic inspection
- Git and GitHub

## Investigation Principles

- Record observable evidence before drawing conclusions.
- Separate confirmed observations from assumptions.
- Do not treat encrypted traffic or TCP resets as inherently malicious.
- Document limitations and recommended follow-up actions.

## Disclaimer

This repository is for educational and authorized defensive-security practice. Findings should not be interpreted as proof of malicious activity without supporting evidence.
