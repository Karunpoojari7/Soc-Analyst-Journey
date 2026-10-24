# Day 8: Network Intrusion Detection with Suricata

## Objective
Learn how a network intrusion detection engine analyzes packet
captures and generates alerts using custom detection rules.

## Environment
- Operating system: Kali Linux
- Suricata version: 8.0.7
- Capture tool: tcpdump
- Test server: Python HTTP server
- Traffic: Local HTTP traffic over loopback

## Detection Rule
- Message: DAY08 LAB HTTP training marker
- Signature ID: 1000001
- Revision: 2
- Match condition: HTTP URI contains /training-check

## Methodology
1. Validated the Suricata configuration and custom rule.
2. Started a local HTTP server bound to 127.0.0.1 on port 8080.
3. Captured local TCP traffic using tcpdump.
4. Sent a request to /training-check.
5. Analyzed the saved PCAP with Suricata.
6. Tested a broad TCP rule before troubleshooting the HTTP rule.
7. Simplified the HTTP rule and reran the analysis.

## Results
- PCAP packets processed: 12
- Broad TCP test alerts: 2
- HTTP marker alert: Confirmed
- Source: 127.0.0.1:51618
- Destination: 127.0.0.1:8080
- Alert message: DAY08 LAB HTTP training marker

## Analysis
Suricata successfully matched the controlled HTTP request against
the custom URI-based rule. The initial rule did not generate an
alert; simplifying the rule by removing the flow condition allowed
the expected alert to appear.

## Limitations
This was a controlled local test, not a real attack investigation.
The results do not demonstrate detection accuracy against all traffic
or establish malicious activity.

## Conclusion
This lab demonstrated custom Suricata rule creation, PCAP analysis,
alert troubleshooting, and basic network event interpretation.
