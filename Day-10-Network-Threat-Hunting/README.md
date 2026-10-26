# Day 10: Network Threat Hunting with TShark

## Objective
Investigate HTTP traffic in a controlled packet capture and interpret
the observed request and response without overclaiming.

## Tools
- Kali Linux
- TShark
- capinfos
- SHA-256

## Findings
- Capture contained 12 packets.
- HTTP request: GET /training-check
- Client: 127.0.0.1:51618
- Server: 127.0.0.1:8080
- HTTP response: 404 Not Found

## Analysis
The observed traffic matches the controlled localhost test performed
during Day 8. An HTTP 404 response alone is not evidence of malicious
activity.

## Contents
- `report/` — investigation report
- `notes/` — learning notes
- `evidence/` — SHA-256 checksum record

## Scope and Limitations
This was a small, controlled TShark-based investigation, not a full
enterprise threat hunt. The original PCAP is intentionally excluded
from this public portfolio.

Zeek installation was blocked by a package dependency conflict, so
TShark was used for this exercise.

## Next Steps
Safely resolve the Zeek installation approach and investigate
structured connection and DNS metadata.
