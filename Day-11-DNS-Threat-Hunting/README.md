# Day 11: DNS Threat Hunting with TShark

## Overview
A hands-on DNS investigation using TShark to inspect a short packet
capture and extract DNS queries, response codes, and returned addresses.

## Tools
- Kali Linux
- TShark 4.4.7
- dig
- capinfos
- SHA-256

## Key Findings
Three DNS query-response pairs were observed:
- github.com — A — 20.207.73.82
- google.com — AAAA — 2404:6800:4007:816::200e
- cloudflare.com — A — 104.16.133.229, 104.16.132.229

All three responses returned DNS response code 0 (NOERROR).

## Portfolio Contents
- `report/` — investigation report
- `notes/` — learning notes
- `evidence/` — report checksum

## Assessment
The observed DNS exchanges completed successfully. No claim of
malicious activity is made from this limited capture.

## Safety
The raw packet capture is intentionally excluded from this public
portfolio. Review any evidence for sensitive information before sharing.
