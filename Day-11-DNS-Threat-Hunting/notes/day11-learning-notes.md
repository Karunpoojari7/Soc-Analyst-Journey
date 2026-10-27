# Day 11 Learning Notes: DNS Threat Hunting

## Concepts
- DNS translates domain names into information used for network communication.
- A records provide IPv4 addresses.
- AAAA records provide IPv6 addresses.
- NOERROR indicates no DNS protocol error, but an answer record may or may not be present.
- TTL indicates how long a DNS answer can be cached.
- DNS observations alone do not prove malicious activity.

## Tools
- dig
- TShark
- capinfos
- sha256sum

## Practical Findings
- github.com A: 20.207.73.82
- google.com AAAA: 2404:6800:4007:816::200e
- cloudflare.com A: 104.16.133.229, 104.16.132.229

## Analyst Lesson
Record actual observations, distinguish facts from assumptions,
and corroborate suspicious findings with additional evidence.
