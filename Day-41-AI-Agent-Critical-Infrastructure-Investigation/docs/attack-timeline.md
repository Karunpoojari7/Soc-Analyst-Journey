# Day 41 — Investigation Timeline

- Case ID: DAY41-CASE-001
- Dataset type: synthetic
- Events: 19

## Observed events

| Timestamp | Source | Event ID | Source IP |
|---|---|---|---|
| 2026-11-27T09:00:00Z | authentication.jsonl | AUTH001 | 192.0.2.44 |
| 2026-11-27T09:08:58Z | firewall.jsonl | FW001 | 198.51.100.77 |
| 2026-11-27T09:09:00Z | api-access.jsonl | API001 | 198.51.100.77 |
| 2026-11-27T09:09:01Z | firewall.jsonl | FW002 | 198.51.100.77 |
| 2026-11-27T09:09:02Z | api-access.jsonl | API002 | 198.51.100.77 |
| 2026-11-27T09:09:04Z | api-access.jsonl | API003 | 198.51.100.77 |
| 2026-11-27T09:09:06Z | api-access.jsonl | API004 | 198.51.100.77 |
| 2026-11-27T09:09:08Z | api-access.jsonl | API005 | 198.51.100.77 |
| 2026-11-27T09:10:00Z | authentication.jsonl | AUTH002 | 198.51.100.77 |
| 2026-11-27T09:10:08Z | authentication.jsonl | AUTH003 | 198.51.100.77 |
| 2026-11-27T09:10:16Z | authentication.jsonl | AUTH004 | 198.51.100.77 |
| 2026-11-27T09:10:24Z | authentication.jsonl | AUTH005 | 198.51.100.77 |
| 2026-11-27T09:11:00Z | firewall.jsonl | FW003 | 198.51.100.77 |
| 2026-11-27T09:12:00Z | authentication.jsonl | AUTH006 | 198.51.100.77 |
| 2026-11-27T09:13:00Z | api-access.jsonl | API006 | 198.51.100.77 |
| 2026-11-27T09:14:00Z | firewall.jsonl | FW004 | 198.51.100.77 |
| 2026-11-27T09:20:00Z | authentication.jsonl | AUTH007 | 192.0.2.44 |
| 2026-11-27T09:21:00Z | api-access.jsonl | API007 | 192.0.2.44 |
| 2026-11-27T09:22:00Z | firewall.jsonl | FW005 | 192.0.2.44 |

## Analyst interpretation

Review the event sequence alongside the detection alerts.
A chronological relationship does not independently establish
causation or AI-agent involvement.
