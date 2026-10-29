# Windows Logon Event Reference

| Event ID | Meaning |
|---|---|
| 4624 | Successful logon |
| 4625 | Failed logon |
| 4634 | Logoff |
| 4648 | Logon attempted using explicit credentials |
| 4672 | Special privileges assigned to a new logon |
| 4776 | NTLM credential validation |

## Common logon types for Event 4624
- 2 — Interactive
- 3 — Network
- 4 — Batch
- 5 — Service
- 7 — Unlock
- 8 — NetworkCleartext
- 9 — NewCredentials
- 10 — RemoteInteractive, commonly associated with Remote Desktop
- 11 — CachedInteractive

Interpret events in context. A single event ID or logon type does not prove malicious activity. Confirm the event details and correlate with other available evidence.
