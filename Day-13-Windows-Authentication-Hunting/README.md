# Day 13 — Windows Authentication Threat Hunting

## Objective
Investigate Windows authentication event patterns and build basic detections for repeated failed logons, failure-to-success sequences, and possible password spraying.

## Topics covered
1. Windows authentication events and logon types.
2. Brute-force and password-spraying detection.
3. Authentication incident triage and evidence-based reporting.

## Lab environment
- Windows PowerShell
- Synthetic CSV training dataset
- Custom PowerShell detection script

## Detection results
- Five failed logons followed by one successful logon for `alex` from `192.0.2.10`, within the configured five-minute window.
- Three failed logons across three accounts from `192.0.2.20`, flagged as possible password spraying.

## Evidence classification
The CSV events are synthetic training data. These findings do not represent confirmed attacks or verified activity on the host.

## Files
- `data/training-auth-events.csv` — synthetic events
- `scripts/authentication-hunt.ps1` — detection logic
- `report/day13-authentication-investigation.md` — investigation report
- `notes/windows-logon-event-reference.md` — event reference
- `notes/detection-logic.md` — detection rules
- `evidence/SHA256SUMS.txt` — file integrity hashes

## Limitations
The rules are educational prototypes, not production-ready detections. They need further testing, alert deduplication, stronger input validation, and validation against real, authorized security telemetry.

## Key lesson
An alert identifies activity worth investigating; it does not independently prove compromise.
