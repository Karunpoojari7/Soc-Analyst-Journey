# Day 28 – SIEM Architecture

## Objective
Build a local SIEM learning pipeline using Python and JSON events.

## Architecture

1. Event ingestion
2. Parsing
3. Normalization
4. Detection
5. Event correlation
6. Alert generation
7. Reporting

## Data Sources

- Linux authentication events
- Endpoint activity
- Network activity
- Privileged activity

## Normalized Event Fields

- timestamp
- event_id
- host
- event_type
- username
- src_ip
- outcome
- severity

## Detection

The pipeline implements authentication threshold detection
and temporal correlation of subsequent activity.

## Storage

Raw synthetic events are stored as JSON Lines.
Normalized events and detection results are stored as JSON.

## Limitations

This is a local educational prototype, not a production SIEM.
It does not implement distributed ingestion, durable queues,
enterprise authentication, multi-tenant isolation or
production-scale storage.
