# Day 37 — Detection Engineering

## Objective
Improve detection reliability and evaluate false positives.

## Detection requirements

### NCIC-001: Authentication correlation
Detect repeated failed logins followed by a successful login
for the same account within a defined time window.

### NCIC-002: Privilege modification
Identify account privilege changes and verify authorization.

### NCIC-003: Database read anomaly
Identify unusually large database read operations.

### NCIC-004: Database modification
Flag sensitive UPDATE and DELETE operations for investigation.

### NCIC-005: Data export correlation
Correlate API export requests with database export activity.

### NCIC-006: Outbound transfer anomaly
Identify unusually large outbound network transfers.

### NCIC-007: Endpoint process review
Identify processes requiring additional investigation.

### NCIC-008: Audit logging gaps
Identify missing or interrupted expected audit events.

## Validation strategy

1. Test suspicious synthetic activity.
2. Test legitimate synthetic activity.
3. Record true positives and false positives.
4. Test boundary conditions.
5. Verify that missing evidence is not treated as proof of compromise.
6. Document limitations.

## Metrics

- True positive: suspicious test activity correctly detected.
- False positive: legitimate test activity incorrectly flagged.
- False negative: suspicious test activity missed.
- True negative: legitimate activity correctly left unflagged.

## Current validation status
Pending implementation and testing.
