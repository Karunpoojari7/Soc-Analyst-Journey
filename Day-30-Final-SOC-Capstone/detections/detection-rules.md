# Day 30 Detection Rules

## D30-DET-001 — Repeated Authentication Failures
Condition: At least five failed authentication events for an account.
Severity: High.
Investigate: Source IP, time range, account and authentication method.
Limitation: Legitimate automation can cause repeated failures.

## D30-DET-002 — Successful Login After Repeated Failures
Condition: Successful authentication after at least five earlier failures
for the same account.
Severity: High.
Investigate: Source IP, session identifier, MFA status and user confirmation.
Limitation: Temporal sequence does not prove the same actor or session.

## D30-DET-003 — Privileged Activity
Condition: Privileged command observed.
Severity: Medium pending context.
Investigate: Authorization, command, account and change ticket.

## D30-DET-004 — Process Execution
Condition: Process execution event observed in the investigation window.
Severity: Medium pending context.
Investigate: Executable path, hash, parent process, arguments and owner.

## D30-DET-005 — Outbound Network Connection
Condition: Outbound connection event observed.
Severity: Medium pending context.
Investigate: Destination reputation, DNS, process, port and business purpose.

All rules require validation and tuning against real environment baselines.
