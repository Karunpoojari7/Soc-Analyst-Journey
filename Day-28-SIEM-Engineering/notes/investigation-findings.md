# Day 28 – SIEM Investigation Findings

## Scenario

NEXORA Technologies – Synthetic SSH authentication investigation.

## Ingestion Results

- Events received: 11
- Events accepted: 11
- Events rejected: 0
- Normalized events: 11

## Detection Results

- Rule: DET-SSH-001
- Detection: SSH authentication failure threshold
- Threshold: 5 failures
- Time window: 600 seconds
- Alerts generated: 1

## Correlation Results

A successful authentication followed the repeated failures.

Subsequent events included:
- Session activity
- Privileged command activity
- Process execution
- Outbound network activity

## Assessment

Investigation priority: HIGH
Classification: REVIEW_REQUIRED
Confirmed compromise: NO

## Limitations

- Synthetic training dataset.
- No real endpoint compromise was investigated.
- No session identifiers were available.
- Process execution details were incomplete.
- Network connection purpose was unknown.
- Correlation does not prove causation.

## Recommendations

1. Validate the account owner.
2. Review authentication source and session records.
3. Obtain full privileged command information.
4. Investigate process command lines and ancestry.
5. Review network destination and traffic metadata.
6. Preserve evidence.
7. Escalate for additional investigation.
