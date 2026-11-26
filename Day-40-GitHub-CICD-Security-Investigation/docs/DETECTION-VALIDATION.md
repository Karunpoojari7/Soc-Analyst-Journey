# Day 40 - Detection Validation

## Detection Rule
STRICT_TOKEN_PERMISSION_WORKFLOW_CHAIN

## Validation Scenarios

| Test | Expected alerts |
|---|---:|
| Correct sequence | 1 |
| Different source IPs | 0 |
| Incomplete sequence | 0 |
| Out-of-order sequence | 0 |

## Execution Results
4/4 tests passed.

## Analyst Assessment
The validation suite tests sequence order, source IP
consistency and incomplete activity.

## Limitations
- Synthetic events only.
- No real GitHub audit telemetry.
- No production detection accuracy established.
- These tests do not establish that a real incident occurred.
