# Active Directory Event Correlation

## Events examined
- 4720: User account created.
- 4722: User account enabled.
- 4724: Password reset attempted.
- 4728, 4732, 4756: Security group membership additions.

## Correlation method
The training script associates account lifecycle activity with
sensitive group additions using the same target account and actor
within a 15-minute window.

## Simulated findings

### newadmin
- 10:00: Account created (4720).
- 10:02: Account enabled (4722).
- 10:04: Password-reset attempt (4724).
- 10:06: Added to Domain Admins (4728).

Assessment: High-priority investigation sequence.

### guest01
Added to Enterprise Admins by unknown_user.
No matching account lifecycle events were present in the supplied dataset.

Assessment: Requires broader log review and actor investigation.

## Limitations
Absence of matching events in this dataset does not prove an event
never occurred. The 15-minute window is a training heuristic.
