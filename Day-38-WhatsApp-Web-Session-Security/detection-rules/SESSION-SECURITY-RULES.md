# Day 38 — Session Security Detection Rules

## WWA-001 — Session Persistence
Detects a browser tab closure while an authenticated session
remains active in the synthetic session evidence.

## WWA-002 — Post-Closure Session Access
Detects session access after browser tab closure and before
a recorded session revocation or logout.

## WWA-003 — Unusual Messaging Volume
Flags messaging events involving 10 or more recipients.

## WWA-004 — Shared Device Activity
Flags suspicious messaging behaviour associated with a
known shared workstation.

## Limitations

- Recipient thresholds are illustrative.
- Shared-device classification comes from the training dataset.
- Browser and session events are synthetic.
- These rules do not access WhatsApp's internal telemetry.
- Alerts require analyst investigation before escalation.
