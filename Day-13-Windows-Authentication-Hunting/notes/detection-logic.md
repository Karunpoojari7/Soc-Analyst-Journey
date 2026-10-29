# Detection Logic

## Rule 1 — Repeated failures followed by success
- Event 4625 represents a failed logon.
- Event 4624 represents a successful logon.
- Group events by account and source IP.
- Flag at least five failures and a later success within five minutes.

## Rule 2 — Possible password spraying
- Identify failed logons from the same source IP.
- Evaluate events in a five-minute window.
- Flag windows containing failures against at least three unique accounts.

## Triage cautions
- Repeated failures may result from mistyped passwords, stale credentials, or misconfigured services.
- A successful logon after failures does not prove the account was compromised.
- Multiple account failures from one source can have legitimate explanations.
- Validate timestamps, source context, logon types, account behaviour, and correlated telemetry.

## Prototype limitations
This is a training script tested on synthetic data. It is not a production detection engine. Further work should include test cases for boundary timestamps, malformed input, duplicate alerts, and legitimate activity.
