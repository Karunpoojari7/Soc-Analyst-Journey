# Day 41 — Detection Evasion and False-Positive Analysis

## Objective

Evaluate how authentication detection behaves under different
activity patterns.

## Test scenarios

### Scenario 1: Repeated failures followed by success

Three failed logins followed by a successful login from the
same source IP and user within ten minutes.

Expected result: Detection.

### Scenario 2: Legitimate login

A successful login without preceding failed attempts.

Expected result: No brute-force detection.

### Scenario 3: Slow authentication attempts

Three failures spread over a period longer than ten minutes,
followed by a successful login.

Expected result: No detection by the current threshold-based rule.

Limitation: Slower attacks may evade this detection window.

### Scenario 4: Different source IP addresses

Failed attempts originate from one IP while the successful
login originates from another IP.

Expected result: No same-IP detection.

Limitation: Distributed attempts may evade source-IP-only correlation.

## False-positive considerations

- Legitimate users mistyping passwords.
- Password managers submitting incorrect credentials.
- Approved administrative automation.
- Shared NAT or proxy addresses.
- Scheduled maintenance activity.

## Recommended improvements

- Correlate by user identity and source IP.
- Monitor authentication failures over longer windows.
- Include MFA outcomes.
- Use identity-provider and endpoint telemetry.
- Establish normal activity baselines.
- Tune thresholds using validated production data.

## Attribution limitation

These tests do not identify an AI agent or prove attacker identity.
