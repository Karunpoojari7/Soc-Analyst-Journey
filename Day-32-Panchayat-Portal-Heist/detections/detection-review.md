# Day 32 — Detection Engineering Review

## 1. Authentication detections

- AUTH-001: Multiple failed authentication attempts.
- AUTH-002: Successful login following repeated failures.
- AUTH-003: Multiple accounts authenticated from one IP.

## 2. MFA detections

- MFA-001: Excessive MFA requests.
- MFA-002: MFA approval outside observed device baseline.
- MFA-003: MFA approval following repeated requests.
- MFA-004: Multiple accounts approved from the same IP and device.

## 3. Financial detections

- TXN-001: High-value payment to a new beneficiary.
- TXN-002: Rapid high-value transaction burst.
- TXN-003: Repeated maker-checker pairing.
- TXN-004: Financial transaction linked to a suspicious session.

## 4. Detection quality observations

- Overlapping transaction windows can produce duplicate alerts.
- Device baselines inferred from observed logs are not proof of trusted devices.
- Correlation should prioritize session IDs and bounded time windows.
- Shared IP addresses alone do not establish that accounts are compromised.
- Alert severity should be supported by multiple evidence sources.

## 5. Improvement objectives

- Deduplicate overlapping transaction alerts.
- Improve session-based correlation.
- Add event time-window validation.
- Record detection evidence and rule metadata.
- Document false-positive considerations.
