# Day 24 – Incident Severity Assessment

## Case Information

- Case ID: IR-2026-001
- Scenario: Suspected SSH brute-force activity
- Evidence classification: Synthetic training dataset
- Target account: svc-backup
- Source: 198.51.100.23 (documentation-only IP)

## Observed Evidence

- Failed authentication events: 7
- Successful password authentication events: 1
- Session opened events: 1
- Successful authentication followed previous failures from the same source.

## Severity Assessment

Provisional severity: HIGH

Reasoning:
Repeated authentication failures followed by successful authentication
and session creation warrant urgent investigation and escalation.

## Unknowns

- Whether the account owner authorised the login.
- Whether svc-backup has privileged access.
- Whether the session executed commands.
- Whether files or sensitive data were accessed.
- Whether other accounts or systems were affected.
- Whether the successful login represents account compromise.

## Recommended Investigation

1. Verify the account owner and expected login activity.
2. Review session activity and process execution records.
3. Examine authentication events across other systems.
4. Review network and endpoint telemetry.
5. Determine whether the account has privileged access.
6. Preserve original evidence and document all actions.

## Provisional SOC Verdict

Suspicious authentication activity requiring escalation.
Account compromise is not confirmed by the available evidence.

## Evidence Limitations

This is a synthetic training scenario. The source IP is reserved for
documentation and is not evidence of a real attacker.
