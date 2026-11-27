# Day 41 — Detection Engineering Rules

## Dataset
Synthetic critical-infrastructure security telemetry.

## DET001 — Repeated Authentication Failures
Severity: HIGH

Detection objective:
Identify repeated failed authentication attempts followed by
a successful login from the same source IP.

Investigation:
- Review the account involved.
- Check timestamps and source IP.
- Verify whether MFA was used.
- Investigate the successful session.

## DET002 — Administrative API Access
Severity: HIGH

Detection objective:
Identify successful requests to administrative API endpoints.

Investigation:
- Verify the requesting account.
- Review the API endpoint and HTTP method.
- Determine whether the access was authorised.
- Review subsequent administrative changes.

## DET003 — Control Network Connection Attempt
Severity: MEDIUM or HIGH

Detection objective:
Identify connection attempts targeting the simulated
industrial control network.

Investigation:
- Review the destination and port.
- Determine whether the firewall allowed or blocked traffic.
- Identify the source system.
- Do not interpret a connection attempt as proof of compromise.

## DET004 — Cross-Source Correlation
Severity: HIGH

Detection objective:
Identify source IP addresses represented across
authentication, API and firewall logs.

Investigation:
- Correlate timestamps.
- Review evidence identifiers.
- Establish the event sequence.
- Determine whether activity is authorised.

## Detection limitations

These rules identify suspicious patterns in synthetic logs.
They do not prove AI-agent involvement, attacker identity,
successful exploitation or industrial control system compromise.
