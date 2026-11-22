# Day 36 — Investigation Findings

## Executive summary

The synthetic investigation identified suspicious authentication,
privilege-change, customer-data export, network-transfer, and
endpoint-process events in a simulated third-party vendor environment.

The evidence demonstrates why a SOC analyst must correlate identity,
application, network, and endpoint telemetry.

## Key observations

### Identity
- Two failed logins were followed by a successful login.
- A subsequent MFA challenge was recorded as passed.
- A privilege-grant event was recorded.

### Customer data
- Export operations involving 1,200 and 3,500 records were observed.
- These exceeded the configured 1,000-record detection threshold.

### Network
- Two connections exceeded the configured 1 MB threshold.
- Their combined recorded transfer volume was 20.5 MB.

### Endpoint
- PowerShell, archive-tool, and unknown process events were flagged
  for analyst review.
- Process names alone are not proof of malicious activity.

## Investigation conclusion

The correlated synthetic evidence warrants escalation for further
investigation of possible unauthorized vendor-account activity and
customer-data exposure.

The lab does not establish whether data was successfully received
by an attacker, identify an actual attacker, or reproduce the
technical attack path of the real JPMorgan incident.

## Recommended response actions

1. Temporarily restrict suspicious vendor sessions while preserving evidence.
2. Verify the affected accounts and privilege changes with the vendor.
3. Review customer-data access and export audit trails.
4. Preserve relevant endpoint and network telemetry.
5. Rotate credentials and revoke sessions if compromise is confirmed.
6. Notify the organization's incident-response and privacy teams
   according to applicable procedures.
7. Review vendor access controls and contractual security requirements.
