# Day 32 — SOC Analyst Assessment

## Investigation Summary

A synthetic financial fraud scenario was investigated through
authentication, MFA and financial transaction logs.

## Key Evidence

- Four repeated authentication failures.
- Successful authentication following the failures.
- Repeated MFA requests and subsequent approval.
- Multiple accounts associated with a common synthetic source IP.
- Four transactions linked to SESSION-SIM-777.
- Synthetic financial exposure: INR 95,00,000.

## Strongest Correlation

The session identifier provides the strongest link between
authentication activity and the four synthetic transactions.

## Incident Response Priorities

1. Validate account activity with authoritative logs.
2. Review MFA enrollment and approval history.
3. Verify beneficiary creation and payment authorization.
4. Preserve original evidence and document chain of custody.
5. Escalate suspicious financial activity through authorized channels.
6. Improve detection logic and alert deduplication.

## Investigation Limitations

The synthetic evidence does not establish credential theft,
phishing, OTP interception or the root cause of an actual incident.

## Learning Outcome

Practised SOC alert triage, multi-source investigation,
session correlation, financial exposure analysis and
evidence-based incident reporting.
