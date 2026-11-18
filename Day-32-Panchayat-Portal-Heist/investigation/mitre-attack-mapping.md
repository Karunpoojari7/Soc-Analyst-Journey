# Day 32 — MITRE ATT&CK Behaviour Mapping

## Investigation Context

This mapping classifies behaviours observed in a fictional,
synthetic financial fraud investigation.

Technique mappings are hypotheses for defensive analysis.
They do not establish attacker attribution or prove that a
specific technique was used.

## Candidate Technique Mappings

| Technique ID | Technique | Observed behaviour | Assessment |
|---|---|---|---|
| T1110 | Brute Force | Repeated failed authentication attempts | Candidate |
| T1078 | Valid Accounts | Successful authentication after repeated failures | Candidate |
| T1621 | Multi-Factor Authentication Request Generation | Repeated MFA requests | Candidate |

## Evidence and Limitations

### T1110 — Brute Force

Four failed authentication events were generated for a synthetic
account from a single synthetic source IP.

This supports investigation of repeated authentication failures.
It does not independently establish a brute-force attack.

### T1078 — Valid Accounts

A successful login followed repeated authentication failures.

This is consistent with possible use of valid account credentials.
The method by which credentials were obtained is unknown.

### T1621 — Multi-Factor Authentication Request Generation

Repeated MFA requests were generated before an MFA approval.

This is a candidate mapping for suspicious MFA request activity.
The synthetic records do not prove MFA fatigue or social engineering.

## Analyst Conclusion

ATT&CK mappings provide a common language for describing
potential adversary behaviours.

All mappings in this exercise are provisional and require
additional evidence before being treated as confirmed.
