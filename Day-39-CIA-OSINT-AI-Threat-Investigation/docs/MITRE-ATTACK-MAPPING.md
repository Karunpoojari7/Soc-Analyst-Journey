# Day 39 – MITRE ATT&CK Mapping

This document maps simulated defensive investigation scenarios
to relevant MITRE ATT&CK techniques.

| Scenario | ATT&CK ID | Technique |
|---|---|---|
| Network reconnaissance | T1595 | Active Scanning |
| Cloud resource discovery | T1580 | Cloud Infrastructure Discovery |
| Legitimate account misuse | T1078 | Valid Accounts |
| Exploiting exposed applications | T1190 | Exploit Public-Facing Application |
| Supply chain compromise | T1195 | Supply Chain Compromise |
| Account modification | T1098 | Account Manipulation |
| Cloud storage data access | T1530 | Data from Cloud Storage |
| Proxy-based communications | T1090 | Proxy |

## Detection coverage

- Authentication monitoring: supports investigation of T1078.
- Cloud discovery monitoring: supports investigation of T1580.
- Cloud storage monitoring: supports investigation of T1530.
- Network investigation: may support investigation of T1090.
- API and application monitoring: may support investigation of T1190.

## Important limitations

A log pattern does not prove that an ATT&CK technique occurred.

The mapping represents investigation hypotheses and potential
coverage. Each technique requires supporting evidence.

The synthetic dataset does not demonstrate every listed technique.
