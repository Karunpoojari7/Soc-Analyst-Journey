# Day 21 — Active Directory Security Investigation

## Objective
Investigate Active Directory security concepts from a SOC analyst perspective.

## Investigation scripts

| Exercise | Script |
|---|---|
| Kerberos hunting | scripts/kerberos_hunt.py |
| SPN security audit | scripts/spn_security_audit.py |
| Privileged group hunting | scripts/privileged_group_hunt.py |
| Account event correlation | scripts/ad_event_correlation.py |

## Run the exercises

- python3 scripts/kerberos_hunt.py evidence/kerberos-events-simulated.csv
- python3 scripts/spn_security_audit.py evidence/ad-service-accounts-simulated.csv
- python3 scripts/privileged_group_hunt.py evidence/ad-group-events-simulated.csv
- python3 scripts/ad_event_correlation.py evidence/ad-account-correlation-simulated.csv

## Topics
- Active Directory architecture
- Kerberos authentication
- AS-REP Roasting and Kerberoasting
- Service Principal Names
- Privileged group monitoring
- Account lifecycle event correlation

## Evidence classification
All CSV datasets are simulated training data.
No live Active Directory domain was queried.

## Report
See reports/Day21-AD-Investigation-Report.md.

The scripts demonstrate educational detection logic and are not
production-ready SIEM detections.
