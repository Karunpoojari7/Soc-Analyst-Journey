# Day 24 – Incident Response Investigation

## Objective
Practise SOC incident handling through Linux SSH authentication analysis,
event correlation, severity assessment, and response planning.

## Investigation Workflow
1. Identify authentication evidence sources.
2. Inspect SSH service status and listening ports.
3. Preserve real host baseline evidence.
4. Analyse a synthetic authentication dataset.
5. Detect repeated failures and subsequent successful authentication.
6. Generate a JSON investigation report using Python.
7. Create an incident timeline.
8. Assess severity and document response recommendations.

## Project Structure
- notes/ – Incident response playbook
- scripts/ – Python investigation tools
- evidence/raw/ – Real host baseline and synthetic training evidence
- output/ – JSON investigation, severity assessment, and timeline
- reports/ – Final SOC investigation report

## Key Findings
- Seven failed authentication attempts.
- One successful password authentication.
- One session-open event.
- Successful authentication followed previous failures from the same source.
- Automated assessment: REVIEW REQUIRED.
- Provisional training severity: HIGH.

## Safety and Evidence Limitations
- The authentication attack dataset is synthetic.
- The source IP is reserved for documentation.
- Real Kali host observations are stored separately.
- No actual account compromise was established.
- No real containment or eradication actions were performed.

See reports/Day24-Incident-Response-Report.md for the full investigation.
