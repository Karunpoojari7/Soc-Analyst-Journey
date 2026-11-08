# Day 23 – Phishing Investigation

## Objective
Investigate synthetic phishing email evidence using offline analysis tools.

## Workflow
1. Preserve email evidence and calculate SHA-256.
2. Analyse email headers and authentication results.
3. Extract and inspect URLs offline.
4. Perform static attachment triage.
5. Run automated phishing detection.
6. Prepare a final SOC investigation report.

## Directory Structure
- evidence/raw/ - Synthetic email evidence
- evidence/attachments/ - Harmless standalone training sample
- scripts/ - Python investigation scripts
- output/ - JSON analysis results
- reports/ - Final SOC investigation report

## Safety
- No URLs were visited.
- No attachments were executed.
- The HTML sample was not embedded in the simulated email.
- Automated indicators do not prove a phishing incident.

## Final Assessment
The automated detector returned REVIEW REQUIRED based on four indicators.
Further validation would be necessary to confirm a real incident.

See reports/Day23-Phishing-Investigation-Report.md.
