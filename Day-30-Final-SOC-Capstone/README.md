# Day 30 — Final SOC Analyst Capstone

## Case
SOC-2026-030 — NEXORA Technologies synthetic Linux account investigation.

## Objectives
- Perform end-to-end alert triage.
- Analyze authentication and post-authentication events.
- Build Python-based detection logic.
- Test detection behavior.
- Assess severity and evidence gaps.
- Prepare an incident response recommendation.
- Produce a professional SOC investigation report.

## Project structure
- data/: synthetic JSONL event dataset
- scripts/: dataset generator, investigation engine and timeline
- tests/: automated tests
- detections/: detection rule documentation
- reports/: analysis results and final report
- evidence/: evidence register
- notes/: analyst observations and lessons learned

## Run the lab

    python3 scripts/generate_events.py
    python3 scripts/analyze_incident.py
    python3 scripts/show_timeline.py
    python3 -m unittest discover -s tests -v

## Important limitations

This is a synthetic investigation. No production systems were accessed.
No compromise is confirmed. Event correlation does not prove causation.
No Splunk search execution or EDR investigation was performed.

## Outcome

A reproducible final SOC investigation portfolio artifact.
