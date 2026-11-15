# Day 29 — Splunk Architecture, SPL and Practical Investigations

## Case
SOC-2026-029 — Synthetic NEXORA Technologies Linux investigation.

## Project structure
- data/raw/: synthetic security event dataset
- queries/: ten Splunk SPL investigation queries
- scripts/: Python investigation engine
- tests/: automated tests
- reports/: investigation report and analysis results
- notes/: Splunk architecture and SPL fundamentals
- evidence/: evidence register

## Execution

Run:

    python3 scripts/analyze_events.py
    python3 -m unittest discover -s tests -v

## Splunk limitation

Splunk is not installed in this lab environment. The SPL queries are
prepared but have not been executed in Splunk.

Python analysis is separate from Splunk search execution.

All events are synthetic. No real compromise is asserted.
