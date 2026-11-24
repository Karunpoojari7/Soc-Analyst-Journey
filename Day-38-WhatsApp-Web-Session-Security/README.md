# Day 38 — WhatsApp Web Session Security Investigation

## Case Information

Case ID: SOC-D38-WWA-001
Investigation: Unattended authenticated browser session
Category: Account Security / Session Management
Environment: Android Termux
Language: Python 3

## Objective

Investigate the security risks associated with leaving an
authenticated WhatsApp Web session active on a shared or
public computer after closing the browser tab.

## Scope

- Browser session lifecycle
- Authentication events
- Session persistence
- Device access
- Account activity
- Suspicious messaging behaviour
- Session revocation and incident response

## Important Disclaimer

This is an independent educational simulation.
All accounts, devices, timestamps and events are synthetic.

No real WhatsApp accounts, session tokens, cookies,
messages or government systems were accessed.

This simulation does not reproduce a confirmed real-world attack.

## Technology

- Android Termux
- Python 3
- CSV
- JSON
- SHA-256
- Git

## Investigation Status

Phase 1: Environment setup
Phase 2: Synthetic evidence generation
Phase 3: Detection engineering
Phase 4: Alert triage
Phase 5: Incident response
Phase 6: Final investigation report

## Investigation workflow

1. Generate synthetic security evidence:

   `python scripts/day38_lab.py`

2. Generate detection alerts:

   `python scripts/detect_sessions.py`

3. Generate benign test data:

   `python scripts/generate_benign_data.py`

4. Test benign messaging activity:

   `python tests/test_benign_detection.py`

5. Build the correlated timeline:

   `python scripts/build_timeline.py`

6. Generate the investigation report:

   `python scripts/generate_report.py`

## Main deliverables

- `output/detection-alerts.json`
- `output/evidence-sha256.txt`
- `output/FINAL-SOC-INVESTIGATION-REPORT.md`
- `timeline/correlated-timeline.csv`
- `docs/INCIDENT-RESPONSE-PLAYBOOK.md`

## Validation status

This project uses synthetic training evidence.
Detection validation is partial, and production readiness
has not been established.
