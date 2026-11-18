# Day 32 – Panchayat Portal Heist
## SOC Investigation and Incident Correlation Lab

### Overview
A synthetic defensive SOC investigation involving suspicious authentication, MFA activity, and financial transactions in a fictional Panchayat portal.

### Scope and Safety
- All users, devices, sessions, beneficiaries, and transactions are synthetic.
- IP addresses use documentation-only ranges.
- No real government portal or banking system was accessed.
- Phishing, OTP compromise, and account takeover remain hypotheses.
- The evidence does not establish criminal activity or root cause.

### Objectives
- Investigate authentication failures and successful logins.
- Analyse unusual IP addresses and devices.
- Investigate MFA request and approval patterns.
- Detect suspicious financial transactions.
- Correlate authentication, MFA, and transaction events.
- Build an incident timeline and analyst assessment.

### Environment
- Kali Linux on WSL2
- Python 3
- JSON and JSONL datasets
- Custom Python detection scripts
- Git and GitHub

### Dataset
| Source | Events |
|---|---:|
| Authentication | 10 |
| MFA | 10 |
| Transactions | 8 |
| Total | 28 |

### Detection Results
| Category | Alerts |
|---|---:|
| Authentication | 3 |
| MFA | 4 |
| Financial fraud | 10 |
| Total | 17 |

### Financial Analysis
- Correlated transactions: 4
- Simulated financial exposure: INR 95,00,000
- Suspicious synthetic session: SESSION-SIM-777

The simulated exposure is not proof of an actual financial loss.

### Incident Correlation
Incident ID: INC-DAY32-001

The correlation engine combines authentication, MFA, and transaction records using user, source IP, session, and event-time relationships.

STRONG represents exact synthetic session linkage. SUPPORTING represents related evidence without exact session linkage. Neither classification proves attacker identity or criminal intent.

### MITRE ATT&CK Mapping
Provisional behavioural mappings:
- T1110 – Brute Force
- T1078 – Valid Accounts
- T1621 – Multi-Factor Authentication Request Generation

See `investigation/mitre-attack-mapping.md`.

### Project Structure
- `data/raw/` – Synthetic source events
- `data/evidence/` – Evidence integrity manifest
- `detections/` – Detection review
- `investigation/` – Incident analysis and timeline
- `output/alerts/` – Generated alerts
- `reports/` – Final incident report
- `scripts/` – Python analysis scripts

### Execution
Run from this directory:

    python3 -m py_compile scripts/*.py
    python3 scripts/analyze_authentication.py
    python3 scripts/analyze_mfa.py
    python3 scripts/analyze_transactions.py
    python3 scripts/correlation_engine.py
    python3 scripts/hash_evidence.py

Do not run `generate_logs.py` during routine analysis. It regenerates synthetic source data and may change evidence hashes.

### Evidence Integrity
SHA-256 hashes of the synthetic raw datasets are recorded in `data/evidence/evidence-manifest.json`.

### Analyst Limitations
- Dataset is synthetic and limited in size.
- Detection rules are not production-tuned.
- IP and device indicators are not independently verified.
- Root cause and attacker attribution remain undetermined.

### Learning Outcomes
- Authentication and MFA investigation
- Financial anomaly detection
- Python detection engineering
- Multi-source event correlation
- Incident timeline construction
- Evidence hashing
- MITRE ATT&CK mapping
- SOC incident reporting

### Deliverables
Synthetic logs, detection scripts, alert JSON files, unified incident JSON, attack timeline, MITRE ATT&CK mapping, analyst assessment, final incident report, and evidence manifest.
