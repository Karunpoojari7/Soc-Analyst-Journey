# Day 33: PAYGUARD SOC — AI-Assisted Financial Attack Detection & Prevention Lab

> **MANDATORY LAB NOTICE**: PAYGUARD SOC is an entirely **local, synthetic cybersecurity training environment**. All monetary values are strictly modeled in **Indian Rupees (INR / ₹)**. **No real money is transferred, no external payment networks are contacted, and no actual financial accounts are modified.** All financial thresholds and limits are configurable synthetic lab parameters.

---

## Executive Summary

PAYGUARD SOC is an end-to-end FinTech security operations center (SOC) and defensive fraud prevention platform developed for **Day 33 of the SOC Analyst Journey**.

The platform is designed around real-world financial cyberattack vectors documented in recent **I4C (Indian Cyber Crime Coordination Centre)** and **CERT-In** advisories regarding Non-Banking Financial Companies (NBFCs), digital lending apps, API exploitation, credential stuffing, mule account laundering, and unauthorized micro-disbursements.

PAYGUARD SOC combines a high-concurrency micro-disbursement transaction core with:
1. **Zero-Trust API Security Gateways** (synthetic tokens, endpoint scopes, nonces, timestamp validation, secret redaction, and IDOR protection).
2. **Explicit 5-State Finite State Machine (FSM)** (`RECEIVED` $\rightarrow$ `VALIDATED` $\rightarrow$ `HELD` $\rightarrow$ `REJECTED` $\rightarrow$ `APPROVED`).
3. **Deterministic Fraud Detection Engine** (explainable rules `DET-01` through `DET-04` kept distinct from ML).
4. **Active Defense Response Coordinator** (`ALLOW`, `HOLD`, `REJECT`, `REVOKE_TOKEN`, `BLOCK_SYNTHETIC_CALLER`, `ESCALATE_INVESTIGATION`).
5. **Cryptographic Tamper-Evident Evidence Vault** (append-only ledger, SQL triggers, SHA-256 hash chaining, and HMAC-signed forensic bundles with standalone CLI verifier).
6. **Dark-Themed SOC Analyst Web Dashboard** (executive overview, live FSM monitor, manual hold review drawer, telemetry stream, incident response, and attack simulator console).
7. **Automated Attack Simulation Suite** (7 reproducible attack scenarios).

---

## System Architecture

```text
                               ┌───────────────────────────────────────────────────────────┐
                               │                 PAYGUARD SOC CLIENT LAYER                 │
                               │  FinTech Partner APIs | Attacker Scripts | SOC Dashboard  │
                               └─────────────────────────────┬─────────────────────────────┘
                                                             │ REST (INR / ₹)
                                                             ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                             API SECURITY & DEFENSE GATEWAY                                              │
│  • Synthetic Bearer Token Validator (Scopes: disbursement:create, disbursement:read, soc:review, audit:export)          │
│  • Replay Protection (Single-Use Nonce Store with TTL eviction)                                                         │
│  • Clock Skew Validator (±300s window)                                                                                  │
│  • IDOR Protection (Tenant/Borrower ownership validation)                                                               │
│  • Secret Redactor (Masks tokens into lab_tok_...[MASKED] in logs)                                                       │
│  • Socket-Level Network Isolation Guard (Blocks non-loopback connections & external DNS)                                 │
└─────────────────────────────────────────────┬───────────────────────────────────────────────────────────────────────────┘
                                              │
                                              ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                           TRANSACTION CORE & 5-STATE FSM                                                │
│                                                                                                                         │
│           ┌──────────────┐         ┌──────────────┐         ┌──────────────┐         ┌──────────────┐                   │
│           │   RECEIVED   │ ──────▶ │  VALIDATED   │ ──────▶ │     HELD     │ ──────▶ │   APPROVED   │                   │
│           └──────────────┘         └──────────────┘         └──────────────┘         └──────────────┘                   │
│                   │                        │                        │                        ▲                          │
│                   │                        ▼                        ▼                        │                          │
│                   │                ┌──────────────┐         ┌──────────────┐                 │                          │
│                   └──────────────▶ │   REJECTED   │         │  SOC REVIEW  │ ────────────────┘ (With Valid Rationale)   │
│                                    └──────────────┘         └──────────────┘                                            │
│                                                                                                                         │
│  • Concurrency Control: SQLite BEGIN IMMEDIATE write serialization (Zero balance over-draw)                              │
│  • Idempotency Engine: SHA-256 Request Hash Matching (Deduplication + 409 Conflict Tamper Detection)                     │
└─────────────────────────────────────────────┬───────────────────────────────────────────────────────────────────────────┘
                                              │
                       ┌──────────────────────┴──────────────────────┐
                       ▼                                             ▼
┌──────────────────────────────────────────────┐ ┌───────────────────────────────────────────────────────────────────────┐
│          DETERMINISTIC FRAUD ENGINE          │ │                    RESPONSE ENGINE & SOC INCIDENTS                     │
│  • DET-01: Micro-Probe to High-Value Drain   │ │  • Automated Actions: HOLD, REJECT, BLOCK_CALLER, REVOKE_TOKEN         │
│  • DET-02: Unseen Beneficiary Velocity Spike │ │  • Incident Store: soc_incidents (OPEN -> INVESTIGATING -> CONTAINED) │
│  • DET-03: Loan Status Integrity Check       │ │  • Analyst Containment: One-click caller isolation & token revocation  │
│  • DET-04: API Authentication Abuse Burst    │ └───────────────────────────────────────────────────────────────────────┘
└──────────────────────┬───────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                     TAMPER-EVIDENT FORENSIC AUDIT LEDGER                                                │
│  • SQLite Application Triggers: trg_audit_no_update & trg_audit_no_delete prevent SQL mutation                           │
│  • Cryptographic Hash Chaining: H_n = SHA-256(H_{n-1} || payload_sha256 || decision_reason)                             │
│  • Forensic Bundle Exporter: JSONL log stream + HMAC-SHA256 signed manifest                                             │
│  • Independent Offline Verifier: evidence/verify_evidence.py (Zero dependency verification)                             │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## Deterministic Detection Rules Specification

All rules in PAYGUARD SOC are **strictly deterministic, explainable, and rule-based**. They do not use opaque machine learning or unexplainable heuristics:

| Rule ID | Rule Name | Threat Pattern / Advisory Context | Logic & Thresholds (Synthetic INR) | Initial Action |
| :--- | :--- | :--- | :--- | :--- |
| **`DET-01`** | **Micro-Probe to High-Value Drain** | Fraudsters test stolen API keys or payment routes with a trivial amount before draining funds. | A transaction $\le ₹50.00$ followed by a transaction $\ge ₹5,000.00$ within $300\text{ seconds}$ on the same loan/borrower. | **`HELD`** (Escalates SOC Incident) |
| **`DET-02`** | **Unseen Beneficiary Velocity Spike** | Stolen accounts quickly disburse money to newly registered mule accounts before the victim notices. | Transfer to a registered beneficiary with zero approved historical transfers, accompanied by $>3\text{ transactions in }60\text{s}$. | **`HELD`** (Escalates SOC Incident) |
| **`DET-03`** | **Loan Facility Integrity Violation** | Attackers attempt to generate disbursements against closed or unauthorized facilities. | Request referencing a loan with status `PENDING`, `CLOSED`, or non-existent loan reference. | **`REJECTED`** (HTTP 400, Audit Logged) |
| **`DET-04`** | **Credential Stuffing & Abuse Burst** | Automated bots bruteforce synthetic API tokens or probe endpoints. | $\ge 3\text{ failed authentication attempts within }60\text{ seconds}$. | **`BLOCK_SYNTHETIC_CALLER`** (HTTP 429) |

---

## Directory Layout

```text
Day-33-PAYGUARD-SOC/
├── backend/
│   ├── api/
│   │   ├── app.py                     # FastAPI REST gateway & SOC routes
│   │   └── security.py                # Token verification, scopes, nonces, & redactor
│   ├── config.py                      # Configurable synthetic lab settings (INR)
│   ├── data/
│   │   ├── database.py                # SQLite schema, BEGIN IMMEDIATE, triggers
│   │   └── seed.py                    # Synthetic seed data in INR (₹)
│   ├── engine/
│   │   ├── audit_ledger.py            # Append-only ledger & SHA-256 hash chaining
│   │   ├── evidence_exporter.py       # JSONL exporter & HMAC manifest signer
│   │   ├── fraud_detector.py          # Deterministic rules DET-01, 02, 03, 04
│   │   ├── response_engine.py         # Defensive coordinator & incident tracker
│   │   └── transaction_engine.py      # Concurrency-safe 5-state FSM
│   ├── models/
│   │   └── domain.py                  # Pydantic schemas, Enums, & INR typing
│   ├── network_isolation.py           # Socket-level guard blocking external traffic
│   ├── requirements.txt               # Backend Python dependencies
│   └── simulator/
│       └── attack_scenarios.py        # Core attack logic for Scenarios 1-7
├── docker/
│   ├── Dockerfile                     # Hardened container definition
│   ├── docker-compose.yml             # Local service orchestration
│   └── .dockerignore                  # Docker build exclusions
├── docs/
│   ├── ARCHITECTURE.md                # Concurrency, FSM, and cryptographic design
│   ├── THREAT_MODEL.md                # STRIDE classification & FinTech threats
│   ├── API_DOCUMENTATION.md           # Complete REST API reference with curl samples
│   ├── DETECTION_RULES.md             # DET-01 to DET-04 detailed specifications
│   ├── TESTING.md                     # Test strategy, matrix, and fixtures
│   ├── DEMO_GUIDE.md                  # 12-step demonstration walkthrough
│   └── SECURITY_LIMITATIONS.md        # Lab boundaries & production divergence
├── evidence/
│   ├── verify_evidence.py             # Standalone CLI hash chain verifier
│   ├── evidence_manifest.json         # Sample exported manifest
│   └── evidence_records.jsonl         # Sample exported audit log stream
├── frontend/
│   ├── index.html                     # Full-featured dark-themed SOC Web Dashboard
│   ├── package.json                   # Optional Vite tooling package
│   └── vite.config.js                 # Dev server proxy configuration
├── simulator/
│   └── run_simulation.py              # Interactive CLI simulation runner
├── tests/
│   ├── test_e2e_api.py                # End-to-end API lifecycle tests
│   ├── test_module1_database.py       # Database, triggers & rollback tests
│   ├── test_module2_transaction_engine.py # FSM, idempotency & race conditions
│   ├── test_module3_security.py       # Scopes, nonces, timestamp skew, redaction
│   ├── test_module4_fraud_detection.py# DET rules & SOC analyst reviews
│   ├── test_module5_evidence.py       # Cryptographic hashing & tamper detection
│   └── test_module6_soc_endpoints.py  # SOC overview, incidents, IDOR, & response
├── .env.example                       # Synthetic configuration template in INR
├── .gitignore                         # Git exclusions (.db, .venv, caches)
├── pytest.ini                         # Pytest execution configuration
└── README.md                          # Executive documentation
```

---

## Quickstart Guide

### 1. Environment Preparation
Ensure Python 3.11+ is installed. Create and activate a virtual environment:
```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r backend/requirements.txt
```

### 2. Run the Full Test Suite
Execute all **39 automated tests** verifying database rollback safety, concurrency write serialization, token lifecycles, replay defenses, fraud detection, and tamper detection:
```bash
pytest tests/ -v
```

### 3. Launch the Application & SOC Web Dashboard
Start the FastAPI server:
```bash
uvicorn backend.api.app:app --host 127.0.0.1 --port 8000 --reload
```
Open your browser and navigate to:
```text
http://127.0.0.1:8000/dashboard
```
*(The dashboard is also accessible directly at `http://127.0.0.1:8000/`)*

### 4. Run the Attack Simulation Suite
In a separate terminal, launch the interactive attack emulator to run all 7 attack scenarios:
```bash
python simulator/run_simulation.py --scenario all
```
Or run a specific scenario (e.g., Scenario 1: Micro-Value Probe):
```bash
python simulator/run_simulation.py --scenario 1
```

### 5. Verify Cryptographic Evidence
Export and independently verify the audit trail using the standalone verification tool:
```bash
python evidence/verify_evidence.py \
  --manifest evidence/evidence_manifest.json \
  --records evidence/evidence_records.jsonl
```

---

## Attack Simulation Scenarios

The simulator implements 7 realistic attack patterns:

1. **Scenario 1: Micro-Value Probe to High-Value Drain (`DET-01`)**:
   - Step 1: Attacker sends a ₹50.00 micro-probe disbursement to verify routing and validity (`APPROVED`).
   - Step 2: Attacker immediately requests ₹40,000.00 disbursement.
   - **Result**: `DET-01` triggers; transaction is placed in `HELD` state; an incident is raised.
2. **Scenario 2: Unseen Beneficiary Velocity Spike (`DET-02`)**:
   - Attacker attempts a high-velocity transfer of ₹25,000.00 to a newly added, unverified beneficiary.
   - **Result**: `DET-02` triggers; transaction placed in `HELD` state.
3. **Scenario 3: Closed Loan Facility Disbursement (`DET-03`)**:
   - Attacker attempts to disburse funds against a `CLOSED` or non-existent loan reference (`LOAN-IND-1004`).
   - **Result**: `DET-03` rejects transaction immediately with `INVALID_OR_UNAPPROVED_LOAN_STATUS`.
4. **Scenario 4: Token Stuffing & Brute-Force (`DET-04`)**:
   - Attacker sends rapid invalid synthetic tokens.
   - **Result**: `DET-04` intercepts the burst on the 4th attempt; caller identity is automatically added to `blocked_callers`.
5. **Scenario 5: Nonce Replay Attack**:
   - Attacker intercepts a valid signed request and replays it with the identical nonce.
   - **Result**: Security gateway detects duplicate nonce and returns HTTP 401 with `SECURITY_REPLAY_DETECTED`.
6. **Scenario 6: Revoked Beneficiary Transfer**:
   - Attacker attempts to disburse funds to `BENEF-IND-REVOKED`.
   - **Result**: Engine validates status in real time and rejects transfer with `BENEFICIARY_NOT_REGISTERED`.
7. **Scenario 7: Insecure Direct Object Reference (IDOR)**:
   - Unauthorized client attempts to fetch another borrower's disbursement status.
   - **Result**: IDOR gateway blocks access with HTTP 403 Forbidden and records an audit security event.

---

## SOC Analyst Workflow: Hold Resolution

When `DET-01` or `DET-02` flags a suspicious transaction, it is not rejected outright; it is placed in the `HELD` state. Funds are **not** deducted from the loan balance.

A SOC analyst must resolve the hold using the `/api/v1/soc/transactions/{id}/review` endpoint or via the Web Dashboard:
- **Analyst ID**: Identified SOC operator (e.g., `ANALYST-VIKRAM-01`).
- **Decision**: `APPROVE` or `REJECT`.
- **Mandatory Decision Rationale**: Minimum 10 characters explaining the operational verification (e.g., *"Beneficiary confirmed via out-of-band borrower phone verification"*).
- If `APPROVE`: The transaction engine re-validates the beneficiary, atomically debits the approved loan balance, and transitions state to `APPROVED`.
- If `REJECT`: State is moved to `REJECTED`, preserving loan limits.

---

## Defensive Engineering Details

### Concurrency & Write Serialization
To avoid double debits or exceeding approved loan limits when concurrent requests arrive:
```python
with atomic_transaction(conn) as cur:
    # 1. Acquire immediate lock
    cur.execute("BEGIN IMMEDIATE;")
    # 2. Query available balance
    # 3. Verify limit: (disbursed + requested <= approved)
    # 4. Atomic update: disbursed_amount_inr = disbursed_amount_inr + amount_inr
```
On Windows WSL UNC mount paths (`\\wsl.localhost\...`), SQLite POSIX byte-range locking is bypassed using `uri=True` with `?nolock=1`, while write serialization is strictly maintained via the application's atomic transaction context manager.

### Network Isolation
All outbound socket connections are intercepted at the Python runtime level:
```python
# Any non-loopback connection or DNS lookup raises an immediate RuntimeError:
RuntimeError("NETWORK_ISOLATION_VIOLATION: Attempted outbound socket connection...")
```

---

## Git Safety & Environment Boundaries
- The project is strictly isolated to `/home/karun/soc-analyst-journey-git/Day-33-PAYGUARD-SOC`.
- Day 32 files (`Day-32-Panchayat-Portal-Heist`) are completely untouched.
- SQLite databases, virtual environments, caches, and test artifacts are excluded from Git via `.gitignore`.
- Zero credentials or real secrets are stored; all tokens follow the `lab_tok_` pattern.

---

## Project Status: Complete & Demonstration-Ready
- **Backend Core**: 100% Implemented & Verified.
- **API Security Gateway**: 100% Implemented with Scope & IDOR Protection.
- **Fraud Engine**: DET-01, 02, 03, 04 Verified.
- **Evidence Vault**: Cryptographic SHA-256 Chaining & HMAC Manifest Verified.
- **SOC Web Dashboard**: Complete & Interactive.
- **Attack Simulator**: 7/7 Scenarios Passing.
- **Test Suite**: 39/39 Tests Passing.
