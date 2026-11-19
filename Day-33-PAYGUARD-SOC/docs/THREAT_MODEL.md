# PAYGUARD SOC: Threat Model & FinTech Cyberattack Analysis

> **Context**: This threat model reflects real-world threat patterns analyzed by the **Indian Cyber Crime Coordination Centre (I4C)** and **CERT-In** regarding Non-Banking Financial Companies (NBFCs), digital lending apps, API exploitation, credential stuffing, and mule accounts. All scenarios in this lab are executed using synthetic INR records in an isolated local environment.

---

## 1. Threat Actors & Motivations

| Threat Actor | Capabilities | Motivations | Target Assets |
| :--- | :--- | :--- | :--- |
| **Organized Loan Drain Syndicates** | Automated API fuzzers, token scrapers, mule bank accounts | Fast financial theft through micro-disbursements | Approved loan limits, unmonitored lending partner APIs |
| **Mule Account Networks** | Coordinated accounts opened via stolen KYC documents | Fund dispersal and money laundering | Registered beneficiary endpoints |
| **Rogue / Compromised Lending Partners** | Legitimate API keys with altered payloads | Cross-tenant data harvesting, double debits | Disbursement authorization tokens |
| **Malicious Insiders / Compromised Analysts** | Elevated internal credentials | Overriding fraud holds without justification | Analyst review endpoints, audit ledgers |

---

## 2. Attack Vectors & Threat Scenarios

### Vector 1: Micro-Probe Account Probing followed by Rapid Drain (DET-01)
- **Mechanism**: Attackers who obtain compromised API credentials or account details test routing with small amounts ($\le ₹50.00$) to verify account status, response timing, and lack of alerting before executing a large drain ($\ge ₹40,000.00$).
- **Mitigation**: `DET-01` maintains a rolling temporal window ($300\text{s}$) per borrower/loan. Any large disbursement preceded by a micro-probe is immediately transitioned to `HELD`, requiring manual SOC investigation.

### Vector 2: Mule Account Redirection & Velocity Bursts (DET-02)
- **Mechanism**: Once access is gained, fraudsters attach a new beneficiary account and rapidly trigger multiple disbursements before the borrower receives notifications or freezes the account.
- **Mitigation**: `DET-02` monitors historical beneficiary approvals. If a transfer targets a newly registered beneficiary with zero disbursement history and velocity exceeds 3 transactions within 60s, it is automatically `HELD`.

### Vector 3: Orphan & Closed Loan Facility Exploitation (DET-03)
- **Mechanism**: Attackers craft API payloads pointing to closed, cancelled, or pending loan facilities, attempting to bypass core banking validations or exploit race conditions.
- **Mitigation**: The transaction engine enforces a rigid `VALIDATED` pre-condition. Any loan whose status is not `APPROVED` is instantly rejected with `INVALID_OR_UNAPPROVED_LOAN_STATUS`.

### Vector 4: Automated Token Stuffing & Brute-Force (DET-04)
- **Mechanism**: Automated scripts send bursts of candidate tokens or test expired tokens against API endpoints.
- **Mitigation**: `DET-04` tracks authentication failures across rolling 60s windows. Reaching $\ge 3$ failures triggers automated caller blocking (`blocked_callers`), raising an incident in `soc_incidents`.

### Vector 5: Replay Attacks via Network Interception
- **Mechanism**: Attackers capture legitimate API traffic and replay the exact same signed request to trigger secondary debits.
- **Mitigation**: Strict nonce caching with single-use verification, combined with an ISO 8601 timestamp skew tolerance of $\pm 300\text{s}$.

### Vector 6: Insecure Direct Object Reference (IDOR)
- **Mechanism**: A legitimate client modifies `transaction_id` parameters in API calls to inspect financial records of unrelated borrowers.
- **Mitigation**: Strict tenant ownership validation; non-elevated tokens can only inspect transactions where `borrower_id == client_id` or originated by their client key.

### Vector 7: Audit Ledger Tampering
- **Mechanism**: An insider with direct database access alters transaction states from `REJECTED` to `APPROVED` or deletes audit entries.
- **Mitigation**: Dual-layer defense: SQLite triggers prevent SQL modifications; cryptographic SHA-256 hash chaining ensures any disk-level bit manipulation is mathematically flagged by `verify_evidence.py`.

---

## 3. STRIDE Threat Classification Matrix

| STRIDE Category | Threat Description | Severity | PAYGUARD Defensive Control | Residual Risk |
| :--- | :--- | :--- | :--- | :--- |
| **Spoofing** | Attacker presents forged or stolen synthetic tokens. | HIGH | Synthetic token registry, scope checks, automated abuse containment (`DET-04`). | Minimal (Token secrecy dependent). |
| **Tampering** | Attacker modifies disbursement amounts or replay payloads. | CRITICAL | Idempotency payload hashing (`IDEMPOTENCY_PAYLOAD_MISMATCH` $\rightarrow 409$). | Negligible. |
| **Repudiation** | Analyst approves a fraudulent transaction and denies action. | HIGH | Mandatory `analyst_id` + documented `decision_reason` recorded in SHA-256 chained audit ledger. | Negligible. |
| **Information Disclosure** | IDOR access across multi-tenant loan transactions. | HIGH | Client ownership verification on `GET /api/v1/disbursements/{id}`. | Negligible. |
| **Denial of Service** | Concurrent burst requests attempting balance overdraw. | HIGH | SQLite `BEGIN IMMEDIATE` write serialization; balance verification under lock. | Negligible. |
| **Elevation of Privilege** | Standard client attempting SOC analyst hold override. | CRITICAL | Scope-based access control requiring `soc:review` scope for review endpoints. | Negligible. |

---

## 4. Defense-in-Depth Architecture

```text
[ External Perimeter ]   --> Socket Network Isolation (Runtime blocks external traffic)
[ API Gateway Layer ]    --> Token scopes + Nonces + Clock skew + IDOR checks + Secret Redaction
[ Transaction Engine ]   --> 5-State FSM + BEGIN IMMEDIATE Concurrency Locks + Idempotency
[ Fraud Detection ]      --> DET-01, DET-02, DET-03, DET-04 Deterministic Evaluators
[ Response Engine ]      --> Proactive Caller Blocking + Token Revocation + Incident Escalation
[ Forensic Storage ]     --> Append-Only Triggers + SHA-256 Chained Ledger + Signed Manifest
```
