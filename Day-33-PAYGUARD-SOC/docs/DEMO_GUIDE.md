# PAYGUARD SOC: 12-Step Demonstration Walkthrough

> **Instructor & Evaluator Guide**: This step-by-step walkthrough demonstrates every defensive capability of the PAYGUARD SOC platform. Commands can be run via the CLI or triggered visually from the **Web Dashboard** at `http://127.0.0.1:8000/dashboard`.

---

## Pre-Requisites
1. Start the API server:
   ```bash
   uvicorn backend.api.app:app --host 127.0.0.1 --port 8000
   ```
2. Open a second terminal for executing commands.

---

### Step 1: Verify System Health & Network Isolation
**Command**:
```bash
curl -s http://127.0.0.1:8000/health
```
**Expected Output**:
```json
{
  "status": "HEALTHY",
  "app": "PAYGUARD-SOC-Core",
  "currency": "INR",
  "network_isolation_active": true
}
```
*Verification*: Confirms currency is strictly INR and socket-level network isolation is active.

---

### Step 2: Execute a Legitimate Disbursement in INR
**Command**:
```bash
curl -s -X POST http://127.0.0.1:8000/api/v1/disbursements \
  -H "Authorization: Bearer lab_tok_disburse_valid_999" \
  -H "X-Idempotency-Key: idemp-demo-step2" \
  -H "X-Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  -H "X-Nonce: nonce-demo-2" \
  -H "Content-Type: application/json" \
  -d '{"loan_id":"LOAN-IND-1001","borrower_id":"BORR-IND-901","beneficiary_id":"BENEF-IND-01","amount_inr":1500.00,"currency":"INR"}'
```
**Expected Output**:
`state: "APPROVED"`, `decision_reason: "APPROVED_OK"`, `amount_inr: 1500.00`.

---

### Step 3: Test Idempotency Deduplication
**Action**: Re-execute the exact command from Step 2 with the same `X-Idempotency-Key: idemp-demo-step2`.
**Expected Outcome**: Returns the exact same response instantly with HTTP 200 without double-debiting the loan balance.

---

### Step 4: Test Idempotency Payload Tampering Detection
**Action**: Send the same idempotency key `idemp-demo-step2`, but change `amount_inr` to `9999.00`.
**Expected Outcome**: Returns **HTTP 409 Conflict** with `IDEMPOTENCY_PAYLOAD_MISMATCH`.

---

### Step 5: Test Expired & Revoked Synthetic Tokens
**Command (Revoked Token)**:
```bash
curl -s -X POST http://127.0.0.1:8000/api/v1/disbursements \
  -H "Authorization: Bearer lab_tok_revoked_666" \
  -H "X-Idempotency-Key: idemp-demo-revoked" \
  -H "Content-Type: application/json" \
  -d '{"loan_id":"LOAN-IND-1001","borrower_id":"BORR-IND-901","beneficiary_id":"BENEF-IND-01","amount_inr":500.00}'
```
**Expected Outcome**: Returns **HTTP 401 Unauthorized** with `SECURITY_TOKEN_REVOKED`.

---

### Step 6: Test Replay Attack Defense
**Action**: Replay a previously used `X-Nonce` value.
**Expected Outcome**: Returns **HTTP 401 Unauthorized** with `SECURITY_REPLAY_DETECTED`.

---

### Step 7: Launch Attack Scenario 1 — Micro-Probe & High-Value Drain (DET-01)
**Command**:
```bash
python simulator/run_simulation.py --scenario 1
```
**Expected Outcome**:
- Probe transaction (₹50.00) is `APPROVED`.
- Subsequent high-value transaction (₹40,000.00) within 300s is flagged by **DET-01**.
- State transitions to **`HELD`**; funds are **not** debited; incident is opened.

---

### Step 8: SOC Analyst Hold Review & Approval
**Action**: In the Web Dashboard under the **Transactions** tab, click **Review** on the held transaction from Step 7.
- Decision: `APPROVE OVERRIDE`
- Analyst ID: `ANALYST-VIKRAM-01`
- Mandatory Reason: *"Borrower confirmed micro-test and subsequent capital purchase."*
- Click **Submit Resolution**.
**Expected Outcome**: Transaction moves to **`APPROVED`**; available loan balance is debited; signed audit record is created.

---

### Step 9: Launch Attack Scenario 2 — Unseen Beneficiary Velocity Spike (DET-02)
**Command**:
```bash
python simulator/run_simulation.py --scenario 2
```
**Expected Outcome**: DET-02 intercepts high-velocity disbursement to an unverified beneficiary; state transitions to **`HELD`**.

---

### Step 10: Test Credential Stuffing & Automated Caller Block (DET-04)
**Command**:
```bash
python simulator/run_simulation.py --scenario 4
```
**Expected Outcome**: Burst of invalid tokens detected; on the 4th attempt caller is blocked (`blocked_callers`); returns **HTTP 429 / HTTP 403**.

---

### Step 11: Export Forensic Evidence & Independent Verification
**Action**: In the Web Dashboard under **Evidence Vault**, click **Export & Verify Evidence Bundle**.
Then run the offline verifier:
```bash
python evidence/verify_evidence.py \
  --manifest evidence/evidence_manifest.json \
  --records evidence/evidence_records.jsonl
```
**Expected Output**:
```text
============================================================
  PAYGUARD SOC — Independent Cryptographic Evidence Verifier
============================================================
[1/2] Verifying HMAC-SHA256 Manifest Signature...
[✓] Manifest Signature VALID. Signed by authorized authority.
[2/2] Verifying Sequential SHA-256 Ledger Hash Chain...
[✓] Cryptographic Hash Chain VALID across all records. Zero tampering detected.
============================================================
```

---

### Step 12: Review Incident Response in SOC Web Dashboard
**Action**: Open `http://127.0.0.1:8000/dashboard` $\rightarrow$ **Incidents** tab.
- Inspect the incident generated by Scenario 1 or 4.
- Click **Respond**, select status `CONTAINED`, select action `BLOCK_SYNTHETIC_CALLER`, and submit.
- The offending caller is now isolated from all financial APIs.
