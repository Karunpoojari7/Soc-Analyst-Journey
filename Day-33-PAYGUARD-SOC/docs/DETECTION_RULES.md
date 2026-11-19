# PAYGUARD SOC: Deterministic Detection Rules Specification

> **Design Principle**: All rules in this engine are strictly **deterministic, explainable, and rule-based**. They are completely separated from opaque statistical machine learning models to ensure that every alert and state transition is 100% auditable for regulatory compliance and forensic review.

---

## Rule Index

- **`DET-01`**: Micro-Value Probe Followed by High-Value Transfer
- **`DET-02`**: Unseen Beneficiary Combined with Velocity Spike
- **`DET-03`**: Loan Facility Integrity & Status Validation
- **`DET-04`**: API Authentication Abuse & Credential Stuffing Burst

---

## 1. DET-01: Micro-Value Probe to High-Value Drain

### Threat Context & Attack Vector
Attackers possessing stolen FinTech credentials or attempting to siphon funds from approved loan facilities typically conduct a "micro-probe". By initiating a trivial disbursement ($\le ₹50.00$), they verify that the API token is valid, the account routing works, and no instant fraud block occurs. Once confirmed, they immediately attempt a large transfer ($\ge ₹5,000.00$) to drain the available limit before security teams intervene.

### Detection Logic & State Machine Transition
When a new disbursement request arrives:
1. Check if `amount_inr >= settings.HIGH_VALUE_MIN_INR` (default: ₹5,000.00).
2. If True, query historical transactions for the same `(loan_id, borrower_id)` within `MICRO_PROBE_WINDOW_SECONDS` (default: 300s):
   ```sql
   SELECT transaction_id, amount_inr, created_at 
   FROM transactions
   WHERE borrower_id = ? 
     AND loan_id = ?
     AND state IN ('APPROVED', 'VALIDATED')
     AND amount_inr <= ?
     AND created_at >= ?
   ORDER BY created_at DESC LIMIT 1;
   ```
3. If a matching micro-transaction is found:
   - **FSM State**: `HELD`
   - **Decision Reason**: `FRAUD_PROBE_MICRO_HIGH_VALUE`
   - **Response Code**: HTTP 200 (Transaction accepted into hold; funds **not** debited)
   - **Escalation**: Automatically registers an incident in `soc_incidents`

### False Positive Mitigation
- Standard borrowers may legitimately make small test transfers. The system does not reject the transaction; it places it in `HELD`, enabling legitimate users to clear the hold via quick SOC operator verification without impacting their credit balance.

---

## 2. DET-02: Unseen Beneficiary Velocity Spike

### Threat Context & Attack Vector
When FinTech systems are compromised, attackers frequently add a new bank account belonging to a money mule syndicate. To maximize illicit extraction before the victim notices SMS alerts, multiple disbursements are pushed in rapid succession.

### Detection Logic & State Machine Transition
When a transaction is evaluated:
1. Verify if `beneficiary_id` has **zero** historically approved disbursements for this borrower:
   ```sql
   SELECT COUNT(*) FROM transactions 
   WHERE borrower_id = ? 
     AND beneficiary_id = ? 
     AND state = 'APPROVED';
   ```
2. If count is 0, query total transactions created by this borrower within `VELOCITY_WINDOW_SECONDS` (default: 60s):
   ```sql
   SELECT COUNT(*) FROM transactions
   WHERE borrower_id = ? 
     AND created_at >= ?;
   ```
3. If `recent_tx_count >= VELOCITY_MAX_TX_COUNT` (default: 3):
   - **FSM State**: `HELD`
   - **Decision Reason**: `FRAUD_UNSEEN_BENEFICIARY_VELOCITY`
   - **Escalation**: Escalates HIGH severity incident in `soc_incidents`

---

## 3. DET-03: Loan Facility Integrity Violation

### Threat Context & Attack Vector
Attackers exploit unvalidated backend routes to disburse against non-existent, cancelled, pending, or closed credit lines, attempting to create phantom loans or cause discrepancies in core banking records.

### Detection Logic & State Machine Transition
1. Query loan status under exclusive `BEGIN IMMEDIATE` lock:
   ```sql
   SELECT approved_limit_inr, disbursed_amount_inr, status 
   FROM loans WHERE loan_id = ?;
   ```
2. If loan does not exist or `status != 'APPROVED'`:
   - **FSM State**: `REJECTED`
   - **Decision Reason**: `INVALID_OR_UNAPPROVED_LOAN_STATUS`
   - **Response Code**: HTTP 400 Bad Request
   - **Audit Action**: `TRANSACTION_REJECTED`

---

## 4. DET-04: API Authentication Abuse Burst

### Threat Context & Attack Vector
Automated attack tools and botnets attempt credential stuffing or iterate through candidate tokens.

### Detection Logic & State Machine Transition
1. On every invalid or missing token verification in `backend/api/security.py`:
   - Record entry into `auth_attempts (client_id, token_presented, status, failure_reason, timestamp)`
2. Evaluate failure burst for caller:
   ```sql
   SELECT COUNT(*) FROM auth_attempts
   WHERE client_id = ? 
     AND status = 'FAILURE' 
     AND timestamp >= (now - 60 seconds);
   ```
3. If failure count $\ge 3$:
   - Automatically insert client into `blocked_callers`
   - Raise `SecurityValidationError(status_code=429, reason_code="SECURITY_AUTH_ABUSE_DETECTED")`
   - Escalate CRITICAL incident in `soc_incidents`
   - All subsequent calls from this client identity immediately return HTTP 403 `SECURITY_CALLER_BLOCKED`
