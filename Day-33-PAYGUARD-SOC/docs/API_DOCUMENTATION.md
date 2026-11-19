# PAYGUARD SOC: REST API Specification & Reference

> **Environment**: All endpoints are purely synthetic and local. All financial values are modeled in **INR (₹)**.

---

## 1. Authentication & Security Headers

All requests to protected endpoints require synthetic Bearer tokens and security headers:

| Header Name | Type | Description | Required On |
| :--- | :--- | :--- | :--- |
| `Authorization` | String | Format: `Bearer <synthetic_token>` | All protected endpoints |
| `X-Idempotency-Key`| UUIDv4 | Unique client request key for deduplication | `POST /api/v1/disbursements` |
| `X-Timestamp` | ISO 8601 | Current UTC timestamp ($\pm 300\text{s}$ tolerance) | Core disbursement calls |
| `X-Nonce` | String | Single-use random identifier for replay protection | Core disbursement calls |
| `X-Correlation-ID` | String | End-to-end tracing identifier (e.g. `CORR-01`) | Optional (Auto-generated if absent) |

### Synthetic Tokens & Scopes

| Token String | Client Identity | Scopes | Role |
| :--- | :--- | :--- | :--- |
| `lab_tok_disburse_valid_999` | `client_lending_partner_01` | `disbursement:create,disbursement:read` | Standard Lending Partner |
| `lab_tok_readonly_888` | `client_auditor_01` | `disbursement:read` | Read-Only Auditor |
| `lab_tok_soc_analyst_777` | `soc_analyst_01` | `soc:review,audit:export,disbursement:read` | SOC Security Analyst |
| `lab_tok_revoked_666` | `client_compromised_01` | `disbursement:create` | Revoked Credential |
| `lab_tok_expired_555` | `client_old_partner_01` | `disbursement:create` | Expired Credential |

---

## 2. API Endpoints

### 2.1 System Health
```http
GET /health
```
**Response (200 OK)**:
```json
{
  "status": "HEALTHY",
  "app": "PAYGUARD-SOC-Core",
  "currency": "INR",
  "network_isolation_active": true
}
```

---

### 2.2 Loan Registry
```http
GET /api/v1/loans
Authorization: Bearer lab_tok_readonly_888
```
**Response (200 OK)**:
```json
[
  {
    "loan_id": "LOAN-IND-1001",
    "borrower_id": "BORR-IND-901",
    "approved_limit_inr": 50000.0,
    "disbursed_amount_inr": 0.0,
    "available_balance_inr": 50000.0,
    "status": "APPROVED",
    "created_at": "2026-11-19T22:00:00Z",
    "updated_at": "2026-11-19T22:00:00Z"
  }
]
```

---

### 2.3 Create Disbursement
```http
POST /api/v1/disbursements
Authorization: Bearer lab_tok_disburse_valid_999
X-Idempotency-Key: idemp-req-001
X-Timestamp: 2026-11-19T23:00:00Z
X-Nonce: nonce-abc-123
Content-Type: application/json

{
  "loan_id": "LOAN-IND-1001",
  "borrower_id": "BORR-IND-901",
  "beneficiary_id": "BENEF-IND-01",
  "amount_inr": 12000.00,
  "currency": "INR",
  "purpose": "Agricultural Micro-Disbursement"
}
```
**Response (200 OK - Approved)**:
```json
{
  "transaction_id": "TX-IND-4DA4A476B6FB",
  "state": "APPROVED",
  "loan_id": "LOAN-IND-1001",
  "borrower_id": "BORR-IND-901",
  "beneficiary_id": "BENEF-IND-01",
  "amount_inr": 12000.0,
  "currency": "INR",
  "decision_reason": "APPROVED_OK",
  "correlation_id": "CORR-TX-901",
  "created_at": "2026-11-19T23:00:01Z"
}
```

---

### 2.4 Get Disbursement (With IDOR Protection)
```http
GET /api/v1/disbursements/{transaction_id}
Authorization: Bearer lab_tok_readonly_888
```
- Non-elevated tokens can only inspect transactions they created or own. Cross-tenant queries return `403 Forbidden`.

---

### 2.5 SOC Analyst Review of HELD Transactions
```http
POST /api/v1/soc/transactions/{transaction_id}/review
Authorization: Bearer lab_tok_soc_analyst_777
Content-Type: application/json

{
  "action": "APPROVE",
  "analyst_id": "ANALYST-VIKRAM-01",
  "decision_reason": "Beneficiary account verified with borrower via phone.",
  "analyst_notes": "Out-of-band verification completed successfully."
}
```
**Response (200 OK)**:
```json
{
  "transaction_id": "TX-IND-4DA4A476B6FB",
  "state": "APPROVED",
  "decision_reason": "ANALYST_OVERRIDE_APPROVED",
  "amount_inr": 40000.0
}
```

---

### 2.6 SOC Executive Overview
```http
GET /api/v1/soc/overview
Authorization: Bearer lab_tok_soc_analyst_777
```
**Response (200 OK)**:
```json
{
  "app_name": "PAYGUARD-SOC-Core",
  "currency": "INR",
  "currency_symbol": "₹",
  "network_isolation_active": true,
  "total_transactions": 25,
  "approved_count": 18,
  "held_count": 3,
  "rejected_count": 4,
  "total_disbursed_inr": 185000.0,
  "total_held_inr": 65000.0,
  "active_alerts_count": 7,
  "open_incidents_count": 2,
  "blocked_callers_count": 1,
  "auth_failures_count": 4
}
```

---

### 2.7 Export Cryptographic Evidence Vault
```http
POST /api/v1/soc/evidence/export
Authorization: Bearer lab_tok_soc_analyst_777
```
**Response (200 OK)**:
```json
{
  "status": "EXPORT_SUCCESS",
  "records_file": "evidence/evidence_records.jsonl",
  "manifest_file": "evidence/evidence_manifest.json",
  "correlation_id": "CORR-EXP-999"
}
```

---

### 2.8 Attack Simulator Trigger
```http
POST /api/v1/simulator/run-scenario
Authorization: Bearer lab_tok_soc_analyst_777
Content-Type: application/json

{
  "scenario": 1
}
```
**Response (200 OK)**:
```json
{
  "scenario_id": 1,
  "name": "Micro-Value Probe & High-Value Rapid Transfer",
  "target_rule": "DET-01",
  "detected": true,
  "defensive_action": "TRANSACTION_HELD",
  "incident_id": "INC-4C30880A"
}
```
