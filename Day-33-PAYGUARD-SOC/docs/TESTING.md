# PAYGUARD SOC: Testing Strategy & Verification Matrix

> **Scope**: 100% automated test coverage across database ACID constraints, concurrency locks, API security gateways, deterministic fraud detection, cryptographic evidence chaining, and SOC endpoints.

---

## 1. Test Architecture & Principles

- **Zero Global Mutation**: Every test module uses isolated temporary databases (`tmp_path / "test.db"`) to guarantee clean, deterministic state without modifying on-disk production records.
- **In-Memory Endpoint Invocations**: Standard Starlette `TestClient` uses thread blocking portals that create Windows loopback socketpairs blocked by Windows sandbox mode (`WinError 10013`). The test suite uses custom in-memory dependency injection (`TestApiClient`), enabling instant socket-free test execution.
- **Strict Currency Validation**: All assertions enforce synthetic Indian Rupees (`INR` / `₹`).

---

## 2. Test Matrix (39 Automated Tests)

| Module | Test Name | Target Capability | Verification Outcome |
| :--- | :--- | :--- | :--- |
| **Module 1: Database & Schema** | `test_seed_loans_inr` | Verifies initial loan limits in INR | PASSED |
| | `test_audit_triggers_application_level_protection` | SQL UPDATE/DELETE blocked on `audit_ledger` | PASSED |
| | `test_atomic_transaction_rollback` | Rollback on exception without partial writes | PASSED |
| **Module 2: Transaction Engine** | `test_successful_disbursement` | Valid transaction reaches `APPROVED` state | PASSED |
| | `test_balance_exhaustion` | Request exceeding approved limit rejected | PASSED |
| | `test_unapproved_loan_rejection` | Pending/Closed loan rejected | PASSED |
| | `test_beneficiary_mismatch_rejection`| Beneficiary belonging to another borrower rejected | PASSED |
| | `test_idempotency_replay_and_conflict` | Deduplication vs. 409 Conflict on payload tampering | PASSED |
| | `test_concurrent_disbursement_balance_exhaustion` | Multi-threaded race condition cannot overdraw | PASSED |
| **Module 3: API Security** | `test_valid_token_and_scope` | Successful authorization with correct scope | PASSED |
| | `test_missing_and_invalid_token` | HTTP 401 on missing or forged token | PASSED |
| | `test_expired_token` | HTTP 401 on expired token timestamp | PASSED |
| | `test_revoked_token` | HTTP 401 on revoked token | PASSED |
| | `test_insufficient_scope` | HTTP 403 on mismatched authorization scope | PASSED |
| | `test_timestamp_skew_and_replay_prevention` | Rejection of clock skew >300s & duplicate nonces | PASSED |
| | `test_secret_log_redaction` | `lab_tok_*` masked to `[REDACTED]` in logs | PASSED |
| | `test_network_isolation_socket_interceptor` | RuntimeError on outbound socket/DNS attempt | PASSED |
| **Module 4: Fraud Detection** | `test_det01_micro_to_high_value_probe` | Micro-probe triggers `HELD` state | PASSED |
| | `test_det02_unseen_beneficiary_velocity_spike` | Unseen recipient + velocity triggers `HELD` | PASSED |
| | `test_analyst_review_workflow_held_to_approved` | SOC analyst review debits balance & approves | PASSED |
| **Module 5: Evidence Vault** | `test_evidence_export_and_valid_independent_verification` | Standalone CLI verifies hash chain $H_0 \to H_N$ | PASSED |
| | `test_tampered_record_detection` | CLI flags altered payload and stops verification | PASSED |
| | `test_tampered_manifest_detection` | CLI flags invalid HMAC signature | PASSED |
| **Module 6: SOC Operations** | `test_health_and_loans_endpoint` | Health check & available balance calculations | PASSED |
| | `test_soc_overview_and_transactions_metrics` | Metrics aggregation by FSM state | PASSED |
| | `test_soc_alerts_and_auth_telemetry` | Detection rules & auth attempts feed | PASSED |
| | `test_soc_incident_lifecycle_and_containment` | Incident creation, update, and caller isolation | PASSED |
| | `test_caller_block_and_unblock` | Administrative blocking & unblocking | PASSED |
| | `test_token_revocation_endpoint` | Immediate token revocation | PASSED |
| | `test_idor_protection_enforcement` | Non-owner client blocked from reading records (403) | PASSED |
| **E2E API Integration** | `test_e2e_successful_disbursement_and_status_check` | Full lifecycle create and fetch | PASSED |
| | `test_e2e_duplicate_request_idempotency` | Duplicate call returns cached response | PASSED |
| | `test_e2e_idempotency_payload_conflict` | Modified payload returns 409 Conflict | PASSED |
| | `test_e2e_expired_and_revoked_tokens` | Gateway security checks | PASSED |
| | `test_e2e_transaction_replay_attack` | Replayed nonce blocked | PASSED |
| | `test_e2e_invalid_loan_reference` | Invalid loan reference rejected | PASSED |
| | `test_e2e_micro_probe_held_and_analyst_review_workflow` | End-to-end DET-01 hold & analyst override | PASSED |
| | `test_e2e_evidence_export_and_standalone_verification` | End-to-end export and validation | PASSED |
| | `test_e2e_network_isolation_verification` | Active isolation blocks outbound connections | PASSED |

---

## 3. How to Run the Tests

```bash
# Run all tests
pytest tests/ -v

# Run with execution duration report
pytest tests/ --durations=10

# Run specific module
pytest tests/test_module6_soc_endpoints.py -v
```
