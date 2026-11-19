"""Module 4 Tests: Deterministic Fraud Rules & SOC Analyst Review Workflow."""

import pytest
from datetime import datetime, timezone
from backend.data.database import get_db_connection
from backend.data.seed import seed_database
from backend.config import settings
from backend.models.domain import (
    DisbursementRequest,
    TransactionState,
    DecisionReason,
    AnalystReviewRequest
)
from backend.engine.transaction_engine import TransactionEngine
from backend.engine.fraud_detector import DeterministicFraudEngine


@pytest.fixture(autouse=True)
def setup_test_db(tmp_path):
    db_file = str(tmp_path / "test_module4.db")
    settings.DATABASE_PATH = db_file
    seed_database(db_file)
    yield db_file


def test_det01_micro_to_high_value_probe():
    conn = get_db_connection()
    engine = TransactionEngine(conn)
    fraud_detector = DeterministicFraudEngine()

    # Step 1: Send micro-value transaction (₹20.00, <= ₹50.00)
    micro_req = DisbursementRequest(
        loan_id="LOAN-IND-1001",
        borrower_id="BORR-IND-901",
        beneficiary_id="BENEF-IND-01",
        amount_inr=20.00
    )
    status1, resp1 = engine.process_disbursement(
        request=micro_req,
        client_id="client_test",
        idempotency_key="idemp-micro-01",
        correlation_id="corr-micro-01",
        fraud_evaluator=fraud_detector
    )
    assert status1 == 200
    assert resp1.state == TransactionState.APPROVED

    # Step 2: Immediately send high-value transfer (₹10,000.00, >= ₹5,000.00)
    high_req = DisbursementRequest(
        loan_id="LOAN-IND-1001",
        borrower_id="BORR-IND-901",
        beneficiary_id="BENEF-IND-01",
        amount_inr=10000.00
    )
    status2, resp2 = engine.process_disbursement(
        request=high_req,
        client_id="client_test",
        idempotency_key="idemp-high-01",
        correlation_id="corr-high-01",
        fraud_evaluator=fraud_detector
    )
    assert status2 == 202
    assert resp2.state == TransactionState.HELD
    assert resp2.decision_reason == DecisionReason.FRAUD_PROBE_MICRO_HIGH_VALUE.value

    # Verify that the loan balance was NOT debited for the HELD transfer
    loan = conn.execute("SELECT disbursed_amount_inr FROM loans WHERE loan_id = 'LOAN-IND-1001';").fetchone()
    assert loan["disbursed_amount_inr"] == 20.00  # Only the micro transfer was debited
    conn.close()


def test_det02_unseen_beneficiary_velocity_spike():
    conn = get_db_connection()
    now_ts = datetime.now(timezone.utc).isoformat()

    # Register a new beneficiary for BORR-IND-901
    conn.execute("""
        INSERT INTO beneficiaries (beneficiary_id, borrower_id, account_number, ifsc_code, status, registered_at)
        VALUES ('BENEF-NEW-99', 'BORR-IND-901', '919999999999', 'HDFC0009999', 'ACTIVE', ?);
    """, (now_ts,))

    engine = TransactionEngine(conn)
    fraud_detector = DeterministicFraudEngine()

    # Simulate 3 rapid prior transactions to an existing beneficiary
    for i in range(3):
        req = DisbursementRequest(
            loan_id="LOAN-IND-1001",
            borrower_id="BORR-IND-901",
            beneficiary_id="BENEF-IND-01",
            amount_inr=100.00
        )
        status, resp = engine.process_disbursement(
            request=req,
            client_id="client_test",
            idempotency_key=f"idemp-vel-{i}",
            correlation_id=f"corr-vel-{i}",
            fraud_evaluator=fraud_detector
        )
        assert status == 200

    # 4th transaction targeting the brand-new, unseen beneficiary
    unseen_req = DisbursementRequest(
        loan_id="LOAN-IND-1001",
        borrower_id="BORR-IND-901",
        beneficiary_id="BENEF-NEW-99",
        amount_inr=2000.00
    )
    status_unseen, resp_unseen = engine.process_disbursement(
        request=unseen_req,
        client_id="client_test",
        idempotency_key="idemp-vel-unseen-4",
        correlation_id="corr-vel-unseen-4",
        fraud_evaluator=fraud_detector
    )
    assert status_unseen == 202
    assert resp_unseen.state == TransactionState.HELD
    assert resp_unseen.decision_reason == DecisionReason.FRAUD_UNSEEN_BENEFICIARY_VELOCITY.value
    conn.close()


def test_analyst_review_workflow_held_to_approved():
    conn = get_db_connection()
    engine = TransactionEngine(conn)
    fraud_detector = DeterministicFraudEngine()

    # Create a HELD transaction via DET-01
    micro_req = DisbursementRequest(
        loan_id="LOAN-IND-1001",
        borrower_id="BORR-IND-901",
        beneficiary_id="BENEF-IND-01",
        amount_inr=10.00
    )
    engine.process_disbursement(
        request=micro_req,
        client_id="client_test",
        idempotency_key="idemp-rev-micro",
        correlation_id="corr-rev-1",
        fraud_evaluator=fraud_detector
    )

    high_req = DisbursementRequest(
        loan_id="LOAN-IND-1001",
        borrower_id="BORR-IND-901",
        beneficiary_id="BENEF-IND-01",
        amount_inr=5000.00
    )
    _, held_resp = engine.process_disbursement(
        request=high_req,
        client_id="client_test",
        idempotency_key="idemp-rev-high",
        correlation_id="corr-rev-2",
        fraud_evaluator=fraud_detector
    )
    assert held_resp.state == TransactionState.HELD

    # SOC Analyst performs manual review and approves
    review = AnalystReviewRequest(
        action="APPROVE",
        analyst_id="SOC-ANALYST-VIKRAM",
        decision_reason="Verified borrower via telephone authentication; verified genuine business expense.",
        analyst_notes="Borrower confirmed sudden supplier payment requirement."
    )

    status_rev, rev_resp = engine.review_held_transaction(
        transaction_id=held_resp.transaction_id,
        review=review,
        correlation_id="corr-analyst-review-01"
    )

    assert status_rev == 200
    assert rev_resp.state == TransactionState.APPROVED
    assert rev_resp.decision_reason == DecisionReason.ANALYST_OVERRIDE_APPROVED.value

    # Verify that the ₹5,000 amount was now debited (total = 10 + 5000 = 5010 INR)
    loan = conn.execute("SELECT disbursed_amount_inr FROM loans WHERE loan_id = 'LOAN-IND-1001';").fetchone()
    assert loan["disbursed_amount_inr"] == 5010.00

    # Verify audit trail records the analyst review
    audit = conn.execute("""
        SELECT actor, action, state_from, state_to, decision_reason 
        FROM audit_ledger 
        WHERE action = 'ANALYST_HOLD_RESOLUTION';
    """).fetchone()

    assert audit["actor"] == "SOC-ANALYST-VIKRAM"
    assert audit["state_from"] == "HELD"
    assert audit["state_to"] == "APPROVED"
    assert "telephone authentication" in audit["decision_reason"]
    conn.close()
