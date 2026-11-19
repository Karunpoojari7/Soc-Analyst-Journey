"""Module 2 Tests: Transaction Engine, FSM, Idempotency & Concurrency Serialization."""

import pytest
import concurrent.futures
from backend.data.database import get_db_connection, init_database
from backend.data.seed import seed_database
from backend.models.domain import (
    DisbursementRequest,
    TransactionState,
    DecisionReason,
    AnalystReviewRequest
)
from backend.engine.transaction_engine import TransactionEngine, IdempotencyConflictError
from backend.config import settings


@pytest.fixture(autouse=True)
def setup_test_db(tmp_path):
    db_file = str(tmp_path / "test_module2.db")
    settings.DATABASE_PATH = db_file
    seed_database(db_file)
    yield db_file


def test_successful_disbursement():
    conn = get_db_connection()
    engine = TransactionEngine(conn)
    
    req = DisbursementRequest(
        loan_id="LOAN-IND-1001",
        borrower_id="BORR-IND-901",
        beneficiary_id="BENEF-IND-01",
        amount_inr=15000.00
    )
    
    status_code, resp = engine.process_disbursement(
        request=req,
        client_id="client_test",
        idempotency_key="idemp-test-01",
        correlation_id="corr-test-01"
    )
    
    assert status_code == 200
    assert resp.state == TransactionState.APPROVED
    assert resp.decision_reason == DecisionReason.APPROVED_OK.value
    assert resp.amount_inr == 15000.00
    
    # Verify loan balance updated
    loan = conn.execute("SELECT disbursed_amount_inr FROM loans WHERE loan_id = 'LOAN-IND-1001';").fetchone()
    assert loan["disbursed_amount_inr"] == 15000.00
    conn.close()


def test_balance_exhaustion():
    conn = get_db_connection()
    engine = TransactionEngine(conn)
    
    # Limit is 50,000 INR - request 60,000 INR
    req = DisbursementRequest(
        loan_id="LOAN-IND-1001",
        borrower_id="BORR-IND-901",
        beneficiary_id="BENEF-IND-01",
        amount_inr=60000.00
    )
    
    status_code, resp = engine.process_disbursement(
        request=req,
        client_id="client_test",
        idempotency_key="idemp-test-02",
        correlation_id="corr-test-02"
    )
    
    assert status_code == 422
    assert resp.state == TransactionState.REJECTED
    assert resp.decision_reason == DecisionReason.INSUFFICIENT_APPROVED_LOAN_BALANCE.value
    conn.close()


def test_unapproved_loan_rejection():
    conn = get_db_connection()
    engine = TransactionEngine(conn)
    
    # LOAN-IND-1003 is PENDING
    req = DisbursementRequest(
        loan_id="LOAN-IND-1003",
        borrower_id="BORR-IND-903",
        beneficiary_id="BENEF-IND-03",
        amount_inr=5000.00
    )
    
    status_code, resp = engine.process_disbursement(
        request=req,
        client_id="client_test",
        idempotency_key="idemp-test-03",
        correlation_id="corr-test-03"
    )
    
    assert status_code == 400
    assert resp.state == TransactionState.REJECTED
    assert resp.decision_reason == DecisionReason.INVALID_OR_UNAPPROVED_LOAN_STATUS.value
    conn.close()


def test_beneficiary_mismatch_rejection():
    conn = get_db_connection()
    engine = TransactionEngine(conn)
    
    # Requesting disbursement to BENEF-IND-02 which belongs to BORR-IND-902, not BORR-IND-901
    req = DisbursementRequest(
        loan_id="LOAN-IND-1001",
        borrower_id="BORR-IND-901",
        beneficiary_id="BENEF-IND-02",
        amount_inr=5000.00
    )
    
    status_code, resp = engine.process_disbursement(
        request=req,
        client_id="client_test",
        idempotency_key="idemp-test-04",
        correlation_id="corr-test-04"
    )
    
    assert status_code == 400
    assert resp.state == TransactionState.REJECTED
    assert resp.decision_reason == DecisionReason.BENEFICIARY_NOT_REGISTERED.value
    conn.close()


def test_idempotency_replay_and_conflict():
    conn = get_db_connection()
    engine = TransactionEngine(conn)
    
    req = DisbursementRequest(
        loan_id="LOAN-IND-1001",
        borrower_id="BORR-IND-901",
        beneficiary_id="BENEF-IND-01",
        amount_inr=5000.00
    )
    
    status1, resp1 = engine.process_disbursement(
        request=req,
        client_id="client_test",
        idempotency_key="idemp-key-replay-100",
        correlation_id="corr-100"
    )
    assert status1 == 200
    assert resp1.state == TransactionState.APPROVED
    
    # Replay identical request with same key
    status2, resp2 = engine.process_disbursement(
        request=req,
        client_id="client_test",
        idempotency_key="idemp-key-replay-100",
        correlation_id="corr-101"
    )
    assert status2 == 200
    assert resp2.transaction_id == resp1.transaction_id
    
    # Verify balance was only deducted ONCE (₹5,000, not ₹10,000)
    loan = conn.execute("SELECT disbursed_amount_inr FROM loans WHERE loan_id = 'LOAN-IND-1001';").fetchone()
    assert loan["disbursed_amount_inr"] == 5000.00
    
    # Conflict: Send different amount with same idempotency key
    req_tampered = DisbursementRequest(
        loan_id="LOAN-IND-1001",
        borrower_id="BORR-IND-901",
        beneficiary_id="BENEF-IND-01",
        amount_inr=9999.00
    )
    with pytest.raises(IdempotencyConflictError):
        engine.process_disbursement(
            request=req_tampered,
            client_id="client_test",
            idempotency_key="idemp-key-replay-100",
            correlation_id="corr-102"
        )
    conn.close()


def test_concurrent_disbursement_balance_exhaustion():
    """Verify that concurrent requests serialize and cannot exceed approved limit."""
    # LOAN-IND-1002 has 100,000 limit with 90,000 already disbursed. Remaining = 10,000 INR.
    # Launch 6 concurrent threads trying to disburse 5,000 INR each (total 30,000 INR requested).
    # Exactly 2 requests must succeed (2 * 5,000 = 10,000 INR). 4 must fail with 422.
    
    def attempt_disbursement(worker_id):
        # Dedicated SQLite connection per worker thread
        local_conn = get_db_connection()
        try:
            local_engine = TransactionEngine(local_conn)
            req = DisbursementRequest(
                loan_id="LOAN-IND-1002",
                borrower_id="BORR-IND-902",
                beneficiary_id="BENEF-IND-02",
                amount_inr=5000.00
            )
            return local_engine.process_disbursement(
                request=req,
                client_id=f"worker_{worker_id}",
                idempotency_key=f"concurrent-key-{worker_id}",
                correlation_id=f"corr-concurrent-{worker_id}"
            )
        finally:
            local_conn.close()

    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
        futures = [executor.submit(attempt_disbursement, i) for i in range(6)]
        results = [f.result() for f in futures]

    statuses = [r[0] for r in results]
    successes = [r for r in results if r[0] == 200]
    failures = [r for r in results if r[0] == 422]

    assert len(successes) == 2, f"Expected exactly 2 successes, got {len(successes)}: {statuses}"
    assert len(failures) == 4, f"Expected exactly 4 failures, got {len(failures)}: {statuses}"

    # Verify final balance is exactly 100,000 INR (never exceeding limit)
    conn = get_db_connection()
    loan = conn.execute("SELECT disbursed_amount_inr, approved_limit_inr FROM loans WHERE loan_id = 'LOAN-IND-1002';").fetchone()
    assert loan["disbursed_amount_inr"] == 100000.00
    conn.close()
