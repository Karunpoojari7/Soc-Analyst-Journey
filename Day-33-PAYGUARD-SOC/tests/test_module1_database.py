"""Module 1 Tests: Database, Schema, Application-Level Triggers & Seed Data."""

import pytest
import sqlite3
from backend.data.database import get_db_connection, atomic_transaction, init_database
from backend.data.seed import seed_database
from backend.config import settings


@pytest.fixture(autouse=True)
def setup_test_db(tmp_path):
    """Use a temporary SQLite database for test isolation."""
    db_file = str(tmp_path / "test_payguard.db")
    settings.DATABASE_PATH = db_file
    seed_database(db_file)
    yield db_file


def test_seed_loans_inr():
    conn = get_db_connection()
    rows = conn.execute("SELECT loan_id, approved_limit_inr, disbursed_amount_inr, status FROM loans").fetchall()
    loans = {r["loan_id"]: dict(r) for r in rows}
    
    assert "LOAN-IND-1001" in loans
    assert loans["LOAN-IND-1001"]["approved_limit_inr"] == 50000.00
    assert loans["LOAN-IND-1001"]["disbursed_amount_inr"] == 0.00
    assert loans["LOAN-IND-1001"]["status"] == "APPROVED"
    
    # Check loan nearing limit
    assert loans["LOAN-IND-1002"]["approved_limit_inr"] == 100000.00
    assert loans["LOAN-IND-1002"]["disbursed_amount_inr"] == 90000.00
    assert loans["LOAN-IND-1002"]["status"] == "APPROVED"
    
    # Check pending & closed
    assert loans["LOAN-IND-1003"]["status"] == "PENDING"
    assert loans["LOAN-IND-1004"]["status"] == "CLOSED"
    conn.close()


def test_audit_triggers_application_level_protection():
    """Verify that SQLite triggers block UPDATE and DELETE on audit_ledger."""
    conn = get_db_connection()
    
    # Insert a dummy audit log directly
    conn.execute("""
    INSERT INTO audit_ledger 
    (event_id, timestamp, correlation_id, actor, action, decision_reason, payload_sha256, prev_hash, record_hash)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
    """, (
        "EVT-TEST-01", "2026-11-19T12:00:00Z", "CORR-01", "test_actor", 
        "TEST_ACTION", "TEST_REASON", "dummy_payload_hash", "0"*64, "dummy_rec_hash"
    ))
    
    # Attempt UPDATE - should be blocked by trigger
    with pytest.raises(sqlite3.IntegrityError, match="APPLICATION INTEGRITY VIOLATION"):
        conn.execute("UPDATE audit_ledger SET actor = 'tampered' WHERE event_id = 'EVT-TEST-01';")
        
    # Attempt DELETE - should be blocked by trigger
    with pytest.raises(sqlite3.IntegrityError, match="APPLICATION INTEGRITY VIOLATION"):
        conn.execute("DELETE FROM audit_ledger WHERE event_id = 'EVT-TEST-01';")
        
    conn.close()


def test_atomic_transaction_rollback():
    """Verify that atomic_transaction rolls back changes upon error."""
    conn = get_db_connection()
    
    with pytest.raises(ValueError):
        with atomic_transaction(conn) as cur:
            cur.execute("""
            UPDATE loans SET disbursed_amount_inr = 99999.00 WHERE loan_id = 'LOAN-IND-1001';
            """)
            raise ValueError("Forced error during atomic block")
            
    # Verify disbursed_amount_inr was rolled back to 0.00
    row = conn.execute("SELECT disbursed_amount_inr FROM loans WHERE loan_id = 'LOAN-IND-1001';").fetchone()
    assert row["disbursed_amount_inr"] == 0.00
    conn.close()
