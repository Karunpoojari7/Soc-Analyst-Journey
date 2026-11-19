"""Module 5 Tests: Evidence Export and Independent Forensic Verification."""

import pytest
import json
import os
from backend.data.database import get_db_connection
from backend.data.seed import seed_database
from backend.config import settings
from backend.models.domain import DisbursementRequest
from backend.engine.transaction_engine import TransactionEngine
from backend.engine.evidence_exporter import export_evidence_bundle
from evidence.verify_evidence import verify_evidence_integrity


@pytest.fixture(autouse=True)
def setup_test_db(tmp_path):
    db_file = str(tmp_path / "test_module5.db")
    settings.DATABASE_PATH = db_file
    seed_database(db_file)
    yield db_file


def test_evidence_export_and_valid_independent_verification(tmp_path):
    conn = get_db_connection()
    engine = TransactionEngine(conn)

    # Perform a few transactions to build an audit trail
    for i in range(3):
        req = DisbursementRequest(
            loan_id="LOAN-IND-1001",
            borrower_id="BORR-IND-901",
            beneficiary_id="BENEF-IND-01",
            amount_inr=1000.00 * (i + 1)
        )
        engine.process_disbursement(
            request=req,
            client_id="client_test",
            idempotency_key=f"idemp-evid-{i}",
            correlation_id=f"corr-evid-{i}"
        )

    # Export evidence bundle to temporary folder
    export_dir = str(tmp_path / "forensics_export")
    records_file, manifest_file = export_evidence_bundle(
        conn=conn,
        output_dir=export_dir,
        hmac_secret=settings.EVIDENCE_HMAC_SECRET
    )

    assert os.path.exists(records_file)
    assert os.path.exists(manifest_file)

    # Run independent verification
    is_valid, msg = verify_evidence_integrity(
        manifest_path=manifest_file,
        records_path=records_file,
        hmac_secret=settings.EVIDENCE_HMAC_SECRET
    )

    assert is_valid is True
    assert "FORENSIC VERIFICATION SUCCESSFUL" in msg
    conn.close()


def test_tampered_record_detection(tmp_path):
    conn = get_db_connection()
    engine = TransactionEngine(conn)

    req = DisbursementRequest(
        loan_id="LOAN-IND-1001",
        borrower_id="BORR-IND-901",
        beneficiary_id="BENEF-IND-01",
        amount_inr=500.00
    )
    engine.process_disbursement(
        request=req,
        client_id="client_test",
        idempotency_key="idemp-tamper-01",
        correlation_id="corr-tamper-01"
    )

    export_dir = str(tmp_path / "forensics_tamper")
    records_file, manifest_file = export_evidence_bundle(
        conn=conn,
        output_dir=export_dir,
        hmac_secret=settings.EVIDENCE_HMAC_SECRET
    )

    # Tamper with the records file: modify the decision_reason of the second line
    with open(records_file, "r", encoding="utf-8") as f:
        lines = f.readlines()

    tampered_rec = json.loads(lines[1])
    tampered_rec["decision_reason"] = "TAMPERED_FRAUDULENT_DECISION"
    lines[1] = json.dumps(tampered_rec) + "\n"

    with open(records_file, "w", encoding="utf-8") as f:
        f.writelines(lines)

    # Verify that independent verifier flags the tampering
    is_valid, msg = verify_evidence_integrity(
        manifest_path=manifest_file,
        records_path=records_file,
        hmac_secret=settings.EVIDENCE_HMAC_SECRET
    )

    assert is_valid is False
    assert "RECORD TAMPERING DETECTED" in msg
    conn.close()


def test_tampered_manifest_detection(tmp_path):
    conn = get_db_connection()
    export_dir = str(tmp_path / "forensics_manifest_tamper")

    # Seed record
    conn.execute("""
        INSERT INTO audit_ledger 
        (event_id, timestamp, correlation_id, actor, action, decision_reason, payload_sha256, prev_hash, record_hash)
        VALUES ('EVT-M1', '2026-11-19T10:00:00Z', 'C1', 'act', 'ACT', 'RSN', 'hash', '0'*64, 'rechash');
    """)

    records_file, manifest_file = export_evidence_bundle(
        conn=conn,
        output_dir=export_dir,
        hmac_secret=settings.EVIDENCE_HMAC_SECRET
    )

    # Tamper with the manifest: alter record_count
    with open(manifest_file, "r", encoding="utf-8") as f:
        manifest_data = json.load(f)

    manifest_data["record_count"] = 999  # Tampered count

    with open(manifest_file, "w", encoding="utf-8") as f:
        json.dump(manifest_data, f)

    is_valid, msg = verify_evidence_integrity(
        manifest_path=manifest_file,
        records_path=records_file,
        hmac_secret=settings.EVIDENCE_HMAC_SECRET
    )

    assert is_valid is False
    assert "FORENSIC INTEGRITY COMPROMISED: Manifest signature mismatch" in msg
    conn.close()
