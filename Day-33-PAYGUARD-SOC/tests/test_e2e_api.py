"""End-to-End API Integration Tests covering all PAYGUARD SOC security specifications."""

import pytest
import uuid
import json
import socket
from datetime import datetime, timezone
from fastapi import HTTPException
from fastapi.responses import JSONResponse

from backend.api.app import (
    app,
    create_disbursement,
    get_disbursement,
    review_held_transaction,
    export_forensic_evidence,
    health_check
)
from backend.models.domain import (
    DisbursementRequest,
    AnalystReviewRequest
)
from backend.api.security import SecurityValidationError
from backend.engine.transaction_engine import IdempotencyConflictError
from backend.data.database import get_db_connection
from backend.data.seed import seed_database
from backend.config import settings
from backend.network_isolation import enable_network_isolation, disable_network_isolation
from evidence.verify_evidence import verify_evidence_integrity


class MockResponse:
    def __init__(self, status_code: int, data: dict):
        self.status_code = status_code
        self._data = data

    def json(self):
        return self._data


class TestApiClient:
    """Direct in-memory API test client ensuring fast, socket-free execution."""

    def post(self, url: str, json: dict = None, headers: dict = None) -> MockResponse:
        headers = headers or {}
        json_data = json or {}

        try:
            if url == "/api/v1/disbursements":
                req = DisbursementRequest(**json_data)
                res: JSONResponse = create_disbursement(
                    request=req,
                    authorization=headers.get("Authorization"),
                    x_idempotency_key=headers.get("X-Idempotency-Key"),
                    x_timestamp=headers.get("X-Timestamp"),
                    x_nonce=headers.get("X-Nonce"),
                    x_correlation_id=headers.get("X-Correlation-ID")
                )
                return MockResponse(res.status_code, self._parse_body(res))

            elif url.startswith("/api/v1/soc/transactions/") and url.endswith("/review"):
                tx_id = url.split("/")[5]
                review = AnalystReviewRequest(**json_data)
                res: JSONResponse = review_held_transaction(
                    transaction_id=tx_id,
                    review=review,
                    authorization=headers.get("Authorization"),
                    x_correlation_id=headers.get("X-Correlation-ID")
                )
                return MockResponse(res.status_code, self._parse_body(res))

            elif url == "/api/v1/soc/evidence/export":
                res = export_forensic_evidence(
                    authorization=headers.get("Authorization"),
                    x_correlation_id=headers.get("X-Correlation-ID")
                )
                return MockResponse(200, res)

            else:
                return MockResponse(404, {"error": "Not Found"})

        except SecurityValidationError as e:
            return MockResponse(e.status_code, {"error": e.reason_code, "message": e.message})
        except IdempotencyConflictError as e:
            return MockResponse(409, {"error": "IDEMPOTENCY_PAYLOAD_MISMATCH", "message": str(e)})
        except HTTPException as e:
            return MockResponse(e.status_code, {"error": e.detail})

    def get(self, url: str, headers: dict = None) -> MockResponse:
        headers = headers or {}
        try:
            if url == "/health":
                res = health_check()
                return MockResponse(200, res)

            elif url.startswith("/api/v1/disbursements/"):
                tx_id = url.split("/")[4]
                res = get_disbursement(
                    transaction_id=tx_id,
                    authorization=headers.get("Authorization")
                )
                return MockResponse(200, res.model_dump())

            else:
                return MockResponse(404, {"error": "Not Found"})

        except SecurityValidationError as e:
            return MockResponse(e.status_code, {"error": e.reason_code, "message": e.message})
        except HTTPException as e:
            return MockResponse(e.status_code, {"error": e.detail})

    def _parse_body(self, res: JSONResponse) -> dict:
        return json.loads(res.body.decode("utf-8"))


@pytest.fixture(autouse=True)
def setup_test_db(tmp_path):
    db_file = str(tmp_path / "test_e2e.db")
    settings.DATABASE_PATH = db_file
    seed_database(db_file)
    yield db_file


@pytest.fixture
def client():
    return TestApiClient()


def test_e2e_successful_disbursement_and_status_check(client):
    now_ts = datetime.now(timezone.utc).isoformat()
    headers = {
        "Authorization": "Bearer lab_tok_disburse_valid_999",
        "X-Idempotency-Key": f"idemp-e2e-{uuid.uuid4().hex}",
        "X-Timestamp": now_ts,
        "X-Nonce": f"nonce-e2e-{uuid.uuid4().hex}"
    }
    payload = {
        "loan_id": "LOAN-IND-1001",
        "borrower_id": "BORR-IND-901",
        "beneficiary_id": "BENEF-IND-01",
        "amount_inr": 12000.00,
        "currency": "INR",
        "purpose": "Agricultural Equipment Micro-Credit"
    }

    res = client.post("/api/v1/disbursements", json=payload, headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["state"] == "APPROVED"
    assert data["amount_inr"] == 12000.00
    assert data["currency"] == "INR"
    assert data["decision_reason"] == "APPROVED_OK"

    # Query transaction status via GET endpoint
    tx_id = data["transaction_id"]
    get_res = client.get(
        f"/api/v1/disbursements/{tx_id}",
        headers={"Authorization": "Bearer lab_tok_readonly_888"}
    )
    assert get_res.status_code == 200
    get_data = get_res.json()
    assert get_data["transaction_id"] == tx_id
    assert get_data["state"] == "APPROVED"


def test_e2e_duplicate_request_idempotency(client):
    now_ts = datetime.now(timezone.utc).isoformat()
    idemp_key = f"idemp-e2e-dup-{uuid.uuid4().hex}"
    headers = {
        "Authorization": "Bearer lab_tok_disburse_valid_999",
        "X-Idempotency-Key": idemp_key,
        "X-Timestamp": now_ts,
        "X-Nonce": "nonce-dup-1"
    }
    payload = {
        "loan_id": "LOAN-IND-1001",
        "borrower_id": "BORR-IND-901",
        "beneficiary_id": "BENEF-IND-01",
        "amount_inr": 8000.00
    }

    # First attempt
    res1 = client.post("/api/v1/disbursements", json=payload, headers=headers)
    assert res1.status_code == 200
    tx1 = res1.json()

    # Replay identical attempt (with new nonce)
    headers["X-Nonce"] = "nonce-dup-2"
    res2 = client.post("/api/v1/disbursements", json=payload, headers=headers)
    assert res2.status_code == 200
    tx2 = res2.json()

    assert tx1["transaction_id"] == tx2["transaction_id"]


def test_e2e_idempotency_payload_conflict(client):
    now_ts = datetime.now(timezone.utc).isoformat()
    idemp_key = f"idemp-conflict-{uuid.uuid4().hex}"
    headers = {
        "Authorization": "Bearer lab_tok_disburse_valid_999",
        "X-Idempotency-Key": idemp_key,
        "X-Timestamp": now_ts,
        "X-Nonce": "nonce-conf-1"
    }
    payload = {
        "loan_id": "LOAN-IND-1001",
        "borrower_id": "BORR-IND-901",
        "beneficiary_id": "BENEF-IND-01",
        "amount_inr": 1000.00
    }
    res1 = client.post("/api/v1/disbursements", json=payload, headers=headers)
    assert res1.status_code == 200

    # Tampered amount with same idempotency key
    headers["X-Nonce"] = "nonce-conf-2"
    payload["amount_inr"] = 9999.00
    res2 = client.post("/api/v1/disbursements", json=payload, headers=headers)
    assert res2.status_code == 409
    assert res2.json()["error"] == "IDEMPOTENCY_PAYLOAD_MISMATCH"


def test_e2e_expired_and_revoked_tokens(client):
    now_ts = datetime.now(timezone.utc).isoformat()
    payload = {
        "loan_id": "LOAN-IND-1001",
        "borrower_id": "BORR-IND-901",
        "beneficiary_id": "BENEF-IND-01",
        "amount_inr": 1000.00
    }

    # 1. Expired Token
    res_exp = client.post(
        "/api/v1/disbursements",
        json=payload,
        headers={
            "Authorization": "Bearer lab_tok_expired_555",
            "X-Idempotency-Key": "idemp-exp",
            "X-Timestamp": now_ts,
            "X-Nonce": "nonce-exp"
        }
    )
    assert res_exp.status_code == 401
    assert res_exp.json()["error"] == "SECURITY_TOKEN_EXPIRED"

    # 2. Revoked Token
    res_rev = client.post(
        "/api/v1/disbursements",
        json=payload,
        headers={
            "Authorization": "Bearer lab_tok_revoked_666",
            "X-Idempotency-Key": "idemp-rev",
            "X-Timestamp": now_ts,
            "X-Nonce": "nonce-rev"
        }
    )
    assert res_rev.status_code == 401
    assert res_rev.json()["error"] == "SECURITY_TOKEN_REVOKED"


def test_e2e_transaction_replay_attack(client):
    now_ts = datetime.now(timezone.utc).isoformat()
    nonce = f"nonce-replay-{uuid.uuid4().hex}"
    headers = {
        "Authorization": "Bearer lab_tok_disburse_valid_999",
        "X-Idempotency-Key": f"idemp-replay-{uuid.uuid4().hex}",
        "X-Timestamp": now_ts,
        "X-Nonce": nonce
    }
    payload = {
        "loan_id": "LOAN-IND-1001",
        "borrower_id": "BORR-IND-901",
        "beneficiary_id": "BENEF-IND-01",
        "amount_inr": 1000.00
    }

    # First request
    res1 = client.post("/api/v1/disbursements", json=payload, headers=headers)
    assert res1.status_code == 200

    # Replay with same Nonce (even with fresh idempotency key)
    headers["X-Idempotency-Key"] = f"idemp-fresh-{uuid.uuid4().hex}"
    res2 = client.post("/api/v1/disbursements", json=payload, headers=headers)
    assert res2.status_code == 401
    assert res2.json()["error"] == "SECURITY_REPLAY_DETECTED"


def test_e2e_invalid_loan_reference(client):
    now_ts = datetime.now(timezone.utc).isoformat()
    headers = {
        "Authorization": "Bearer lab_tok_disburse_valid_999",
        "X-Idempotency-Key": f"idemp-inv-{uuid.uuid4().hex}",
        "X-Timestamp": now_ts,
        "X-Nonce": f"nonce-inv-{uuid.uuid4().hex}"
    }
    # Non-existent loan
    payload = {
        "loan_id": "LOAN-NONEXISTENT",
        "borrower_id": "BORR-IND-901",
        "beneficiary_id": "BENEF-IND-01",
        "amount_inr": 1000.00
    }

    res = client.post("/api/v1/disbursements", json=payload, headers=headers)
    assert res.status_code == 400
    assert res.json()["state"] == "REJECTED"
    assert res.json()["decision_reason"] == "INVALID_OR_UNAPPROVED_LOAN_STATUS"


def test_e2e_micro_probe_held_and_analyst_review_workflow(client):
    # Step 1: Send micro-value transaction (₹30.00)
    now_ts = datetime.now(timezone.utc).isoformat()
    client.post(
        "/api/v1/disbursements",
        json={
            "loan_id": "LOAN-IND-1001",
            "borrower_id": "BORR-IND-901",
            "beneficiary_id": "BENEF-IND-01",
            "amount_inr": 30.00
        },
        headers={
            "Authorization": "Bearer lab_tok_disburse_valid_999",
            "X-Idempotency-Key": "idemp-p-1",
            "X-Timestamp": now_ts,
            "X-Nonce": "nonce-p-1"
        }
    )

    # Step 2: Send high-value transaction (₹8,000.00) -> transitions to HELD
    held_res = client.post(
        "/api/v1/disbursements",
        json={
            "loan_id": "LOAN-IND-1001",
            "borrower_id": "BORR-IND-901",
            "beneficiary_id": "BENEF-IND-01",
            "amount_inr": 8000.00
        },
        headers={
            "Authorization": "Bearer lab_tok_disburse_valid_999",
            "X-Idempotency-Key": "idemp-p-2",
            "X-Timestamp": now_ts,
            "X-Nonce": "nonce-p-2"
        }
    )
    assert held_res.status_code == 202
    held_data = held_res.json()
    assert held_data["state"] == "HELD"
    assert held_data["decision_reason"] == "FRAUD_PROBE_MICRO_HIGH_VALUE"
    tx_id = held_data["transaction_id"]

    # Step 3: SOC Analyst approves the transaction
    review_res = client.post(
        f"/api/v1/soc/transactions/{tx_id}/review",
        json={
            "action": "APPROVE",
            "analyst_id": "ANALYST-SOC-PRIYA",
            "decision_reason": "Out-of-band verification completed with borrower manager.",
            "analyst_notes": "All invoice documentation verified."
        },
        headers={"Authorization": "Bearer lab_tok_soc_analyst_777"}
    )
    assert review_res.status_code == 200
    rev_data = review_res.json()
    assert rev_data["state"] == "APPROVED"
    assert rev_data["decision_reason"] == "ANALYST_OVERRIDE_APPROVED"


def test_e2e_evidence_export_and_standalone_verification(client, tmp_path):
    # Perform transaction
    now_ts = datetime.now(timezone.utc).isoformat()
    client.post(
        "/api/v1/disbursements",
        json={
            "loan_id": "LOAN-IND-1001",
            "borrower_id": "BORR-IND-901",
            "beneficiary_id": "BENEF-IND-01",
            "amount_inr": 2500.00
        },
        headers={
            "Authorization": "Bearer lab_tok_disburse_valid_999",
            "X-Idempotency-Key": "idemp-e2e-exp-1",
            "X-Timestamp": now_ts,
            "X-Nonce": "nonce-e2e-exp-1"
        }
    )

    # Call evidence export endpoint
    exp_res = client.post(
        "/api/v1/soc/evidence/export",
        headers={"Authorization": "Bearer lab_tok_soc_analyst_777"}
    )
    assert exp_res.status_code == 200
    exp_data = exp_res.json()
    assert exp_data["status"] == "EXPORT_SUCCESS"

    # Verify exported bundle using independent verification utility
    is_valid, msg = verify_evidence_integrity(
        manifest_path=exp_data["manifest_file"],
        records_path=exp_data["records_file"],
        hmac_secret=settings.EVIDENCE_HMAC_SECRET
    )
    assert is_valid is True
    assert "FORENSIC VERIFICATION SUCCESSFUL" in msg


def test_e2e_network_isolation_verification():
    """Verify that socket-level isolation rejects all outbound connections to financial networks/internet."""
    enable_network_isolation()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        with pytest.raises(RuntimeError, match="NETWORK_ISOLATION_VIOLATION"):
            # Attempt connection to external IP (simulating financial network / public gateway)
            s.connect(("8.8.8.8", 443))
        s.close()
    finally:
        disable_network_isolation()
