"""PAYGUARD SOC - Unit & Integration Tests for SOC Operations Endpoints.

Tests:
1. System health check and loans listing in INR.
2. Executive SOC overview metrics.
3. SOC transactions listing with risk grading.
4. Alerts generation from DET rules.
5. Auth telemetry, failed logins, and caller blocking/unblocking.
6. Incident lifecycle, containment, and response actions.
7. Token revocation via SOC operations.
8. IDOR protection enforcement on disbursement access.
9. Simulation scenario API execution.
"""

import uuid
from datetime import datetime, timezone
import pytest

from backend.config import settings
from backend.data.database import init_database, get_db_connection
from backend.data.seed import seed_database
from backend.models.domain import TransactionState, DecisionReason
from backend.api.app import (
    health_check,
    get_loans,
    get_soc_overview,
    list_soc_transactions,
    list_soc_alerts,
    get_auth_telemetry,
    list_incidents,
    get_incident_details,
    respond_to_incident,
    block_synthetic_caller,
    unblock_synthetic_caller,
    revoke_api_token,
    create_disbursement,
    get_disbursement,
    api_run_simulation_scenario
)
from backend.models.domain import (
    DisbursementRequest,
    IncidentUpdateRequest,
    CallerBlockRequest,
    TokenRevokeRequest,
    SimulatorScenarioRequest
)
from fastapi import HTTPException


@pytest.fixture
def clean_db(tmp_path, monkeypatch):
    test_db = str(tmp_path / "test_soc_ops.db")
    monkeypatch.setattr(settings, "DATABASE_PATH", test_db)
    init_database(test_db)
    seed_database(test_db)
    return test_db


def test_health_and_loans_endpoint(clean_db):
    h = health_check()
    assert h["status"] == "HEALTHY"
    assert h["currency"] == "INR"

    loans = get_loans(authorization="Bearer lab_tok_readonly_888")
    assert len(loans) >= 4
    for l in loans:
        assert l["approved_limit_inr"] >= 0
        assert l["available_balance_inr"] == l["approved_limit_inr"] - l["disbursed_amount_inr"]


def test_soc_overview_and_transactions_metrics(clean_db):
    # Retrieve overview with SOC token
    overview = get_soc_overview(authorization="Bearer lab_tok_soc_analyst_777")
    assert overview["currency"] == "INR"
    assert "total_transactions" in overview
    assert "approved_count" in overview

    # Make a disbursement to check transaction metrics update
    now_ts = datetime.now(timezone.utc).isoformat()
    req = DisbursementRequest(
        loan_id="LOAN-IND-1001",
        borrower_id="BORR-IND-901",
        beneficiary_id="BENEF-IND-01",
        amount_inr=5000.00,
        currency="INR"
    )
    create_disbursement(
        request=req,
        authorization="Bearer lab_tok_disburse_valid_999",
        x_idempotency_key=f"idemp-soc-overview-{uuid.uuid4().hex[:8]}",
        x_timestamp=now_ts,
        x_nonce=f"nonce-soc-{uuid.uuid4().hex[:8]}"
    )

    txs = list_soc_transactions(limit=10, authorization="Bearer lab_tok_soc_analyst_777")
    assert len(txs) >= 1
    assert txs[0]["risk_level"] in ("LOW", "HIGH", "SUSPICIOUS")


def test_soc_alerts_and_auth_telemetry(clean_db):
    # Fetch alerts
    alerts = list_soc_alerts(authorization="Bearer lab_tok_soc_analyst_777")
    assert isinstance(alerts, list)

    # Fetch auth telemetry
    telemetry = get_auth_telemetry(authorization="Bearer lab_tok_soc_analyst_777")
    assert "total_attempts" in telemetry
    assert "recent_logs" in telemetry
    assert "blocked_callers" in telemetry


def test_soc_incident_lifecycle_and_containment(clean_db):
    # 1. Trigger Scenario 1 to generate an incident
    sim_res = api_run_simulation_scenario(
        req=SimulatorScenarioRequest(scenario=1),
        authorization="Bearer lab_tok_soc_analyst_777"
    )
    assert sim_res["detected"] is True
    inc_id = sim_res["incident_id"]
    assert inc_id is not None

    # 2. View incident details
    inc_details = get_incident_details(incident_id=inc_id, authorization="Bearer lab_tok_soc_analyst_777")
    assert inc_details["incident"]["incident_id"] == inc_id
    assert inc_details["incident"]["status"] == "OPEN"

    # 3. Contain and resolve incident
    update_req = IncidentUpdateRequest(
        status="CONTAINED",
        analyst_id="ANALYST-VIKRAM-01",
        notes="Held transaction inspected. Contacted borrower, flagged suspicious micro-probe sequence.",
        action="BLOCK_SYNTHETIC_CALLER"
    )
    updated = respond_to_incident(
        incident_id=inc_id,
        update=update_req,
        authorization="Bearer lab_tok_soc_analyst_777"
    )
    assert updated["status"] == "CONTAINED"
    assert updated["assigned_analyst"] == "ANALYST-VIKRAM-01"


def test_caller_block_and_unblock(clean_db):
    target_client = "client_malicious_probe"
    
    # Block caller
    block_req = CallerBlockRequest(
        client_id=target_client,
        reason="Suspicious high-rate API probing detected",
        analyst_id="ANALYST-01"
    )
    res_block = block_synthetic_caller(
        client_id=target_client,
        req=block_req,
        authorization="Bearer lab_tok_soc_analyst_777"
    )
    assert res_block["action"] == "BLOCKED"

    # Check caller is in blocked list
    telemetry = get_auth_telemetry(authorization="Bearer lab_tok_soc_analyst_777")
    blocked_ids = [b["client_id"] for b in telemetry["blocked_callers"]]
    assert target_client in blocked_ids

    # Unblock caller
    res_unblock = unblock_synthetic_caller(
        client_id=target_client,
        authorization="Bearer lab_tok_soc_analyst_777"
    )
    assert res_unblock["action"] == "UNBLOCKED"


def test_token_revocation_endpoint(clean_db):
    target_tok = "TOK-01"
    revoke_req = TokenRevokeRequest(
        token_identifier=target_tok,
        reason="Partner API credential suspected leaked",
        analyst_id="ANALYST-01"
    )
    res = revoke_api_token(
        token_id=target_tok,
        req=revoke_req,
        authorization="Bearer lab_tok_soc_analyst_777"
    )
    assert res["action"] == "REVOKED"


def test_idor_protection_enforcement(clean_db):
    now_ts = datetime.now(timezone.utc).isoformat()
    
    # 1. Client creates disbursement for BORR-IND-901
    req = DisbursementRequest(
        loan_id="LOAN-IND-1001",
        borrower_id="BORR-IND-901",
        beneficiary_id="BENEF-IND-01",
        amount_inr=3000.00,
        currency="INR"
    )
    raw_res = create_disbursement(
        request=req,
        authorization="Bearer lab_tok_disburse_valid_999",
        x_idempotency_key=f"idemp-idor-test-{uuid.uuid4().hex[:8]}",
        x_timestamp=now_ts,
        x_nonce=f"nonce-idor-{uuid.uuid4().hex[:8]}"
    )
    tx_id = raw_res.body.decode()
    import json
    tx_id = json.loads(tx_id)["transaction_id"]

    # 2. SOC Analyst can read any transaction
    analyst_res = get_disbursement(transaction_id=tx_id, authorization="Bearer lab_tok_soc_analyst_777")
    assert analyst_res.transaction_id == tx_id

    # 3. Creator client can read transaction
    owner_res = get_disbursement(transaction_id=tx_id, authorization="Bearer lab_tok_disburse_valid_999")
    assert owner_res.transaction_id == tx_id

    # 4. Create an unauthorized client token in db with only disbursement:read
    conn = get_db_connection()
    try:
        conn.execute("""
            INSERT INTO api_tokens (token_id, token_string, client_id, scopes, is_revoked, expires_at, created_at)
            VALUES ('TOK-SNOOPER', 'lab_tok_snooper_111', 'attacker_client_snooper', 'disbursement:read', 0, '2035-01-01T00:00:00Z', ?);
        """, (now_ts,))
        conn.commit()
    finally:
        conn.close()

    # 5. Attacker tries to read BORR-IND-901's transaction -> Expect 403 Forbidden
    with pytest.raises(HTTPException) as excinfo:
        get_disbursement(transaction_id=tx_id, authorization="Bearer lab_tok_snooper_111")
    assert excinfo.value.status_code == 403
    assert "IDOR" in excinfo.value.detail
