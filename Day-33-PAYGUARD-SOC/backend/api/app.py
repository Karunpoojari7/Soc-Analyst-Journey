"""PAYGUARD SOC - Core FastAPI Application & Security Gateway.

Exposes REST endpoints protected by synthetic token validation, nonce replay protection,
and endpoint-specific authorization scopes. Provides active defense telemetry, incident
management, and evidence vault capabilities for the SOC Analyst team.
"""

import uuid
import logging
from contextlib import asynccontextmanager
from typing import Optional, Any, List
import os
from fastapi import FastAPI, Header, HTTPException, Depends, Request, Response
from fastapi.responses import JSONResponse, HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware

from backend.config import settings
from backend.models.domain import (
    DisbursementRequest,
    DisbursementResponse,
    AnalystReviewRequest,
    TokenInfo,
    DecisionReason,
    IncidentResponse,
    IncidentUpdateRequest,
    CallerBlockRequest,
    TokenRevokeRequest,
    SimulatorScenarioRequest,
    AuditAction
)
from backend.data.database import get_db_connection, init_database
from backend.data.seed import seed_database
from backend.engine.transaction_engine import TransactionEngine, IdempotencyConflictError
from backend.engine.fraud_detector import DeterministicFraudEngine
from backend.engine.response_engine import ResponseEngine
from backend.engine.audit_ledger import record_audit_event
from backend.engine.evidence_exporter import export_evidence_bundle
from backend.api.security import (
    verify_synthetic_token,
    verify_replay_and_timestamp,
    SecurityValidationError,
    SecretRedactorFilter
)
from backend.network_isolation import (
    enable_network_isolation,
    disable_network_isolation,
    is_network_isolation_active
)
from backend.simulator.attack_scenarios import run_scenario


# Attach Secret Redactor to root logger
root_logger = logging.getLogger()
redactor_filter = SecretRedactorFilter()
for handler in root_logger.handlers:
    handler.addFilter(redactor_filter)

logger = logging.getLogger("payguard.api.app")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Enforce network isolation in synthetic lab
    if settings.ENFORCE_NETWORK_ISOLATION:
        enable_network_isolation()
        logger.info("PAYGUARD Network Isolation strictly enforced on startup.")
    
    # Initialize DB if needed
    init_database()
    try:
        yield
    finally:
        disable_network_isolation()


app = FastAPI(
    title=settings.APP_NAME,
    description="PAYGUARD SOC FinTech Micro-Disbursement & Security Operations Center Lab (Purely Synthetic / INR)",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Exception handler for security validation errors
@app.exception_handler(SecurityValidationError)
async def security_exception_handler(request: Request, exc: SecurityValidationError):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.reason_code,
            "message": exc.message,
            "correlation_id": request.headers.get("X-Correlation-ID", "UNKNOWN")
        }
    )


@app.exception_handler(IdempotencyConflictError)
async def idempotency_conflict_handler(request: Request, exc: IdempotencyConflictError):
    return JSONResponse(
        status_code=409,
        content={
            "error": DecisionReason.IDEMPOTENCY_PAYLOAD_MISMATCH.value,
            "message": str(exc),
            "correlation_id": request.headers.get("X-Correlation-ID", "UNKNOWN")
        }
    )


def _unwrap_header(val: Any) -> Optional[str]:
    """Helper to unwrap FastAPI Header parameter defaults if invoked directly in tests."""
    if val is None or hasattr(val, "default"):
        return None
    return str(val)


# ============================================================================
# SYSTEM HEALTH & LOAN REGISTRY ENDPOINTS
# ============================================================================

FRONTEND_INDEX = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "frontend", "index.html"))


@app.get("/", response_class=HTMLResponse)
@app.get("/dashboard", response_class=HTMLResponse)
def get_dashboard():
    """Serve the interactive PAYGUARD SOC Dark Web Dashboard."""
    if os.path.exists(FRONTEND_INDEX):
        return FileResponse(FRONTEND_INDEX)
    return HTMLResponse("<h2>PAYGUARD SOC API is running. (Frontend index.html not found)</h2>")


@app.get("/health")
def health_check():
    """System health check and network isolation status."""
    return {
        "status": "HEALTHY",
        "app": settings.APP_NAME,
        "currency": settings.SYNTHETIC_CURRENCY,
        "network_isolation_active": is_network_isolation_active()
    }


@app.get("/api/v1/loans")
def get_loans(authorization: Optional[str] = Header(None)):
    """List approved synthetic loans and available balances in INR."""
    auth_token = _unwrap_header(authorization)
    conn = get_db_connection()
    try:
        verify_synthetic_token(token=auth_token, conn=conn, required_scope="disbursement:read")
        rows = conn.execute("""
            SELECT loan_id, borrower_id, approved_limit_inr, disbursed_amount_inr, 
                   (approved_limit_inr - disbursed_amount_inr) as available_balance_inr,
                   status, created_at, updated_at
            FROM loans ORDER BY loan_id ASC;
        """).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


# ============================================================================
# DISBURSEMENT & CORE TRANSACTION ENDPOINTS
# ============================================================================

@app.post("/api/v1/disbursements", response_model=DisbursementResponse)
def create_disbursement(
    request: DisbursementRequest,
    authorization: Optional[str] = Header(None),
    x_idempotency_key: Optional[str] = Header(None, alias="X-Idempotency-Key"),
    x_timestamp: Optional[str] = Header(None, alias="X-Timestamp"),
    x_nonce: Optional[str] = Header(None, alias="X-Nonce"),
    x_correlation_id: Optional[str] = Header(None, alias="X-Correlation-ID")
):
    """Initiate an atomic loan disbursement in INR."""
    auth_token = _unwrap_header(authorization)
    idemp_key = _unwrap_header(x_idempotency_key)
    ts = _unwrap_header(x_timestamp)
    nonce = _unwrap_header(x_nonce)
    raw_corr = _unwrap_header(x_correlation_id)
    correlation_id = raw_corr or f"CORR-{uuid.uuid4().hex[:10].upper()}"

    if not idemp_key:
        raise HTTPException(status_code=400, detail="Missing required 'X-Idempotency-Key' header.")

    conn = get_db_connection()
    try:
        # 1. API Security: Token Authentication & Scope Check
        token_info = verify_synthetic_token(
            token=auth_token,
            conn=conn,
            required_scope="disbursement:create",
            correlation_id=correlation_id
        )

        # 2. API Security: Nonce Replay & Timestamp Skew Check
        verify_replay_and_timestamp(
            conn=conn,
            client_id=token_info.client_id,
            timestamp_str=ts,
            nonce=nonce
        )

        # 3. Transaction Core & Deterministic Fraud Evaluation
        fraud_detector = DeterministicFraudEngine()
        engine = TransactionEngine(conn)

        status_code, response = engine.process_disbursement(
            request=request,
            client_id=token_info.client_id,
            idempotency_key=idemp_key,
            correlation_id=correlation_id,
            fraud_evaluator=fraud_detector
        )

        # Automatically escalate to SOC incident if held
        if response.state == "HELD":
            ResponseEngine(conn).create_incident(
                rule_code="DET-FRAUD",
                severity="HIGH",
                title=f"Transaction Held: {response.decision_reason}",
                description=f"Transaction {response.transaction_id} (₹{response.amount_inr:,.2f}) held due to {response.decision_reason}.",
                affected_entity=response.borrower_id,
                transaction_id=response.transaction_id,
                recommended_action="SOC Analyst review required before funds can be approved.",
                correlation_id=correlation_id
            )

        return JSONResponse(status_code=status_code, content=response.model_dump())
    finally:
        conn.close()


@app.get("/api/v1/disbursements", response_model=List[DisbursementResponse])
def list_disbursements(
    limit: int = 50,
    authorization: Optional[str] = Header(None)
):
    """List recent disbursements. Standard clients only see their own; SOC analysts see all."""
    auth_token = _unwrap_header(authorization)
    conn = get_db_connection()
    try:
        token_info = verify_synthetic_token(token=auth_token, conn=conn, required_scope="disbursement:read")
        is_elevated = any(s in token_info.scopes for s in ["soc:review", "audit:export", "admin"])
        
        if is_elevated:
            rows = conn.execute("""
                SELECT transaction_id, loan_id, borrower_id, beneficiary_id, amount_inr, 
                       currency, state, decision_reason, correlation_id, created_at 
                FROM transactions ORDER BY created_at DESC LIMIT ?;
            """, (limit,)).fetchall()
        else:
            rows = conn.execute("""
                SELECT transaction_id, loan_id, borrower_id, beneficiary_id, amount_inr, 
                       currency, state, decision_reason, correlation_id, created_at 
                FROM transactions 
                WHERE borrower_id = ? OR idempotency_key IN (
                    SELECT idempotency_key FROM idempotency_records WHERE client_id = ?
                )
                ORDER BY created_at DESC LIMIT ?;
            """, (token_info.client_id, token_info.client_id, limit)).fetchall()
            
        return [DisbursementResponse(**dict(r)) for r in rows]
    finally:
        conn.close()


@app.get("/api/v1/disbursements/{transaction_id}", response_model=DisbursementResponse)
def get_disbursement(
    transaction_id: str,
    authorization: Optional[str] = Header(None)
):
    """Retrieve transaction state and audit reason with strict IDOR protection."""
    auth_token = _unwrap_header(authorization)
    conn = get_db_connection()
    try:
        token_info = verify_synthetic_token(
            token=auth_token,
            conn=conn,
            required_scope="disbursement:read"
        )

        row = conn.execute("""
            SELECT transaction_id, loan_id, borrower_id, beneficiary_id, amount_inr, 
                   currency, state, decision_reason, correlation_id, created_at 
            FROM transactions WHERE transaction_id = ?;
        """, (transaction_id,)).fetchone()

        if not row:
            raise HTTPException(status_code=404, detail="Transaction not found.")

        # IDOR Protection: Elevated analysts and auditors can read all transactions.
        # Standard clients can only read transactions where borrower_id == client_id OR
        # the transaction was initiated by this client (via idempotency_records).
        is_elevated = (
            "auditor" in token_info.client_id.lower() or
            any(s in token_info.scopes for s in ["soc:review", "audit:export", "admin"])
        )
        if not is_elevated:
            is_owner = (token_info.client_id == row["borrower_id"])
            if not is_owner:
                idemp_row = conn.execute(
                    "SELECT client_id FROM idempotency_records WHERE idempotency_key = (SELECT idempotency_key FROM transactions WHERE transaction_id = ?);",
                    (transaction_id,)
                ).fetchone()
                if not idemp_row or idemp_row["client_id"] != token_info.client_id:
                    record_audit_event(
                        conn=conn,
                        correlation_id=f"CORR-IDOR-{uuid.uuid4().hex[:8].upper()}",
                        actor=token_info.client_id,
                        action="IDOR_ACCESS_BLOCKED",
                        decision_reason="Unauthorized access attempt to transaction belonging to another client/borrower",
                        payload={"attempted_transaction_id": transaction_id, "caller": token_info.client_id}
                    )
                    raise HTTPException(status_code=403, detail="Forbidden: IDOR protection prevented access to another client's transaction.")

        return DisbursementResponse(**dict(row))
    finally:
        conn.close()


# ============================================================================
# SOC OPERATIONS & ANALYST ENDPOINTS
# ============================================================================

@app.get("/api/v1/soc/overview")
def get_soc_overview(authorization: Optional[str] = Header(None)):
    """Executive summary metrics and defensive status for the SOC dashboard."""
    auth_token = _unwrap_header(authorization)
    conn = get_db_connection()
    try:
        verify_synthetic_token(token=auth_token, conn=conn, required_scope="soc:review")

        states = {"APPROVED": 0, "HELD": 0, "REJECTED": 0, "VALIDATED": 0, "RECEIVED": 0}
        rows = conn.execute("SELECT state, COUNT(*) as cnt, SUM(amount_inr) as total_amt FROM transactions GROUP BY state;").fetchall()
        total_tx = 0
        total_disbursed = 0.0
        total_held = 0.0
        for r in rows:
            st = r["state"]
            cnt = r["cnt"]
            amt = r["total_amt"] or 0.0
            states[st] = cnt
            total_tx += cnt
            if st == "APPROVED":
                total_disbursed += amt
            elif st == "HELD":
                total_held += amt

        incidents_open = conn.execute("SELECT COUNT(*) as cnt FROM soc_incidents WHERE status IN ('OPEN', 'INVESTIGATING');").fetchone()["cnt"]
        blocked_callers = conn.execute("SELECT COUNT(*) as cnt FROM blocked_callers;").fetchone()["cnt"]
        auth_fails = conn.execute("SELECT COUNT(*) as cnt FROM auth_attempts WHERE status = 'FAILURE';").fetchone()["cnt"]

        return {
            "app_name": settings.APP_NAME,
            "currency": settings.SYNTHETIC_CURRENCY,
            "currency_symbol": settings.SYNTHETIC_CURRENCY_SYMBOL,
            "network_isolation_active": is_network_isolation_active(),
            "total_transactions": total_tx,
            "approved_count": states["APPROVED"],
            "held_count": states["HELD"],
            "rejected_count": states["REJECTED"],
            "total_disbursed_inr": total_disbursed,
            "total_held_inr": total_held,
            "active_alerts_count": states["HELD"] + states["REJECTED"],
            "open_incidents_count": incidents_open,
            "blocked_callers_count": blocked_callers,
            "auth_failures_count": auth_fails
        }
    finally:
        conn.close()


@app.get("/api/v1/soc/transactions")
def list_soc_transactions(
    limit: int = 100,
    state: Optional[str] = None,
    authorization: Optional[str] = Header(None)
):
    """Retrieve transactions with risk indicators and decision reasoning for SOC investigation."""
    auth_token = _unwrap_header(authorization)
    conn = get_db_connection()
    try:
        verify_synthetic_token(token=auth_token, conn=conn, required_scope="soc:review")
        if state:
            rows = conn.execute("""
                SELECT transaction_id, loan_id, borrower_id, beneficiary_id, amount_inr, 
                       currency, state, decision_reason, correlation_id, created_at, updated_at
                FROM transactions WHERE state = ? ORDER BY created_at DESC LIMIT ?;
            """, (state.upper(), limit)).fetchall()
        else:
            rows = conn.execute("""
                SELECT transaction_id, loan_id, borrower_id, beneficiary_id, amount_inr, 
                       currency, state, decision_reason, correlation_id, created_at, updated_at
                FROM transactions ORDER BY created_at DESC LIMIT ?;
            """, (limit,)).fetchall()

        items = []
        for r in rows:
            d = dict(r)
            if d["state"] in ("HELD", "REJECTED"):
                d["risk_level"] = "HIGH"
            elif "PROBE" in d["decision_reason"] or "VELOCITY" in d["decision_reason"]:
                d["risk_level"] = "SUSPICIOUS"
            else:
                d["risk_level"] = "LOW"
            items.append(d)
        return items
    finally:
        conn.close()


@app.get("/api/v1/soc/alerts")
def list_soc_alerts(authorization: Optional[str] = Header(None)):
    """List fraud and security alerts generated by DET-01, DET-02, DET-03, DET-04."""
    auth_token = _unwrap_header(authorization)
    conn = get_db_connection()
    try:
        verify_synthetic_token(token=auth_token, conn=conn, required_scope="soc:review")
        alerts = []
        # Get from HELD/REJECTED transactions
        tx_rows = conn.execute("""
            SELECT transaction_id, loan_id, borrower_id, amount_inr, state, decision_reason, correlation_id, created_at
            FROM transactions
            WHERE state IN ('HELD', 'REJECTED')
            ORDER BY created_at DESC LIMIT 50;
        """).fetchall()

        for tx in tx_rows:
            reason = tx["decision_reason"]
            rule_code = "DET-GENERIC"
            severity = "MEDIUM"
            title = f"Transaction {tx['state']}: {reason}"
            if reason == "FRAUD_PROBE_MICRO_HIGH_VALUE":
                rule_code = "DET-01"
                severity = "HIGH"
                title = "DET-01: Micro-Value Probe Followed by High-Value Transfer"
            elif reason == "FRAUD_UNSEEN_BENEFICIARY_VELOCITY":
                rule_code = "DET-02"
                severity = "HIGH"
                title = "DET-02: Unseen Beneficiary Velocity Spike"
            elif reason in ("INVALID_OR_UNAPPROVED_LOAN_STATUS", "INSUFFICIENT_APPROVED_LOAN_BALANCE"):
                rule_code = "DET-03"
                severity = "CRITICAL"
                title = f"DET-03: Loan Integrity Violation ({reason})"

            alerts.append({
                "alert_id": f"ALT-{tx['transaction_id'][:12]}",
                "rule_code": rule_code,
                "severity": severity,
                "title": title,
                "decision_reason": reason,
                "transaction_id": tx["transaction_id"],
                "borrower_id": tx["borrower_id"],
                "amount_inr": tx["amount_inr"],
                "timestamp": tx["created_at"]
            })

        # Get from auth telemetry (DET-04)
        auth_abuse_rows = conn.execute("""
            SELECT client_id, timestamp, failure_reason
            FROM auth_attempts
            WHERE status = 'FAILURE'
            ORDER BY timestamp DESC LIMIT 20;
        """).fetchall()

        for ab in auth_abuse_rows:
            alerts.append({
                "alert_id": f"ALT-AUTH-{uuid.uuid4().hex[:6].upper()}",
                "rule_code": "DET-04",
                "severity": "HIGH",
                "title": f"DET-04: API Authentication Failure ({ab['failure_reason']})",
                "decision_reason": ab["failure_reason"] or "AUTH_FAILURE",
                "transaction_id": None,
                "borrower_id": ab["client_id"],
                "amount_inr": 0.0,
                "timestamp": ab["timestamp"]
            })

        return alerts
    finally:
        conn.close()


@app.get("/api/v1/soc/auth-telemetry")
def get_auth_telemetry(authorization: Optional[str] = Header(None)):
    """Auth attempt telemetry, failed authentications, replay attempts, and blocked callers."""
    auth_token = _unwrap_header(authorization)
    conn = get_db_connection()
    try:
        verify_synthetic_token(token=auth_token, conn=conn, required_scope="soc:review")
        total = conn.execute("SELECT COUNT(*) as c FROM auth_attempts;").fetchone()["c"]
        successes = conn.execute("SELECT COUNT(*) as c FROM auth_attempts WHERE status = 'SUCCESS';").fetchone()["c"]
        failures = conn.execute("SELECT COUNT(*) as c FROM auth_attempts WHERE status = 'FAILURE';").fetchone()["c"]

        recent = conn.execute("""
            SELECT id, client_id, status, failure_reason, timestamp
            FROM auth_attempts ORDER BY timestamp DESC LIMIT 50;
        """).fetchall()

        blocked = conn.execute("SELECT client_id, reason, blocked_by, blocked_at FROM blocked_callers;").fetchall()

        return {
            "total_attempts": total,
            "successful_attempts": successes,
            "failed_attempts": failures,
            "recent_logs": [dict(r) for r in recent],
            "blocked_callers": [dict(b) for b in blocked]
        }
    finally:
        conn.close()


@app.get("/api/v1/soc/incidents", response_model=List[IncidentResponse])
def list_incidents(authorization: Optional[str] = Header(None)):
    """List all escalated SOC incidents."""
    auth_token = _unwrap_header(authorization)
    conn = get_db_connection()
    try:
        verify_synthetic_token(token=auth_token, conn=conn, required_scope="soc:review")
        rows = conn.execute("SELECT * FROM soc_incidents ORDER BY created_at DESC;").fetchall()
        return [IncidentResponse(**dict(r)) for r in rows]
    finally:
        conn.close()


@app.get("/api/v1/soc/incidents/{incident_id}")
def get_incident_details(incident_id: str, authorization: Optional[str] = Header(None)):
    """Retrieve incident details, associated transaction, and audit timeline."""
    auth_token = _unwrap_header(authorization)
    conn = get_db_connection()
    try:
        verify_synthetic_token(token=auth_token, conn=conn, required_scope="soc:review")
        row = conn.execute("SELECT * FROM soc_incidents WHERE incident_id = ?;", (incident_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Incident not found.")
        incident_data = dict(row)

        tx = None
        if incident_data.get("transaction_id"):
            tx_row = conn.execute("SELECT * FROM transactions WHERE transaction_id = ?;", (incident_data["transaction_id"],)).fetchone()
            if tx_row:
                tx = dict(tx_row)

        timeline = conn.execute("""
            SELECT event_id, timestamp, correlation_id, actor, action, state_from, state_to, decision_reason
            FROM audit_ledger
            ORDER BY id DESC LIMIT 50;
        """).fetchall()

        return {
            "incident": incident_data,
            "transaction": tx,
            "audit_timeline": [dict(t) for t in timeline]
        }
    finally:
        conn.close()


@app.post("/api/v1/soc/incidents/{incident_id}/respond")
def respond_to_incident(
    incident_id: str,
    update: IncidentUpdateRequest,
    authorization: Optional[str] = Header(None)
):
    """Execute defensive action and update incident containment status."""
    auth_token = _unwrap_header(authorization)
    conn = get_db_connection()
    try:
        verify_synthetic_token(token=auth_token, conn=conn, required_scope="soc:review")
        resp_engine = ResponseEngine(conn)

        cur_row = conn.execute("SELECT * FROM soc_incidents WHERE incident_id = ?;", (incident_id,)).fetchone()
        if not cur_row:
            raise HTTPException(status_code=404, detail="Incident not found.")

        if update.action == "BLOCK_SYNTHETIC_CALLER":
            resp_engine.block_caller(
                client_id=cur_row["affected_entity"],
                reason=f"Blocked via incident {incident_id}: {update.notes}",
                actor=update.analyst_id
            )
        elif update.action == "REVOKE_TOKEN":
            resp_engine.revoke_token(
                token_identifier=cur_row["affected_entity"],
                reason=f"Revoked via incident {incident_id}: {update.notes}",
                actor=update.analyst_id
            )

        updated = resp_engine.update_incident(
            incident_id=incident_id,
            status=update.status,
            analyst_id=update.analyst_id,
            notes=update.notes
        )
        return updated
    finally:
        conn.close()


@app.post("/api/v1/soc/callers/{client_id}/block")
def block_synthetic_caller(
    client_id: str,
    req: CallerBlockRequest,
    authorization: Optional[str] = Header(None)
):
    """Administratively block a synthetic caller."""
    auth_token = _unwrap_header(authorization)
    conn = get_db_connection()
    try:
        verify_synthetic_token(token=auth_token, conn=conn, required_scope="soc:review")
        ResponseEngine(conn).block_caller(client_id=client_id, reason=req.reason, actor=req.analyst_id)
        return {"status": "SUCCESS", "client_id": client_id, "action": "BLOCKED"}
    finally:
        conn.close()


@app.post("/api/v1/soc/callers/{client_id}/unblock")
def unblock_synthetic_caller(
    client_id: str,
    authorization: Optional[str] = Header(None)
):
    """Administratively unblock a synthetic caller."""
    auth_token = _unwrap_header(authorization)
    conn = get_db_connection()
    try:
        verify_synthetic_token(token=auth_token, conn=conn, required_scope="soc:review")
        ResponseEngine(conn).unblock_caller(client_id=client_id, actor="SOC_ANALYST")
        return {"status": "SUCCESS", "client_id": client_id, "action": "UNBLOCKED"}
    finally:
        conn.close()


@app.post("/api/v1/soc/tokens/{token_id}/revoke")
def revoke_api_token(
    token_id: str,
    req: TokenRevokeRequest,
    authorization: Optional[str] = Header(None)
):
    """Administratively revoke a synthetic API token."""
    auth_token = _unwrap_header(authorization)
    conn = get_db_connection()
    try:
        verify_synthetic_token(token=auth_token, conn=conn, required_scope="soc:review")
        ResponseEngine(conn).revoke_token(token_identifier=token_id, reason=req.reason, actor=req.analyst_id)
        return {"status": "SUCCESS", "token_identifier": token_id, "action": "REVOKED"}
    finally:
        conn.close()


@app.post("/api/v1/soc/transactions/{transaction_id}/review", response_model=DisbursementResponse)
def review_held_transaction(
    transaction_id: str,
    review: AnalystReviewRequest,
    authorization: Optional[str] = Header(None),
    x_correlation_id: Optional[str] = Header(None, alias="X-Correlation-ID")
):
    """Authenticated SOC Analyst resolution for HELD transactions."""
    auth_token = _unwrap_header(authorization)
    raw_corr = _unwrap_header(x_correlation_id)
    correlation_id = raw_corr or f"CORR-SOC-{uuid.uuid4().hex[:10].upper()}"

    conn = get_db_connection()
    try:
        token_info = verify_synthetic_token(
            token=auth_token,
            conn=conn,
            required_scope="soc:review",
            correlation_id=correlation_id
        )

        engine = TransactionEngine(conn)
        try:
            status_code, response = engine.review_held_transaction(
                transaction_id=transaction_id,
                review=review,
                correlation_id=correlation_id
            )
            return JSONResponse(status_code=status_code, content=response.model_dump())
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
    finally:
        conn.close()


@app.post("/api/v1/soc/evidence/export")
def export_forensic_evidence(
    authorization: Optional[str] = Header(None),
    x_correlation_id: Optional[str] = Header(None, alias="X-Correlation-ID")
):
    """Export complete tamper-evident audit ledger and cryptographic manifest."""
    auth_token = _unwrap_header(authorization)
    raw_corr = _unwrap_header(x_correlation_id)
    correlation_id = raw_corr or f"CORR-EXP-{uuid.uuid4().hex[:10].upper()}"

    conn = get_db_connection()
    try:
        verify_synthetic_token(
            token=auth_token,
            conn=conn,
            required_scope="audit:export",
            correlation_id=correlation_id
        )

        records_file, manifest_file = export_evidence_bundle(conn=conn)
        return {
            "status": "EXPORT_SUCCESS",
            "records_file": records_file,
            "manifest_file": manifest_file,
            "correlation_id": correlation_id
        }
    finally:
        conn.close()


# ============================================================================
# ATTACK SIMULATOR API INTEGRATION (FOR SOC DASHBOARD & AUTOMATION)
# ============================================================================

@app.post("/api/v1/simulator/run-scenario")
def api_run_simulation_scenario(
    req: SimulatorScenarioRequest,
    authorization: Optional[str] = Header(None)
):
    """Trigger a synthetic cyberattack simulation scenario from the dashboard."""
    auth_token = _unwrap_header(authorization)
    conn = get_db_connection()
    try:
        # SOC review permission is required to trigger lab simulations
        verify_synthetic_token(token=auth_token, conn=conn, required_scope="soc:review")
        result = run_scenario(req.scenario)
        return result
    finally:
        conn.close()
