"""PAYGUARD SOC - Core Transaction Engine & Concurrency Control.

Implements the strict 5-State Finite State Machine (RECEIVED -> VALIDATED -> HELD -> APPROVED / REJECTED),
idempotency tracking, and atomic loan balance debiting with BEGIN IMMEDIATE write serialization.
NO REAL-WORLD MONEY TRANSFERS: Approvals only produce internal synthetic ledger mutations.
"""

import uuid
import json
import logging
from datetime import datetime, timezone
import sqlite3
from typing import Optional, Tuple, Any

from backend.data.database import atomic_transaction
from backend.models.domain import (
    TransactionState,
    DisbursementRequest,
    DisbursementResponse,
    DecisionReason,
    AuditAction,
    AnalystReviewRequest
)
from backend.engine.audit_ledger import record_audit_event, compute_payload_sha256

logger = logging.getLogger("payguard.engine.transactions")


class IdempotencyConflictError(Exception):
    """Raised when an idempotency key is reused with a different request payload."""
    pass


class TransactionEngine:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def check_idempotency(self, idempotency_key: str, request_hash: str) -> Optional[Tuple[int, str]]:
        """Look up existing idempotency record.
        
        Returns:
            (status_code, response_body) if identical request was previously completed.
        Raises:
            IdempotencyConflictError if key was reused with differing payload.
        """
        row = self.conn.execute("""
            SELECT request_hash, response_code, response_body 
            FROM idempotency_records 
            WHERE idempotency_key = ?;
        """, (idempotency_key,)).fetchone()

        if not row:
            return None

        if row["request_hash"] != request_hash:
            raise IdempotencyConflictError(
                f"Idempotency key '{idempotency_key}' was previously used with a different request payload."
            )

        return (row["response_code"], row["response_body"])

    def save_idempotency(self, cur: sqlite3.Cursor, idempotency_key: str, client_id: str,
                         request_hash: str, status_code: int, response_body: str) -> None:
        """Store response for future idempotent replays."""
        cur.execute("""
            INSERT OR REPLACE INTO idempotency_records 
            (idempotency_key, client_id, request_hash, response_code, response_body, created_at)
            VALUES (?, ?, ?, ?, ?, ?);
        """, (
            idempotency_key, client_id, request_hash, status_code, response_body,
            datetime.now(timezone.utc).isoformat()
        ))

    def process_disbursement(
        self,
        request: DisbursementRequest,
        client_id: str,
        idempotency_key: str,
        correlation_id: str,
        fraud_evaluator: Optional[Any] = None
    ) -> Tuple[int, DisbursementResponse]:
        """Execute atomic disbursement pipeline through the 5-state lifecycle."""
        request_payload_dict = request.model_dump()
        req_hash = compute_payload_sha256(request_payload_dict)

        # 1. Idempotency Check (pre-transaction check for cached response)
        cached = self.check_idempotency(idempotency_key, req_hash)
        if cached:
            status_code, cached_body = cached
            cached_data = json.loads(cached_body)
            return status_code, DisbursementResponse(**cached_data)

        tx_id = f"TX-IND-{uuid.uuid4().hex[:12].upper()}"
        now_ts = datetime.now(timezone.utc).isoformat()

        # Atomic Execution with BEGIN IMMEDIATE
        with atomic_transaction(self.conn) as cur:
            # Re-check idempotency inside write lock to prevent race on the key itself
            cached_in_lock = cur.execute("""
                SELECT request_hash, response_code, response_body 
                FROM idempotency_records WHERE idempotency_key = ?;
            """, (idempotency_key,)).fetchone()

            if cached_in_lock:
                if cached_in_lock["request_hash"] != req_hash:
                    raise IdempotencyConflictError(
                        f"Idempotency key '{idempotency_key}' was previously used with a different request payload."
                    )
                cached_data = json.loads(cached_in_lock["response_body"])
                return cached_in_lock["response_code"], DisbursementResponse(**cached_data)

            # 2. State: RECEIVED
            cur.execute("""
                INSERT INTO transactions 
                (transaction_id, loan_id, borrower_id, beneficiary_id, amount_inr, 
                 currency, state, idempotency_key, decision_reason, correlation_id, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, (
                tx_id, request.loan_id, request.borrower_id, request.beneficiary_id,
                request.amount_inr, request.currency, TransactionState.RECEIVED.value,
                idempotency_key, "PENDING_VALIDATION", correlation_id, now_ts, now_ts
            ))

            record_audit_event(
                conn=self.conn,
                correlation_id=correlation_id,
                actor=client_id,
                action=AuditAction.TRANSACTION_RECEIVED,
                state_from=None,
                state_to=TransactionState.RECEIVED.value,
                decision_reason="Transaction ingested for validation",
                payload={"transaction_id": tx_id, "request": request_payload_dict}
            )

            # 3. State: VALIDATION
            loan_row = cur.execute("""
                SELECT loan_id, borrower_id, approved_limit_inr, disbursed_amount_inr, status 
                FROM loans WHERE loan_id = ?;
            """, (request.loan_id,)).fetchone()

            if not loan_row or loan_row["status"] != "APPROVED" or loan_row["borrower_id"] != request.borrower_id:
                reason = DecisionReason.INVALID_OR_UNAPPROVED_LOAN_STATUS.value
                return self._finalize_in_tx(
                    cur=cur,
                    tx_id=tx_id,
                    request=request,
                    client_id=client_id,
                    idempotency_key=idempotency_key,
                    req_hash=req_hash,
                    correlation_id=correlation_id,
                    final_state=TransactionState.REJECTED,
                    decision_reason=reason,
                    status_code=400
                )

            # Beneficiary Check
            benef_row = cur.execute("""
                SELECT beneficiary_id, borrower_id, status 
                FROM beneficiaries WHERE beneficiary_id = ?;
            """, (request.beneficiary_id,)).fetchone()

            if not benef_row or benef_row["borrower_id"] != request.borrower_id or benef_row["status"] != "ACTIVE":
                reason = DecisionReason.BENEFICIARY_NOT_REGISTERED.value
                return self._finalize_in_tx(
                    cur=cur,
                    tx_id=tx_id,
                    request=request,
                    client_id=client_id,
                    idempotency_key=idempotency_key,
                    req_hash=req_hash,
                    correlation_id=correlation_id,
                    final_state=TransactionState.REJECTED,
                    decision_reason=reason,
                    status_code=400
                )

            # Available Balance Check
            approved_limit = loan_row["approved_limit_inr"]
            disbursed_so_far = loan_row["disbursed_amount_inr"]
            available_balance = approved_limit - disbursed_so_far

            if request.amount_inr > available_balance:
                reason = DecisionReason.INSUFFICIENT_APPROVED_LOAN_BALANCE.value
                return self._finalize_in_tx(
                    cur=cur,
                    tx_id=tx_id,
                    request=request,
                    client_id=client_id,
                    idempotency_key=idempotency_key,
                    req_hash=req_hash,
                    correlation_id=correlation_id,
                    final_state=TransactionState.REJECTED,
                    decision_reason=reason,
                    status_code=422
                )

            # Validation Passed -> Transition to VALIDATED
            cur.execute("""
                UPDATE transactions 
                SET state = ?, decision_reason = ?, updated_at = ?
                WHERE transaction_id = ?;
            """, (TransactionState.VALIDATED.value, "VALIDATION_PASSED", datetime.now(timezone.utc).isoformat(), tx_id))

            record_audit_event(
                conn=self.conn,
                correlation_id=correlation_id,
                actor=client_id,
                action=AuditAction.TRANSACTION_VALIDATED,
                state_from=TransactionState.RECEIVED.value,
                state_to=TransactionState.VALIDATED.value,
                decision_reason="Schema, loan status, and balance limits verified",
                payload={"transaction_id": tx_id}
            )

            # 4. State: FRAUD EVALUATION
            if fraud_evaluator:
                fraud_result = fraud_evaluator.evaluate(
                    request=request,
                    conn=self.conn,
                    correlation_id=correlation_id
                )
                if fraud_result.is_flagged:
                    return self._finalize_in_tx(
                        cur=cur,
                        tx_id=tx_id,
                        request=request,
                        client_id=client_id,
                        idempotency_key=idempotency_key,
                        req_hash=req_hash,
                        correlation_id=correlation_id,
                        final_state=TransactionState.HELD,
                        decision_reason=fraud_result.reason_code,
                        status_code=202
                    )

            # 5. State: APPROVED (Atomic Concurrency Lock & Balance Deduction)
            cur.execute("""
                UPDATE loans 
                SET disbursed_amount_inr = disbursed_amount_inr + ?,
                    updated_at = ?
                WHERE loan_id = ? 
                  AND (disbursed_amount_inr + ?) <= approved_limit_inr;
            """, (
                request.amount_inr, datetime.now(timezone.utc).isoformat(),
                request.loan_id, request.amount_inr
            ))

            if cur.rowcount == 0:
                # Balance was exhausted concurrently
                return self._finalize_in_tx(
                    cur=cur,
                    tx_id=tx_id,
                    request=request,
                    client_id=client_id,
                    idempotency_key=idempotency_key,
                    req_hash=req_hash,
                    correlation_id=correlation_id,
                    final_state=TransactionState.REJECTED,
                    decision_reason=DecisionReason.INSUFFICIENT_APPROVED_LOAN_BALANCE.value,
                    status_code=422
                )

            return self._finalize_in_tx(
                cur=cur,
                tx_id=tx_id,
                request=request,
                client_id=client_id,
                idempotency_key=idempotency_key,
                req_hash=req_hash,
                correlation_id=correlation_id,
                final_state=TransactionState.APPROVED,
                decision_reason=DecisionReason.APPROVED_OK.value,
                status_code=200
            )

    def review_held_transaction(
        self,
        transaction_id: str,
        review: AnalystReviewRequest,
        correlation_id: str
    ) -> Tuple[int, DisbursementResponse]:
        """Perform authenticated SOC Analyst resolution for a HELD transaction."""
        with atomic_transaction(self.conn) as cur:
            tx_row = cur.execute("""
                SELECT transaction_id, loan_id, borrower_id, beneficiary_id, amount_inr, 
                       currency, state, idempotency_key, correlation_id, created_at
                FROM transactions WHERE transaction_id = ?;
            """, (transaction_id,)).fetchone()

            if not tx_row:
                raise ValueError(f"Transaction '{transaction_id}' not found.")

            if tx_row["state"] != TransactionState.HELD.value:
                raise ValueError(
                    f"Only transactions in HELD state can be reviewed. Current state: '{tx_row['state']}'"
                )

            now_ts = datetime.now(timezone.utc).isoformat()

            if review.action == "APPROVE":
                loan_id = tx_row["loan_id"]
                amount_inr = tx_row["amount_inr"]
                beneficiary_id = tx_row["beneficiary_id"]
                borrower_id = tx_row["borrower_id"]

                # RE-VALIDATION DEFENSE (Fix for TOCTOR Audit Finding):
                # Ensure the beneficiary was not revoked or altered while held in the queue
                benef_check = cur.execute("""
                    SELECT beneficiary_id, borrower_id, status 
                    FROM beneficiaries WHERE beneficiary_id = ?;
                """, (beneficiary_id,)).fetchone()

                if not benef_check or benef_check["status"] != "ACTIVE" or benef_check["borrower_id"] != borrower_id:
                    final_state = TransactionState.REJECTED
                    final_reason = DecisionReason.BENEFICIARY_NOT_REGISTERED.value
                    status_code = 400
                else:
                    cur.execute("""
                        UPDATE loans 
                        SET disbursed_amount_inr = disbursed_amount_inr + ?,
                            updated_at = ?
                        WHERE loan_id = ? 
                          AND (disbursed_amount_inr + ?) <= approved_limit_inr;
                    """, (amount_inr, now_ts, loan_id, amount_inr))

                    if cur.rowcount == 0:
                        final_state = TransactionState.REJECTED
                        final_reason = DecisionReason.INSUFFICIENT_APPROVED_LOAN_BALANCE.value
                        status_code = 422
                    else:
                        final_state = TransactionState.APPROVED
                        final_reason = DecisionReason.ANALYST_OVERRIDE_APPROVED.value
                        status_code = 200

            else:  # REJECT
                final_state = TransactionState.REJECTED
                final_reason = DecisionReason.ANALYST_OVERRIDE_REJECTED.value
                status_code = 200

            cur.execute("""
                UPDATE transactions 
                SET state = ?, decision_reason = ?, updated_at = ?
                WHERE transaction_id = ?;
            """, (final_state.value, final_reason, now_ts, transaction_id))

            record_audit_event(
                conn=self.conn,
                correlation_id=correlation_id,
                actor=review.analyst_id,
                action=AuditAction.ANALYST_HOLD_RESOLUTION,
                state_from=TransactionState.HELD.value,
                state_to=final_state.value,
                decision_reason=review.decision_reason,
                payload={
                    "transaction_id": transaction_id,
                    "analyst_id": review.analyst_id,
                    "action": review.action,
                    "analyst_notes": review.analyst_notes
                }
            )

            response = DisbursementResponse(
                transaction_id=tx_row["transaction_id"],
                state=final_state,
                loan_id=tx_row["loan_id"],
                borrower_id=tx_row["borrower_id"],
                beneficiary_id=tx_row["beneficiary_id"],
                amount_inr=tx_row["amount_inr"],
                currency=tx_row["currency"],
                decision_reason=final_reason,
                correlation_id=correlation_id,
                created_at=tx_row["created_at"]
            )

            self.save_idempotency(
                cur=cur,
                idempotency_key=tx_row["idempotency_key"],
                client_id=review.analyst_id,
                request_hash=compute_payload_sha256({"transaction_id": transaction_id}),
                status_code=status_code,
                response_body=response.model_dump_json()
            )

            return status_code, response

    def _finalize_in_tx(
        self,
        cur: sqlite3.Cursor,
        tx_id: str,
        request: DisbursementRequest,
        client_id: str,
        idempotency_key: str,
        req_hash: str,
        correlation_id: str,
        final_state: TransactionState,
        decision_reason: str,
        status_code: int
    ) -> Tuple[int, DisbursementResponse]:
        """Record final state transition, write audit log, and save idempotency inside the active transaction."""
        now_ts = datetime.now(timezone.utc).isoformat()

        cur.execute("""
            UPDATE transactions 
            SET state = ?, decision_reason = ?, updated_at = ?
            WHERE transaction_id = ?;
        """, (final_state.value, decision_reason, now_ts, tx_id))

        audit_action = {
            TransactionState.APPROVED: AuditAction.TRANSACTION_APPROVED,
            TransactionState.HELD: AuditAction.TRANSACTION_HELD,
            TransactionState.REJECTED: AuditAction.TRANSACTION_REJECTED
        }.get(final_state, AuditAction.TRANSACTION_REJECTED)

        record_audit_event(
            conn=self.conn,
            correlation_id=correlation_id,
            actor=client_id,
            action=audit_action,
            state_from=TransactionState.VALIDATED.value if final_state != TransactionState.REJECTED else TransactionState.RECEIVED.value,
            state_to=final_state.value,
            decision_reason=decision_reason,
            payload={"transaction_id": tx_id, "amount_inr": request.amount_inr}
        )

        response = DisbursementResponse(
            transaction_id=tx_id,
            state=final_state,
            loan_id=request.loan_id,
            borrower_id=request.borrower_id,
            beneficiary_id=request.beneficiary_id,
            amount_inr=request.amount_inr,
            currency=request.currency,
            decision_reason=decision_reason,
            correlation_id=correlation_id,
            created_at=now_ts
        )

        self.save_idempotency(
            cur=cur,
            idempotency_key=idempotency_key,
            client_id=client_id,
            request_hash=req_hash,
            status_code=status_code,
            response_body=response.model_dump_json()
        )

        return status_code, response
