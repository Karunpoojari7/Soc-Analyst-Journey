"""PAYGUARD SOC - Deterministic Fraud Detection Engine.

ARCHITECTURAL SEPARATION NOTICE:
This module contains purely deterministic, rule-based detection logic.
It is explicitly separated from any statistical or Machine Learning models.
All thresholds are loaded from configurable synthetic lab values denominated in INR (₹).
"""

from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import Optional, List
import sqlite3
import logging

from backend.config import settings
from backend.models.domain import (
    DisbursementRequest,
    DecisionReason,
    AuditAction,
    TransactionState
)
from backend.engine.audit_ledger import record_audit_event

logger = logging.getLogger("payguard.engine.fraud")


@dataclass
class FraudEvaluationResult:
    is_flagged: bool
    rule_code: Optional[str] = None
    reason_code: Optional[str] = None
    severity: str = "LOW"
    description: Optional[str] = None


class DeterministicFraudEngine:
    """Evaluates transactions against deterministic SOC fraud rules prior to approval."""

    def __init__(self, config=None):
        self.config = config or settings

    def evaluate(
        self,
        request: DisbursementRequest,
        conn: sqlite3.Connection,
        correlation_id: str
    ) -> FraudEvaluationResult:
        """Run all deterministic fraud rules sequentially."""
        
        # Rule DET-01: Micro-Value to High-Value Probe Detection
        det01_result = self._check_micro_probe_rule(request, conn)
        if det01_result.is_flagged:
            self._log_fraud_alert(conn, correlation_id, request, det01_result)
            return det01_result

        # Rule DET-02: New Beneficiary & Velocity Spike
        det02_result = self._check_unseen_beneficiary_velocity(request, conn)
        if det02_result.is_flagged:
            self._log_fraud_alert(conn, correlation_id, request, det02_result)
            return det02_result

        return FraudEvaluationResult(is_flagged=False)

    def _check_micro_probe_rule(
        self,
        request: DisbursementRequest,
        conn: sqlite3.Connection
    ) -> FraudEvaluationResult:
        """DET-01: Flag high-value transfers preceded by micro-value probe within the probe window."""
        # Only evaluate if current request is High-Value
        if request.amount_inr < self.config.HIGH_VALUE_MIN_INR:
            return FraudEvaluationResult(is_flagged=False)

        cutoff_ts = (
            datetime.now(timezone.utc) - timedelta(seconds=self.config.MICRO_PROBE_WINDOW_SECONDS)
        ).isoformat()

        # Check for prior micro transactions to the same borrower/beneficiary in the window
        row = conn.execute("""
            SELECT transaction_id, amount_inr, created_at, state 
            FROM transactions 
            WHERE borrower_id = ? 
              AND beneficiary_id = ?
              AND amount_inr <= ?
              AND created_at >= ?
              AND state IN ('APPROVED', 'HELD', 'VALIDATED')
            ORDER BY created_at DESC LIMIT 1;
        """, (
            request.borrower_id,
            request.beneficiary_id,
            self.config.MICRO_VALUE_MAX_INR,
            cutoff_ts
        )).fetchone()

        if row:
            desc = (
                f"DET-01 Violation: Incoming high-value transfer of ₹{request.amount_inr:,.2f} "
                f"was preceded by micro-probe transaction '{row['transaction_id']}' (₹{row['amount_inr']:,.2f}) "
                f"within {self.config.MICRO_PROBE_WINDOW_SECONDS}s."
            )
            logger.warning(desc)
            return FraudEvaluationResult(
                is_flagged=True,
                rule_code="DET-01",
                reason_code=DecisionReason.FRAUD_PROBE_MICRO_HIGH_VALUE.value,
                severity="HIGH",
                description=desc
            )

        return FraudEvaluationResult(is_flagged=False)

    def _check_unseen_beneficiary_velocity(
        self,
        request: DisbursementRequest,
        conn: sqlite3.Connection
    ) -> FraudEvaluationResult:
        """DET-02: Flag rapid transaction velocity to an unseen or freshly linked beneficiary."""
        # 1. Check if borrower has any prior APPROVED transactions to this beneficiary
        prior_approved = conn.execute("""
            SELECT COUNT(*) FROM transactions 
            WHERE borrower_id = ? 
              AND beneficiary_id = ? 
              AND state = 'APPROVED';
        """, (request.borrower_id, request.beneficiary_id)).fetchone()[0]

        is_unseen = (prior_approved == 0)

        # 2. Check borrower transaction velocity in recent window
        velocity_cutoff = (
            datetime.now(timezone.utc) - timedelta(seconds=self.config.VELOCITY_WINDOW_SECONDS)
        ).isoformat()

        recent_tx_count = conn.execute("""
            SELECT COUNT(*) FROM transactions 
            WHERE borrower_id = ? 
              AND created_at >= ?;
        """, (request.borrower_id, velocity_cutoff)).fetchone()[0]

        # Flag if unseen beneficiary AND velocity exceeds configured lab limit
        if is_unseen and recent_tx_count >= self.config.VELOCITY_MAX_TX_COUNT:
            desc = (
                f"DET-02 Violation: Borrower '{request.borrower_id}' has high velocity "
                f"({recent_tx_count} transactions in {self.config.VELOCITY_WINDOW_SECONDS}s) "
                f"targeting unverified beneficiary '{request.beneficiary_id}'."
            )
            logger.warning(desc)
            return FraudEvaluationResult(
                is_flagged=True,
                rule_code="DET-02",
                reason_code=DecisionReason.FRAUD_UNSEEN_BENEFICIARY_VELOCITY.value,
                severity="HIGH",
                description=desc
            )

        return FraudEvaluationResult(is_flagged=False)

    def check_auth_abuse(self, client_id: str, conn: sqlite3.Connection) -> bool:
        """DET-04: Check if client ID has triggered repeated authentication failures."""
        cutoff_ts = (
            datetime.now(timezone.utc) - timedelta(seconds=self.config.AUTH_FAILURE_WINDOW_SECONDS)
        ).isoformat()

        fail_count = conn.execute("""
            SELECT COUNT(*) FROM auth_attempts 
            WHERE client_id = ? 
              AND status = 'FAILURE' 
              AND timestamp >= ?;
        """, (client_id, cutoff_ts)).fetchone()[0]

        return fail_count >= self.config.AUTH_FAILURE_BURST_LIMIT

    def _log_fraud_alert(
        self,
        conn: sqlite3.Connection,
        correlation_id: str,
        request: DisbursementRequest,
        result: FraudEvaluationResult
    ) -> None:
        """Emit structured SOC fraud alert to the append-only audit ledger."""
        record_audit_event(
            conn=conn,
            correlation_id=correlation_id,
            actor="SYSTEM_FRAUD_ENGINE",
            action=AuditAction.TRANSACTION_HELD,
            state_from=TransactionState.VALIDATED.value,
            state_to=TransactionState.HELD.value,
            decision_reason=result.reason_code or "FRAUD_SUSPECTED",
            payload={
                "rule_code": result.rule_code,
                "severity": result.severity,
                "description": result.description,
                "borrower_id": request.borrower_id,
                "beneficiary_id": request.beneficiary_id,
                "amount_inr": request.amount_inr
            }
        )
