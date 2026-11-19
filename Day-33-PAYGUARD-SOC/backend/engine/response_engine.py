"""PAYGUARD SOC - Response Engine & Defensive Action Coordinator.

Implements server-side, explainable, and auditable defensive actions:
- ALLOW
- HOLD
- REJECT
- REVOKE TOKEN
- BLOCK SYNTHETIC CALLER
- ESCALATE FOR INVESTIGATION
"""

import uuid
import logging
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, Dict, Any, List
import sqlite3

from backend.data.database import atomic_transaction
from backend.engine.audit_ledger import record_audit_event
from backend.models.domain import AuditAction

logger = logging.getLogger("payguard.engine.response")


class ResponseAction(str, Enum):
    ALLOW = "ALLOW"
    HOLD = "HOLD"
    REJECT = "REJECT"
    REVOKE_TOKEN = "REVOKE_TOKEN"
    BLOCK_SYNTHETIC_CALLER = "BLOCK_SYNTHETIC_CALLER"
    ESCALATE_INVESTIGATION = "ESCALATE_INVESTIGATION"


class IncidentStatus(str, Enum):
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    CONTAINED = "CONTAINED"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class ResponseEngine:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def block_caller(self, client_id: str, reason: str, actor: str, correlation_id: str = None) -> bool:
        """Administratively block a synthetic caller from accessing financial APIs."""
        corr_id = correlation_id or f"CORR-BLOCK-{uuid.uuid4().hex[:8].upper()}"
        now_ts = datetime.now(timezone.utc).isoformat()

        with atomic_transaction(self.conn) as cur:
            cur.execute("""
                INSERT OR REPLACE INTO blocked_callers (client_id, reason, blocked_by, blocked_at)
                VALUES (?, ?, ?, ?);
            """, (client_id, reason, actor, now_ts))

            record_audit_event(
                conn=self.conn,
                correlation_id=corr_id,
                actor=actor,
                action="CALLER_BLOCKED",
                decision_reason=reason,
                payload={"client_id": client_id, "action": ResponseAction.BLOCK_SYNTHETIC_CALLER.value}
            )

        logger.warning(f"DEFENSIVE ACTION EXECUTED: Caller '{client_id}' has been BLOCKED. Reason: {reason}")
        return True

    def unblock_caller(self, client_id: str, actor: str, correlation_id: str = None) -> bool:
        """Unblock a previously blocked synthetic caller."""
        corr_id = correlation_id or f"CORR-UNBLOCK-{uuid.uuid4().hex[:8].upper()}"
        with atomic_transaction(self.conn) as cur:
            cur.execute("DELETE FROM blocked_callers WHERE client_id = ?;", (client_id,))
            record_audit_event(
                conn=self.conn,
                correlation_id=corr_id,
                actor=actor,
                action="CALLER_UNBLOCKED",
                decision_reason="Administrative unblock",
                payload={"client_id": client_id}
            )
        return True

    def revoke_token(self, token_identifier: str, reason: str, actor: str, correlation_id: str = None) -> bool:
        """Revoke a synthetic API token immediately."""
        corr_id = correlation_id or f"CORR-REVOKE-{uuid.uuid4().hex[:8].upper()}"

        with atomic_transaction(self.conn) as cur:
            cur.execute("""
                UPDATE api_tokens 
                SET is_revoked = 1 
                WHERE token_id = ? OR token_string = ?;
            """, (token_identifier, token_identifier))

            if cur.rowcount == 0:
                raise ValueError(f"Token '{token_identifier}' not found in registry.")

            record_audit_event(
                conn=self.conn,
                correlation_id=corr_id,
                actor=actor,
                action=AuditAction.TOKEN_REVOCATION,
                decision_reason=reason,
                payload={"token_identifier": token_identifier, "action": ResponseAction.REVOKE_TOKEN.value}
            )

        logger.warning(f"DEFENSIVE ACTION EXECUTED: Token '{token_identifier}' has been REVOKED.")
        return True

    def create_incident(
        self,
        rule_code: str,
        severity: str,
        title: str,
        description: str,
        affected_entity: str,
        transaction_id: Optional[str] = None,
        recommended_action: str = "ESCALATE_INVESTIGATION",
        correlation_id: str = None
    ) -> str:
        """Create and escalate a SOC security incident."""
        incident_id = f"INC-{uuid.uuid4().hex[:8].upper()}"
        now_ts = datetime.now(timezone.utc).isoformat()
        corr_id = correlation_id or f"CORR-INC-{incident_id}"

        with atomic_transaction(self.conn) as cur:
            cur.execute("""
                INSERT INTO soc_incidents 
                (incident_id, rule_code, severity, title, description, affected_entity, 
                 transaction_id, status, recommended_action, analyst_notes, assigned_analyst, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, (
                incident_id, rule_code, severity, title, description, affected_entity,
                transaction_id, IncidentStatus.OPEN.value, recommended_action, "", None, now_ts, now_ts
            ))

            record_audit_event(
                conn=self.conn,
                correlation_id=corr_id,
                actor="SYSTEM_RESPONSE_ENGINE",
                action="INCIDENT_CREATED",
                decision_reason=f"Rule {rule_code} triggered incident escalation",
                payload={
                    "incident_id": incident_id,
                    "rule_code": rule_code,
                    "severity": severity,
                    "affected_entity": affected_entity
                }
            )

        return incident_id

    def update_incident(
        self,
        incident_id: str,
        status: IncidentStatus | str,
        analyst_id: str,
        notes: str,
        correlation_id: str = None
    ) -> Dict[str, Any]:
        """Update incident investigation notes and containment status."""
        status_str = status.value if isinstance(status, IncidentStatus) else str(status)
        now_ts = datetime.now(timezone.utc).isoformat()
        corr_id = correlation_id or f"CORR-INC-UPDATE-{uuid.uuid4().hex[:8].upper()}"

        with atomic_transaction(self.conn) as cur:
            cur.execute("""
                UPDATE soc_incidents 
                SET status = ?, analyst_notes = ?, assigned_analyst = ?, updated_at = ?
                WHERE incident_id = ?;
            """, (status_str, notes, analyst_id, now_ts, incident_id))

            if cur.rowcount == 0:
                raise ValueError(f"Incident '{incident_id}' not found.")

            record_audit_event(
                conn=self.conn,
                correlation_id=corr_id,
                actor=analyst_id,
                action="INCIDENT_UPDATED",
                decision_reason=f"Status changed to {status_str}",
                payload={"incident_id": incident_id, "status": status_str, "notes": notes}
            )

        row = self.conn.execute("SELECT * FROM soc_incidents WHERE incident_id = ?;", (incident_id,)).fetchone()
        return dict(row)
