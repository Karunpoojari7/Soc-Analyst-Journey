"""PAYGUARD SOC - Append-Only Audit Ledger & Cryptographic Hash Chainer.

Maintains an immutable, append-only operational audit trail of all transaction decisions,
state transitions, security events, and analyst reviews.
"""

import hashlib
import json
import uuid
from datetime import datetime, timezone
import sqlite3
from typing import Optional, Dict, Any
from backend.data.database import get_db_connection, atomic_transaction
from backend.models.domain import AuditRecord, AuditAction


GENESIS_HASH = "0" * 64


def compute_payload_sha256(payload: Any) -> str:
    """Compute deterministic SHA-256 hash of an arbitrary payload."""
    if payload is None:
        raw_str = ""
    elif isinstance(payload, str):
        raw_str = payload
    else:
        raw_str = json.dumps(payload, sort_keys=True)
    return hashlib.sha256(raw_str.encode("utf-8")).hexdigest()


def compute_record_hash(prev_hash: str, event_id: str, timestamp: str,
                        action: str, decision_reason: str, payload_sha256: str) -> str:
    """Compute cryptographic hash linking this audit entry to the previous record."""
    preimage = f"{prev_hash}|{event_id}|{timestamp}|{action}|{decision_reason}|{payload_sha256}"
    return hashlib.sha256(preimage.encode("utf-8")).hexdigest()


def record_audit_event(
    conn: sqlite3.Connection,
    correlation_id: str,
    actor: str,
    action: AuditAction | str,
    decision_reason: str,
    state_from: Optional[str] = None,
    state_to: Optional[str] = None,
    payload: Optional[Dict[str, Any]] = None,
    timestamp: Optional[str] = None,
) -> AuditRecord:
    """Append a cryptographically chained audit record to the audit_ledger."""
    event_id = f"EVT-IND-{uuid.uuid4().hex[:12].upper()}"
    ts = timestamp or datetime.now(timezone.utc).isoformat()
    action_str = action.value if isinstance(action, AuditAction) else str(action)
    payload_hash = compute_payload_sha256(payload)

    # Fetch previous hash
    last_row = conn.execute("""
        SELECT record_hash FROM audit_ledger ORDER BY id DESC LIMIT 1;
    """).fetchone()
    prev_hash = last_row["record_hash"] if last_row else GENESIS_HASH

    record_hash = compute_record_hash(
        prev_hash=prev_hash,
        event_id=event_id,
        timestamp=ts,
        action=action_str,
        decision_reason=decision_reason,
        payload_sha256=payload_hash
    )

    conn.execute("""
        INSERT INTO audit_ledger 
        (event_id, timestamp, correlation_id, actor, action, state_from, state_to, 
         decision_reason, payload_sha256, prev_hash, record_hash)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
    """, (
        event_id, ts, correlation_id, actor, action_str,
        state_from, state_to, decision_reason, payload_hash, prev_hash, record_hash
    ))

    return AuditRecord(
        event_id=event_id,
        timestamp=ts,
        correlation_id=correlation_id,
        actor=actor,
        action=action_str,
        state_from=state_from,
        state_to=state_to,
        decision_reason=decision_reason,
        payload_sha256=payload_hash,
        prev_hash=prev_hash,
        record_hash=record_hash
    )
