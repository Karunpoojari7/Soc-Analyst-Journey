"""PAYGUARD SOC - API Security, Synthetic Token Validator, Replay Guard & Log Redactor.

Enforces:
1. Rejection of missing, invalid, expired, and revoked synthetic tokens.
2. Route-level authorization scopes.
3. Timestamp skew validation (±300s) and single-use Nonce replay prevention with TTL cleanup.
4. Active caller blocking and authentication abuse detection (DET-04).
5. Secret and token masking in all log handlers.
6. Zero reliance on IP allowlisting as primary control.
"""

import re
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, List
import sqlite3
from pydantic import BaseModel

from backend.config import settings
from backend.models.domain import DecisionReason, TokenInfo, AuditAction
from backend.engine.audit_ledger import record_audit_event


logger = logging.getLogger("payguard.api.security")


class SecurityValidationError(Exception):
    def __init__(self, status_code: int, reason_code: str, message: str):
        self.status_code = status_code
        self.reason_code = reason_code
        self.message = message
        super().__init__(message)


class SecretRedactorFilter(logging.Filter):
    """Logging filter that ensures complete tokens, secrets, and authorization credentials are never logged."""
    TOKEN_REGEX = re.compile(settings.SECRET_REDACTION_PATTERN)
    BEARER_REGEX = re.compile(r"Bearer\s+[a-zA-Z0-9_\-\.]+", re.IGNORECASE)
    SECRET_REGEX = re.compile(r"(secret|password|apikey|api_key|token)['\"]\s*:\s*['\"][^'\"]+['\"]", re.IGNORECASE)

    def redact_string(self, text: str) -> str:
        text = self.TOKEN_REGEX.sub("lab_tok_***[REDACTED]***", text)
        text = self.BEARER_REGEX.sub("Bearer ***[REDACTED]***", text)
        text = self.SECRET_REGEX.sub(r"\1: '***[REDACTED]***'", text)
        return text

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = self.redact_string(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {
                    k: self.redact_string(v) if isinstance(v, str) else v
                    for k, v in record.args.items()
                }
            elif isinstance(record.args, tuple):
                record.args = tuple(
                    self.redact_string(a) if isinstance(a, str) else a
                    for a in record.args
                )
        return True


def record_auth_attempt(conn: sqlite3.Connection, client_id: str, token_string: str,
                        status: str, failure_reason: Optional[str] = None) -> None:
    """Record authentication telemetry for brute force and abuse monitoring (DET-04)."""
    sanitized_tok = f"{token_string[:11]}...[MASKED]" if len(token_string) > 11 else "[MALFORMED]"
    conn.execute("""
        INSERT INTO auth_attempts (client_id, token_presented, status, failure_reason, timestamp)
        VALUES (?, ?, ?, ?, ?);
    """, (
        client_id, sanitized_tok, status, failure_reason, datetime.now(timezone.utc).isoformat()
    ))


def is_caller_blocked(conn: sqlite3.Connection, client_id: str) -> Optional[str]:
    """Check if the synthetic client identity is explicitly blocked in blocked_callers."""
    row = conn.execute("SELECT reason FROM blocked_callers WHERE client_id = ?;", (client_id,)).fetchone()
    return row["reason"] if row else None


def check_auth_abuse_trigger(conn: sqlite3.Connection, client_id: str) -> bool:
    """DET-04: Evaluate recent burst failures for the given client identity."""
    cutoff_ts = (
        datetime.now(timezone.utc) - timedelta(seconds=settings.AUTH_FAILURE_WINDOW_SECONDS)
    ).isoformat()

    fail_count = conn.execute("""
        SELECT COUNT(*) FROM auth_attempts 
        WHERE client_id = ? 
          AND status = 'FAILURE' 
          AND timestamp >= ?;
    """, (client_id, cutoff_ts)).fetchone()[0]

    return fail_count >= settings.AUTH_FAILURE_BURST_LIMIT


def verify_synthetic_token(
    token: Optional[str],
    conn: sqlite3.Connection,
    required_scope: Optional[str] = None,
    correlation_id: Optional[str] = "CORR-AUTH",
    client_id: Optional[str] = None
) -> TokenInfo:
    """Verify validity, expiration, revocation, abuse threshold, and scope of synthetic token."""
    caller_id = client_id or "anonymous"

    # Pre-check if caller identity is explicitly blocked
    if caller_id != "anonymous":
        block_reason = is_caller_blocked(conn, caller_id)
        if block_reason:
            record_auth_attempt(conn, caller_id, "[BLOCKED_CALLER]", "FAILURE", f"CALLER_BLOCKED: {block_reason}")
            raise SecurityValidationError(
                status_code=403,
                reason_code="SECURITY_CALLER_BLOCKED",
                message=f"Access Denied: Caller '{caller_id}' is administratively blocked by SOC. Reason: {block_reason}"
            )

    if not token or not token.strip():
        record_auth_attempt(conn, caller_id, "[EMPTY_TOKEN]", "FAILURE", "TOKEN_MISSING")
        raise SecurityValidationError(
            status_code=401,
            reason_code=DecisionReason.SECURITY_TOKEN_INVALID.value,
            message="Authorization token is missing."
        )

    # Clean bearer prefix if present
    token_str = token.strip()
    if token_str.startswith("Bearer "):
        token_str = token_str[7:].strip()

    row = conn.execute("""
        SELECT token_id, token_string, client_id, scopes, is_revoked, expires_at, created_at 
        FROM api_tokens WHERE token_string = ?;
    """, (token_str,)).fetchone()

    if not row:
        record_auth_attempt(conn, caller_id, token_str, "FAILURE", "TOKEN_NOT_FOUND")
        
        # Check DET-04 abuse threshold on invalid token bursts
        if check_auth_abuse_trigger(conn, caller_id):
            now_iso = datetime.now(timezone.utc).isoformat()
            conn.execute("""
                INSERT OR REPLACE INTO blocked_callers (client_id, reason, blocked_by, blocked_at)
                VALUES (?, 'DET-04: Automated burst authentication abuse', 'SYSTEM_DETECTION_ENGINE', ?);
            """, (caller_id, now_iso))
            record_audit_event(
                conn=conn,
                correlation_id=correlation_id or "CORR-AUTH-ABUSE",
                actor=caller_id,
                action=AuditAction.AUTH_FAILURE,
                decision_reason=DecisionReason.SECURITY_AUTH_ABUSE_DETECTED.value,
                payload={"client_id": caller_id, "error": "Consecutive authentication failures exceeded burst limit"}
            )
            raise SecurityValidationError(
                status_code=429,
                reason_code=DecisionReason.SECURITY_AUTH_ABUSE_DETECTED.value,
                message=f"DET-04 Triggered: Client '{caller_id}' blocked due to repeated authentication failures in 60s."
            )

        record_audit_event(
            conn=conn,
            correlation_id=correlation_id or "CORR-AUTH-FAIL",
            actor=caller_id,
            action=AuditAction.AUTH_FAILURE,
            decision_reason=DecisionReason.SECURITY_TOKEN_INVALID.value,
            payload={"error": "Token not found in synthetic registry"}
        )
        raise SecurityValidationError(
            status_code=401,
            reason_code=DecisionReason.SECURITY_TOKEN_INVALID.value,
            message="Invalid synthetic API token."
        )

    client_id = row["client_id"]
    scopes = [s.strip() for s in row["scopes"].split(",") if s.strip()]

    # 1. Check if caller is blocked by SOC Response Action
    block_reason = is_caller_blocked(conn, client_id)
    if block_reason:
        record_auth_attempt(conn, client_id, token_str, "FAILURE", f"CALLER_BLOCKED: {block_reason}")
        raise SecurityValidationError(
            status_code=403,
            reason_code="SECURITY_CALLER_BLOCKED",
            message=f"Access Denied: Caller '{client_id}' is administratively blocked by SOC. Reason: {block_reason}"
        )

    # 2. Check DET-04 Authentication Abuse Burst Threshold
    if check_auth_abuse_trigger(conn, client_id):
        record_audit_event(
            conn=conn,
            correlation_id=correlation_id or "CORR-AUTH-ABUSE",
            actor=client_id,
            action=AuditAction.AUTH_FAILURE,
            decision_reason=DecisionReason.SECURITY_AUTH_ABUSE_DETECTED.value,
            payload={"client_id": client_id, "error": "Consecutive authentication failures exceeded burst limit"}
        )
        raise SecurityValidationError(
            status_code=429,
            reason_code=DecisionReason.SECURITY_AUTH_ABUSE_DETECTED.value,
            message=f"DET-04 Triggered: Client '{client_id}' blocked due to repeated authentication failures in 60s."
        )

    # 3. Check Revocation
    if row["is_revoked"] == 1:
        record_auth_attempt(conn, client_id, token_str, "FAILURE", "TOKEN_REVOKED")
        record_audit_event(
            conn=conn,
            correlation_id=correlation_id or "CORR-AUTH-FAIL",
            actor=client_id,
            action=AuditAction.AUTH_FAILURE,
            decision_reason=DecisionReason.SECURITY_TOKEN_REVOKED.value,
            payload={"error": "Token is explicitly revoked"}
        )
        raise SecurityValidationError(
            status_code=401,
            reason_code=DecisionReason.SECURITY_TOKEN_REVOKED.value,
            message="Synthetic API token has been revoked."
        )

    # 4. Check Expiration
    expires_at_dt = datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00"))
    now_dt = datetime.now(timezone.utc)
    if now_dt > expires_at_dt:
        record_auth_attempt(conn, client_id, token_str, "FAILURE", "TOKEN_EXPIRED")
        record_audit_event(
            conn=conn,
            correlation_id=correlation_id or "CORR-AUTH-FAIL",
            actor=client_id,
            action=AuditAction.AUTH_FAILURE,
            decision_reason=DecisionReason.SECURITY_TOKEN_EXPIRED.value,
            payload={"error": "Token has expired"}
        )
        raise SecurityValidationError(
            status_code=401,
            reason_code=DecisionReason.SECURITY_TOKEN_EXPIRED.value,
            message="Synthetic API token has expired."
        )

    # 5. Check Scopes
    if required_scope and required_scope not in scopes:
        record_audit_event(
            conn=conn,
            correlation_id=correlation_id or "CORR-AUTH-FAIL",
            actor=client_id,
            action=AuditAction.AUTH_FAILURE,
            decision_reason=DecisionReason.SECURITY_INSUFFICIENT_SCOPE.value,
            payload={"required_scope": required_scope, "assigned_scopes": scopes}
        )
        raise SecurityValidationError(
            status_code=403,
            reason_code=DecisionReason.SECURITY_INSUFFICIENT_SCOPE.value,
            message=f"Insufficient authorization scope. Required: '{required_scope}'"
        )

    # Auth Success
    record_auth_attempt(conn, client_id, token_str, "SUCCESS")
    return TokenInfo(
        token_id=row["token_id"],
        client_id=row["client_id"],
        scopes=scopes,
        is_revoked=bool(row["is_revoked"]),
        expires_at=row["expires_at"],
        created_at=row["created_at"]
    )


def verify_replay_and_timestamp(
    conn: sqlite3.Connection,
    client_id: str,
    timestamp_str: Optional[str],
    nonce: Optional[str]
) -> None:
    """Validate request timestamp window, enforce single-use Nonce, and purge expired nonces."""
    if not timestamp_str or not nonce:
        raise SecurityValidationError(
            status_code=400,
            reason_code=DecisionReason.SECURITY_REPLAY_DETECTED.value,
            message="Missing required security headers: 'X-Timestamp' and 'X-Nonce'."
        )

    try:
        req_dt = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
    except ValueError:
        raise SecurityValidationError(
            status_code=400,
            reason_code=DecisionReason.SECURITY_TIMESTAMP_SKEWED.value,
            message="Malformed 'X-Timestamp' header. Must be ISO 8601 UTC."
        )

    now_dt = datetime.now(timezone.utc)
    skew = abs((now_dt - req_dt).total_seconds())

    if skew > settings.TIMESTAMP_SKEW_TOLERANCE_SECONDS:
        raise SecurityValidationError(
            status_code=400,
            reason_code=DecisionReason.SECURITY_TIMESTAMP_SKEWED.value,
            message=(
                f"Timestamp skew of {skew:.1f}s exceeds allowable tolerance "
                f"({settings.TIMESTAMP_SKEW_TOLERANCE_SECONDS}s)."
            )
        )

    # Clean up nonces older than the allowable tolerance window (prevents unbounded table growth)
    purge_cutoff = (now_dt - timedelta(seconds=settings.NONCE_CACHE_TTL_SECONDS)).isoformat()
    conn.execute("DELETE FROM used_nonces WHERE created_at < ?;", (purge_cutoff,))

    # Check Nonce Collision
    row = conn.execute("""
        SELECT nonce FROM used_nonces WHERE nonce = ? AND client_id = ?;
    """, (nonce, client_id)).fetchone()

    if row:
        raise SecurityValidationError(
            status_code=401,
            reason_code=DecisionReason.SECURITY_REPLAY_DETECTED.value,
            message=f"Replay attack detected: Nonce '{nonce}' has already been consumed."
        )

    # Register Nonce
    conn.execute("""
        INSERT INTO used_nonces (nonce, client_id, created_at)
        VALUES (?, ?, ?);
    """, (nonce, client_id, now_dt.isoformat()))
