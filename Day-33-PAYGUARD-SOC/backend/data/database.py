"""PAYGUARD SOC - Database Initialization, Concurrency Management & Schema.

CONCURRENCY & TRANSACTION SERIALIZATION:
SQLite in WAL (Write-Ahead Logging) mode allows multiple concurrent readers,
but enforces a single-writer constraint. Default deferred transactions (BEGIN DEFERRED)
can result in lock-upgrade deadlocks when concurrent threads attempt to write.
To enforce strict write serialization and eliminate deadlocks:
1. All state mutations and balance checks execute inside 'BEGIN IMMEDIATE' transactions.
2. PRAGMA busy_timeout is set to 5000ms to allow concurrent write queues to serialize cleanly.
3. PRAGMA journal_mode is configured to WAL.

APPLICATION-LEVEL PROTECTION vs. FORENSIC IMMUTABILITY:
SQLite triggers (trg_audit_no_update, trg_audit_no_delete) provide APPLICATION-LEVEL
protection against accidental or unauthorized updates/deletions originating from ORMs,
APIs, or SQL clients. However, they do not guarantee absolute forensic immutability against
raw disk-level byte manipulation. Absolute forensic defensibility is achieved via the
independent SHA-256 cryptographic hash chain and signed export manifest.
"""

import os
import sqlite3
import logging
from contextlib import contextmanager
from typing import Generator
import uuid
from backend.config import settings

logger = logging.getLogger("payguard.data.database")


def get_db_connection(db_path: str = None) -> sqlite3.Connection:
    """Create a configured SQLite connection with write serialization and busy timeout."""
    target_path = db_path or settings.DATABASE_PATH
    if target_path == ":memory:":
        conn = sqlite3.connect(":memory:", isolation_level=None)
    elif target_path.startswith("file:"):
        conn = sqlite3.connect(
            target_path,
            uri=True,
            timeout=settings.SQLITE_BUSY_TIMEOUT_MS / 1000.0,
            isolation_level=None
        )
    else:
        abs_p = os.path.abspath(target_path)
        if abs_p.startswith(("\\\\", "//")):
            # Running across UNC / network drive (such as \\wsl.localhost)
            # where Windows SMB byte-range locking hangs or raises 'database is locked'.
            # URI mode with nolock=1 allows robust execution.
            uri = f"file:{target_path}?nolock=1"
            conn = sqlite3.connect(
                uri,
                uri=True,
                timeout=settings.SQLITE_BUSY_TIMEOUT_MS / 1000.0,
                isolation_level=None
            )
        else:
            conn = sqlite3.connect(
                target_path,
                timeout=settings.SQLITE_BUSY_TIMEOUT_MS / 1000.0,
                isolation_level=None
            )
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode = WAL;")
    except sqlite3.OperationalError:
        pass
    conn.execute(f"PRAGMA busy_timeout = {settings.SQLITE_BUSY_TIMEOUT_MS};")
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


@contextmanager
def atomic_transaction(conn: sqlite3.Connection) -> Generator[sqlite3.Cursor, None, None]:
    """Execute code within an atomic SQLite transaction using BEGIN IMMEDIATE.
    
    BEGIN IMMEDIATE reserves the write lock immediately, preventing concurrent
    writers from causing deadlocks while allowing WAL readers to proceed.
    Supports nesting via SQLite SAVEPOINTs if already within an active transaction.
    """
    cursor = conn.cursor()
    if conn.in_transaction:
        sp_name = f"sp_{uuid.uuid4().hex[:8]}"
        cursor.execute(f"SAVEPOINT {sp_name};")
        try:
            yield cursor
            cursor.execute(f"RELEASE SAVEPOINT {sp_name};")
        except Exception:
            cursor.execute(f"ROLLBACK TO SAVEPOINT {sp_name};")
            raise
    else:
        cursor.execute("BEGIN IMMEDIATE;")
        try:
            yield cursor
            cursor.execute("COMMIT;")
        except Exception:
            if conn.in_transaction:
                cursor.execute("ROLLBACK;")
            raise


def init_database(db_path: str = None) -> None:
    """Initialize database tables, indices, and application-level protection triggers."""
    conn = get_db_connection(db_path)
    try:
        with atomic_transaction(conn) as cur:
            # 1. Approved Loans Table (Strictly INR)
            cur.execute("""
            CREATE TABLE IF NOT EXISTS loans (
                loan_id TEXT PRIMARY KEY,
                borrower_id TEXT NOT NULL,
                approved_limit_inr REAL NOT NULL CHECK(approved_limit_inr >= 0),
                disbursed_amount_inr REAL NOT NULL DEFAULT 0.0 CHECK(disbursed_amount_inr >= 0),
                status TEXT NOT NULL CHECK(status IN ('APPROVED', 'PENDING', 'CLOSED')),
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            """)

            # 2. Registered Beneficiaries Table
            cur.execute("""
            CREATE TABLE IF NOT EXISTS beneficiaries (
                beneficiary_id TEXT PRIMARY KEY,
                borrower_id TEXT NOT NULL,
                account_number TEXT NOT NULL,
                ifsc_code TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('ACTIVE', 'REVOKED')),
                registered_at TEXT NOT NULL
            );
            """)

            # 3. Transactions Table (Explicit 5-State Machine)
            cur.execute("""
            CREATE TABLE IF NOT EXISTS transactions (
                transaction_id TEXT PRIMARY KEY,
                loan_id TEXT NOT NULL,
                borrower_id TEXT NOT NULL,
                beneficiary_id TEXT NOT NULL,
                amount_inr REAL NOT NULL CHECK(amount_inr > 0),
                currency TEXT NOT NULL DEFAULT 'INR',
                state TEXT NOT NULL CHECK(state IN ('RECEIVED', 'VALIDATED', 'HELD', 'REJECTED', 'APPROVED')),
                idempotency_key TEXT UNIQUE NOT NULL,
                decision_reason TEXT NOT NULL,
                correlation_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            """)

            # 4. Idempotency Store
            cur.execute("""
            CREATE TABLE IF NOT EXISTS idempotency_records (
                idempotency_key TEXT PRIMARY KEY,
                client_id TEXT NOT NULL,
                request_hash TEXT NOT NULL,
                response_code INTEGER NOT NULL,
                response_body TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            """)

            # 5. Synthetic API Tokens Table
            cur.execute("""
            CREATE TABLE IF NOT EXISTS api_tokens (
                token_id TEXT PRIMARY KEY,
                token_string TEXT UNIQUE NOT NULL,
                client_id TEXT NOT NULL,
                scopes TEXT NOT NULL,
                is_revoked INTEGER NOT NULL DEFAULT 0 CHECK(is_revoked IN (0, 1)),
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            """)

            # 6. Used Nonces for Replay Protection
            cur.execute("""
            CREATE TABLE IF NOT EXISTS used_nonces (
                nonce TEXT NOT NULL,
                client_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (nonce, client_id)
            );
            """)

            # 7. Authentication Attempts Telemetry (for DET-04)
            cur.execute("""
            CREATE TABLE IF NOT EXISTS auth_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_id TEXT NOT NULL,
                token_presented TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('SUCCESS', 'FAILURE')),
                failure_reason TEXT,
                timestamp TEXT NOT NULL
            );
            """)

            # 8. Blocked Callers Table (DET-04 & Response Engine)
            cur.execute("""
            CREATE TABLE IF NOT EXISTS blocked_callers (
                client_id TEXT PRIMARY KEY,
                reason TEXT NOT NULL,
                blocked_by TEXT NOT NULL,
                blocked_at TEXT NOT NULL
            );
            """)

            # 9. SOC Security Incidents Table
            cur.execute("""
            CREATE TABLE IF NOT EXISTS soc_incidents (
                incident_id TEXT PRIMARY KEY,
                rule_code TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                affected_entity TEXT NOT NULL,
                transaction_id TEXT,
                status TEXT NOT NULL CHECK(status IN ('OPEN', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'FALSE_POSITIVE')),
                recommended_action TEXT NOT NULL,
                analyst_notes TEXT,
                assigned_analyst TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            """)

            # 10. Append-Only Audit Ledger
            cur.execute("""
            CREATE TABLE IF NOT EXISTS audit_ledger (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT UNIQUE NOT NULL,
                timestamp TEXT NOT NULL,
                correlation_id TEXT NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                state_from TEXT,
                state_to TEXT,
                decision_reason TEXT NOT NULL,
                payload_sha256 TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                record_hash TEXT NOT NULL
            );
            """)

            # Application-Level Protection Triggers for audit_ledger
            cur.execute("""
            CREATE TRIGGER IF NOT EXISTS trg_audit_no_update
            BEFORE UPDATE ON audit_ledger
            BEGIN
                SELECT RAISE(FAIL, 'APPLICATION INTEGRITY VIOLATION: Updates to audit_ledger are strictly prohibited.');
            END;
            """)

            cur.execute("""
            CREATE TRIGGER IF NOT EXISTS trg_audit_no_delete
            BEFORE DELETE ON audit_ledger
            BEGIN
                SELECT RAISE(FAIL, 'APPLICATION INTEGRITY VIOLATION: Deletions from audit_ledger are strictly prohibited.');
            END;
            """)

        logger.info("PAYGUARD Database initialized with schema, incidents, and protection triggers.")
    finally:
        conn.close()
