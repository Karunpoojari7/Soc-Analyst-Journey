"""Module 3 Tests: API Security, Token Lifecycle, Replay Guard, Redaction & Network Isolation."""

import pytest
import logging
import io
import socket
from datetime import datetime, timezone, timedelta
from backend.data.database import get_db_connection
from backend.data.seed import seed_database
from backend.config import settings
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


@pytest.fixture(autouse=True)
def setup_test_db(tmp_path):
    db_file = str(tmp_path / "test_module3.db")
    settings.DATABASE_PATH = db_file
    seed_database(db_file)
    yield db_file


def test_valid_token_and_scope():
    conn = get_db_connection()
    # lab_tok_disburse_valid_999 has disbursement:create, disbursement:read
    tok_info = verify_synthetic_token(
        token="Bearer lab_tok_disburse_valid_999",
        conn=conn,
        required_scope="disbursement:create"
    )
    assert tok_info.client_id == "client_lending_partner_01"
    assert "disbursement:create" in tok_info.scopes
    conn.close()


def test_missing_and_invalid_token():
    conn = get_db_connection()
    with pytest.raises(SecurityValidationError) as exc:
        verify_synthetic_token(token="", conn=conn)
    assert exc.value.status_code == 401

    with pytest.raises(SecurityValidationError) as exc:
        verify_synthetic_token(token="lab_tok_nonexistent_000", conn=conn)
    assert exc.value.status_code == 401
    assert exc.value.reason_code == "SECURITY_TOKEN_INVALID"
    conn.close()


def test_expired_token():
    conn = get_db_connection()
    with pytest.raises(SecurityValidationError) as exc:
        verify_synthetic_token(token="lab_tok_expired_555", conn=conn)
    assert exc.value.status_code == 401
    assert exc.value.reason_code == "SECURITY_TOKEN_EXPIRED"
    conn.close()


def test_revoked_token():
    conn = get_db_connection()
    with pytest.raises(SecurityValidationError) as exc:
        verify_synthetic_token(token="lab_tok_revoked_666", conn=conn)
    assert exc.value.status_code == 401
    assert exc.value.reason_code == "SECURITY_TOKEN_REVOKED"
    conn.close()


def test_insufficient_scope():
    conn = get_db_connection()
    # lab_tok_readonly_888 only has disbursement:read
    with pytest.raises(SecurityValidationError) as exc:
        verify_synthetic_token(
            token="lab_tok_readonly_888",
            conn=conn,
            required_scope="soc:review"
        )
    assert exc.value.status_code == 403
    assert exc.value.reason_code == "SECURITY_INSUFFICIENT_SCOPE"
    conn.close()


def test_timestamp_skew_and_replay_prevention():
    conn = get_db_connection()
    now_dt = datetime.now(timezone.utc)
    
    # 1. Skewed timestamp (15 minutes in the past)
    old_ts = (now_dt - timedelta(minutes=15)).isoformat()
    with pytest.raises(SecurityValidationError) as exc:
        verify_replay_and_timestamp(conn, "client_01", old_ts, "nonce-101")
    assert exc.value.status_code == 400
    assert exc.value.reason_code == "SECURITY_TIMESTAMP_SKEWED"

    # 2. Valid timestamp and nonce
    valid_ts = now_dt.isoformat()
    verify_replay_and_timestamp(conn, "client_01", valid_ts, "nonce-102")

    # 3. Replay of same nonce
    with pytest.raises(SecurityValidationError) as exc:
        verify_replay_and_timestamp(conn, "client_01", valid_ts, "nonce-102")
    assert exc.value.status_code == 401
    assert exc.value.reason_code == "SECURITY_REPLAY_DETECTED"
    conn.close()


def test_secret_log_redaction():
    logger = logging.getLogger("test_redactor")
    logger.setLevel(logging.INFO)
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.addFilter(SecretRedactorFilter())
    logger.addHandler(handler)

    test_token = "lab_tok_disburse_valid_999"
    logger.info("Processing request with token %s and secret %s", test_token, "lab_tok_secret_value")

    log_output = stream.getvalue()
    assert test_token not in log_output
    assert "lab_tok_***[REDACTED]***" in log_output


def test_network_isolation_socket_interceptor():
    enable_network_isolation()
    assert is_network_isolation_active() is True
    
    try:
        # Attempting outbound connection to non-local address must raise RuntimeError
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        with pytest.raises(RuntimeError, match="NETWORK_ISOLATION_VIOLATION"):
            s.connect(("8.8.8.8", 53))
        s.close()
    finally:
        disable_network_isolation()
        assert is_network_isolation_active() is False
