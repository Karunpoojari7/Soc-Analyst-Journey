"""PAYGUARD SOC - Synthetic Data Seed.

Populates initial loans, beneficiaries, and synthetic API tokens in INR.
"""

from datetime import datetime, timezone
import sqlite3
from backend.data.database import get_db_connection, atomic_transaction, init_database
from backend.config import settings


def seed_database(db_path: str = None) -> None:
    """Populate database with synthetic loans, beneficiaries, and tokens in INR."""
    init_database(db_path)
    conn = get_db_connection(db_path)
    now = datetime.now(timezone.utc).isoformat()
    
    try:
        with atomic_transaction(conn) as cur:
            # 1. Synthetic Loans (All amounts strictly INR)
            loans = [
                ("LOAN-IND-1001", "BORR-IND-901", 50000.00, 0.00, "APPROVED", now, now),
                ("LOAN-IND-1002", "BORR-IND-902", 100000.00, 90000.00, "APPROVED", now, now),
                ("LOAN-IND-1003", "BORR-IND-903", 75000.00, 0.00, "PENDING", now, now),
                ("LOAN-IND-1004", "BORR-IND-904", 25000.00, 25000.00, "CLOSED", now, now),
            ]
            cur.executemany("""
            INSERT OR REPLACE INTO loans 
            (loan_id, borrower_id, approved_limit_inr, disbursed_amount_inr, status, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?);
            """, loans)

            # 2. Registered Beneficiaries
            beneficiaries = [
                ("BENEF-IND-01", "BORR-IND-901", "912345678901", "HDFC0001234", "ACTIVE", now),
                ("BENEF-IND-02", "BORR-IND-902", "912345678902", "SBIN0005678", "ACTIVE", now),
                ("BENEF-IND-03", "BORR-IND-903", "912345678903", "ICIC0009999", "ACTIVE", now),
                ("BENEF-IND-REVOKED", "BORR-IND-901", "912345678999", "UTIB0001111", "REVOKED", now),
            ]
            cur.executemany("""
            INSERT OR REPLACE INTO beneficiaries
            (beneficiary_id, borrower_id, account_number, ifsc_code, status, registered_at)
            VALUES (?, ?, ?, ?, ?, ?);
            """, beneficiaries)

            # 3. Synthetic API Tokens
            tokens = [
                # Standard Lending Client (Can create and read disbursements)
                ("TOK-01", "lab_tok_disburse_valid_999", "client_lending_partner_01", 
                 "disbursement:create,disbursement:read", 0, "2035-01-01T00:00:00Z", now),
                # Read-Only Auditor Client
                ("TOK-02", "lab_tok_readonly_888", "client_auditor_01", 
                 "disbursement:read", 0, "2035-01-01T00:00:00Z", now),
                # SOC Analyst Client (Can review HELD transactions and export audit logs)
                ("TOK-03", "lab_tok_soc_analyst_777", "soc_analyst_01", 
                 "soc:review,audit:export,disbursement:read", 0, "2035-01-01T00:00:00Z", now),
                # Revoked Synthetic Token
                ("TOK-04", "lab_tok_revoked_666", "client_compromised_01", 
                 "disbursement:create", 1, "2035-01-01T00:00:00Z", now),
                # Expired Synthetic Token
                ("TOK-05", "lab_tok_expired_555", "client_old_partner_01", 
                 "disbursement:create", 0, "2020-01-01T00:00:00Z", now),
            ]
            cur.executemany("""
            INSERT OR REPLACE INTO api_tokens
            (token_id, token_string, client_id, scopes, is_revoked, expires_at, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?);
            """, tokens)
            
    finally:
        conn.close()


if __name__ == "__main__":
    seed_database()
    print("Database seeded successfully with synthetic INR test data.")
