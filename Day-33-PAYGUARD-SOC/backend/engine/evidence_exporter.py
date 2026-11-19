"""PAYGUARD SOC - Forensic Evidence Exporter & Manifest Generator.

Exports audit records into structured forensic bundles with SHA-256 hash chaining
and HMAC-signed manifests for independent offline verification.
"""

import os
import json
import hmac
import hashlib
import uuid
from datetime import datetime, timezone
import sqlite3
from typing import Dict, Any, Tuple
from backend.config import settings
from backend.engine.audit_ledger import GENESIS_HASH


def generate_manifest_signature(secret: str, record_count: int, first_id: str,
                                last_id: str, root_hash: str) -> str:
    """Generate HMAC-SHA256 signature for the export manifest."""
    preimage = f"{record_count}|{first_id}|{last_id}|{root_hash}"
    return hmac.new(
        key=secret.encode("utf-8"),
        msg=preimage.encode("utf-8"),
        digestmod=hashlib.sha256
    ).hexdigest()


def export_evidence_bundle(
    conn: sqlite3.Connection,
    output_dir: str = None,
    hmac_secret: str = None
) -> Tuple[str, str]:
    """Export complete audit ledger to JSONL and generate an HMAC-signed manifest.
    
    Returns:
        (records_file_path, manifest_file_path)
    """
    target_dir = output_dir or settings.EVIDENCE_DIR
    secret = hmac_secret or settings.EVIDENCE_HMAC_SECRET
    os.makedirs(target_dir, exist_ok=True)

    cursor = conn.execute("""
        SELECT id, event_id, timestamp, correlation_id, actor, action, 
               state_from, state_to, decision_reason, payload_sha256, prev_hash, record_hash
        FROM audit_ledger 
        ORDER BY id ASC;
    """)
    rows = [dict(r) for r in cursor.fetchall()]

    if not rows:
        raise ValueError("Audit ledger is empty; cannot generate evidence bundle.")

    records_file = os.path.join(target_dir, "evidence_records.jsonl")
    manifest_file = os.path.join(target_dir, "evidence_manifest.json")

    # 1. Write Records in JSONL format
    with open(records_file, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, sort_keys=True) + "\n")

    # 2. Compute Manifest Metadata
    record_count = len(rows)
    first_event_id = rows[0]["event_id"]
    last_event_id = rows[-1]["event_id"]
    root_hash = rows[-1]["record_hash"]

    manifest_signature = generate_manifest_signature(
        secret=secret,
        record_count=record_count,
        first_id=first_event_id,
        last_id=last_event_id,
        root_hash=root_hash
    )

    manifest_data = {
        "export_id": f"EXP-{uuid.uuid4().hex[:12].upper()}",
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "application": settings.APP_NAME,
        "environment": settings.ENVIRONMENT,
        "record_count": record_count,
        "first_event_id": first_event_id,
        "last_event_id": last_event_id,
        "genesis_hash": GENESIS_HASH,
        "root_hash": root_hash,
        "manifest_signature": manifest_signature,
        "hashing_algorithm": "SHA-256",
        "signature_algorithm": "HMAC-SHA256"
    }

    with open(manifest_file, "w", encoding="utf-8") as f:
        json.dump(manifest_data, f, indent=2, sort_keys=True)

    return records_file, manifest_file
