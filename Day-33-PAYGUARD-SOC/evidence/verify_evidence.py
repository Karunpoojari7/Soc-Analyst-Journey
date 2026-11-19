"""PAYGUARD SOC - Independent Forensic Evidence Verifier.

STANDALONE VERIFICATION SCRIPT:
This tool is completely independent of the application database and API server.
It verifies:
1. The authenticity of the manifest via HMAC-SHA256 signature verification.
2. The cryptographic integrity of every record in the append-only hash chain.
3. The exact record where tampering or corruption occurred, if any.
"""

import sys
import os
import json
import hmac
import hashlib
import argparse
from typing import Tuple, Optional

GENESIS_HASH = "0" * 64
DEFAULT_SECRET = "synthetic-lab-evidence-hmac-key-2026-inr"


def compute_record_hash(prev_hash: str, event_id: str, timestamp: str,
                        action: str, decision_reason: str, payload_sha256: str) -> str:
    """Recompute the cryptographic SHA-256 digest of an audit record."""
    preimage = f"{prev_hash}|{event_id}|{timestamp}|{action}|{decision_reason}|{payload_sha256}"
    return hashlib.sha256(preimage.encode("utf-8")).hexdigest()


def verify_evidence_integrity(
    manifest_path: str,
    records_path: str,
    hmac_secret: Optional[str] = None
) -> Tuple[bool, str]:
    """Verify evidence manifest signature and sequential hash chain integrity.
    
    Returns:
        (is_valid: bool, report_message: str)
    """
    secret = hmac_secret or DEFAULT_SECRET

    if not os.path.exists(manifest_path):
        return False, f"Manifest file not found: {manifest_path}"
    if not os.path.exists(records_path):
        return False, f"Records file not found: {records_path}"

    # 1. Load and Verify Manifest Signature
    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    expected_sig = hmac.new(
        key=secret.encode("utf-8"),
        msg=f"{manifest['record_count']}|{manifest['first_event_id']}|{manifest['last_event_id']}|{manifest['root_hash']}".encode("utf-8"),
        digestmod=hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(manifest["manifest_signature"], expected_sig):
        return False, "FORENSIC INTEGRITY COMPROMISED: Manifest signature mismatch (Manifest has been tampered with)."

    # 2. Sequentially Verify Audit Hash Chain
    records = []
    with open(records_path, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line_str = line.strip()
            if not line_str:
                continue
            try:
                rec = json.loads(line_str)
                records.append(rec)
            except json.JSONDecodeError:
                return False, f"JSON parse error in records file at line {line_no}"

    if len(records) != manifest["record_count"]:
        return False, (
            f"Record count mismatch: Manifest declares {manifest['record_count']} records, "
            f"but found {len(records)} records."
        )

    current_prev_hash = GENESIS_HASH

    for idx, rec in enumerate(records):
        event_id = rec.get("event_id", f"UNKNOWN_IDX_{idx}")

        # Check chain continuity
        if rec.get("prev_hash") != current_prev_hash:
            return False, (
                f"HASH CHAIN BROKEN at record index {idx} (Event: {event_id}): "
                f"Expected prev_hash '{current_prev_hash}', got '{rec.get('prev_hash')}'."
            )

        # Recompute record hash
        recomputed = compute_record_hash(
            prev_hash=rec["prev_hash"],
            event_id=rec["event_id"],
            timestamp=rec["timestamp"],
            action=rec["action"],
            decision_reason=rec["decision_reason"],
            payload_sha256=rec["payload_sha256"]
        )

        if recomputed != rec.get("record_hash"):
            return False, (
                f"RECORD TAMPERING DETECTED at record index {idx} (Event: {event_id}): "
                f"Recomputed hash '{recomputed}' does not match stored hash '{rec.get('record_hash')}'."
            )

        current_prev_hash = rec["record_hash"]

    # 3. Check Final Root Hash
    if current_prev_hash != manifest["root_hash"]:
        return False, (
            f"ROOT HASH MISMATCH: Final chained hash '{current_prev_hash}' "
            f"does not match manifest root_hash '{manifest['root_hash']}'."
        )

    return True, (
        f"FORENSIC VERIFICATION SUCCESSFUL: All {len(records)} audit records and hash chains "
        f"are cryptographically valid. Root hash: {manifest['root_hash']}"
    )


def main():
    parser = argparse.ArgumentParser(description="PAYGUARD SOC Independent Evidence Verifier")
    parser.add_argument("--manifest", default="evidence/evidence_manifest.json", help="Path to manifest JSON")
    parser.add_argument("--records", default="evidence/evidence_records.jsonl", help="Path to records JSONL")
    parser.add_argument("--secret", default=DEFAULT_SECRET, help="HMAC verification key")

    args = parser.parse_args()
    is_valid, report = verify_evidence_integrity(args.manifest, args.records, args.secret)

    if is_valid:
        print(f"[OK] {report}")
        sys.exit(0)
    else:
        print(f"[FAIL] {report}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
