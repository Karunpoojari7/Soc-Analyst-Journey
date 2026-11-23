import csv
import hashlib
import json
from pathlib import Path
from collections import defaultdict
from datetime import datetime

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence"
OUTPUT = ROOT / "output"
TIMELINE = ROOT / "timeline"

DATA = {
    "identity-logs/identity-events.csv": [
        ["event_id","timestamp","username","source_ip","event_type","result"],
        ["I001","2026-11-23T09:00:00","officer_102","192.0.2.10","LOGIN","SUCCESS"],
        ["I002","2026-11-23T09:12:00","officer_102","198.51.100.24","LOGIN","FAILED"],
        ["I003","2026-11-23T09:13:00","officer_102","198.51.100.24","LOGIN","FAILED"],
        ["I004","2026-11-23T09:14:00","officer_102","198.51.100.24","LOGIN","SUCCESS"],
        ["I005","2026-11-23T09:15:00","officer_102","198.51.100.24","MFA","PASSED"],
        ["I006","2026-11-23T09:18:00","admin_01","198.51.100.24","ROLE_CHANGE","PRIVILEGE_GRANTED"],
        ["I007","2026-11-23T10:00:00","officer_205","192.0.2.15","LOGIN","SUCCESS"]
    ],
    "api-logs/api-events.csv": [
        ["event_id","timestamp","username","source_ip","endpoint","method","status"],
        ["A001","2026-11-23T09:20:00","officer_102","198.51.100.24","/records/search","POST","200"],
        ["A002","2026-11-23T09:21:00","officer_102","198.51.100.24","/records/search","POST","200"],
        ["A003","2026-11-23T09:22:00","officer_102","198.51.100.24","/records/export","POST","200"],
        ["A004","2026-11-23T09:25:00","admin_01","198.51.100.24","/admin/permissions","POST","200"],
        ["A005","2026-11-23T10:01:00","officer_205","192.0.2.15","/records/search","POST","200"]
    ],
    "database-logs/database-events.csv": [
        ["event_id","timestamp","username","operation","records","result"],
        ["D001","2026-11-23T09:20:00","officer_102","SELECT",15,"SUCCESS"],
        ["D002","2026-11-23T09:21:00","officer_102","SELECT",2500,"SUCCESS"],
        ["D003","2026-11-23T09:22:00","officer_102","EXPORT",3500,"SUCCESS"],
        ["D004","2026-11-23T09:26:00","admin_01","UPDATE",1,"SUCCESS"],
        ["D005","2026-11-23T09:27:00","admin_01","DELETE",5,"SUCCESS"],
        ["D006","2026-11-23T10:02:00","officer_205","SELECT",12,"SUCCESS"]
    ],
    "network-logs/network-events.csv": [
        ["event_id","timestamp","source_ip","destination_ip","destination_port","bytes"],
        ["N001","2026-11-23T09:22:00","198.51.100.24","203.0.113.20",443,8500000],
        ["N002","2026-11-23T09:24:00","198.51.100.24","203.0.113.20",443,12000000],
        ["N003","2026-11-23T10:05:00","192.0.2.15","203.0.113.30",443,18000]
    ],
    "endpoint-logs/endpoint-events.csv": [
        ["event_id","timestamp","hostname","username","process","event_type"],
        ["E001","2026-11-23T09:16:00","TRAINING-WS01","officer_102","browser.exe","USER_SESSION"],
        ["E002","2026-11-23T09:23:00","TRAINING-WS01","officer_102","powershell.exe","PROCESS_START"],
        ["E003","2026-11-23T09:24:00","TRAINING-WS01","admin_01","archive-tool.exe","FILE_ARCHIVE"],
        ["E004","2026-11-23T09:28:00","TRAINING-WS01","admin_01","unknown.exe","PROCESS_START"],
        ["E005","2026-11-23T10:00:00","TRAINING-WS02","officer_205","browser.exe","USER_SESSION"]
    ]
}

def write_csv(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerows(rows)

def read_csv(path):
    with path.open(newline="") as f:
        return list(csv.DictReader(f))

def generate_evidence():
    for name, rows in DATA.items():
        write_csv(EVIDENCE / name, rows)
    print("[PASS] Generated five synthetic evidence datasets.")

def validate_evidence():
    manifest = []
    total = 0
    for path in sorted(EVIDENCE.rglob("*.csv")):
        rows = read_csv(path)
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        manifest.append(f"{digest}  {path.relative_to(ROOT)}")
        total += len(rows)
        print(f"[PASS] {path.name}: {len(rows)} records")
    (OUTPUT / "evidence-sha256.txt").write_text("\n".join(manifest) + "\n")
    print(f"[PASS] Total records: {total}")
    print("[PASS] SHA-256 manifest generated.")
    return total

def analyze():
    alerts = []
    events = []

    identity = read_csv(EVIDENCE / "identity-logs/identity-events.csv")
    api = read_csv(EVIDENCE / "api-logs/api-events.csv")
    database = read_csv(EVIDENCE / "database-logs/database-events.csv")
    network = read_csv(EVIDENCE / "network-logs/network-events.csv")
    endpoint = read_csv(EVIDENCE / "endpoint-logs/endpoint-events.csv")

    # Authentication: repeated failures followed by success.
    failures = defaultdict(list)
    for row in identity:
        if row["event_type"] == "LOGIN" and row["result"] == "FAILED":
            failures[row["username"]].append(row)
        if row["event_type"] == "LOGIN" and row["result"] == "SUCCESS":
            prior = failures[row["username"]]
            if len(prior) >= 2:
                alerts.append(("HIGH","NCIC-001","Repeated login failures followed by success",row["username"],row["timestamp"]))

    # Privilege change.
    for row in identity:
        if row["event_type"] == "ROLE_CHANGE":
            alerts.append(("HIGH","NCIC-002","Privilege change requires authorization review",row["username"],row["timestamp"]))

    # API export.
    for row in api:
        if row["endpoint"] == "/records/export":
            alerts.append(("HIGH","NCIC-005","Records export API request",row["username"],row["timestamp"]))

    # Database queries and changes.
    for row in database:
        count = int(row["records"])
        if row["operation"] == "SELECT" and count >= 1000:
            alerts.append(("HIGH","NCIC-003",f"Unusually high database read: {count} records",row["username"],row["timestamp"]))
        if row["operation"] in ("UPDATE","DELETE"):
            alerts.append(("MEDIUM","NCIC-004",f"Database {row['operation']} requires authorization review",row["username"],row["timestamp"]))
        if row["operation"] == "EXPORT" and count >= 1000:
            alerts.append(("CRITICAL","NCIC-005",f"Large database export: {count} records",row["username"],row["timestamp"]))

    # Large outbound transfers.
    for row in network:
        if int(row["bytes"]) >= 1000000:
            alerts.append(("HIGH","NCIC-006",f"Large outbound transfer: {row['bytes']} bytes",row["source_ip"],row["timestamp"]))

    # Endpoint review.
    suspicious = {"powershell.exe","archive-tool.exe","unknown.exe"}
    for row in endpoint:
        if row["process"].lower() in suspicious:
            alerts.append(("MEDIUM","NCIC-007",f"Endpoint process review: {row['process']}",row["username"],row["timestamp"]))

    # Correlated timeline.
    for dataset, rows in [
        ("IDENTITY",identity),("API",api),("DATABASE",database),
        ("NETWORK",network),("ENDPOINT",endpoint)
    ]:
        for row in rows:
            events.append({
                "timestamp": row["timestamp"],
                "source": dataset,
                "event_id": row["event_id"],
                "details": json.dumps(row, sort_keys=True)
            })

    events.sort(key=lambda x: x["timestamp"])
    timeline_path = TIMELINE / "correlated-timeline.csv"
    timeline_path.parent.mkdir(parents=True, exist_ok=True)
    with timeline_path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["timestamp","source","event_id","details"])
        writer.writeheader()
        writer.writerows(events)

    alert_data = [
        {"severity":a[0],"rule_id":a[1],"description":a[2],"entity":a[3],"timestamp":a[4]}
        for a in alerts
    ]
    (OUTPUT / "detection-alerts.json").write_text(json.dumps(alert_data, indent=2))

    print(f"[PASS] Correlated {len(events)} events into timeline.")
    print(f"[INFO] Detection alerts generated: {len(alerts)}")
    for a in alerts:
        print(f"[{a[0]}] {a[1]} | {a[2]} | {a[3]} | {a[4]}")
    return alerts

def test_benign():
    # Unit checks for expected detections in this fixed training dataset.
    alerts = json.loads((OUTPUT / "detection-alerts.json").read_text())
    rules = {a["rule_id"] for a in alerts}
    required = {"NCIC-001","NCIC-002","NCIC-003","NCIC-004","NCIC-005","NCIC-006","NCIC-007"}
    missing = required - rules
    if missing:
        raise AssertionError(f"Missing detection rules: {sorted(missing)}")
    if not alerts:
        raise AssertionError("No alerts were generated.")
    print("[PASS] Suspicious dataset triggered all seven detection categories.")
    print("[INFO] Benign dataset testing is a separate next exercise; no benign result is claimed.")

def report():
    alerts = json.loads((OUTPUT / "detection-alerts.json").read_text())
    report_text = f"""# Day 37 — SOC Investigation Report

## Case
Simulated NCIC-style government database intrusion investigation.

## Evidence
Five synthetic CSV datasets were generated:
- Identity
- API
- Database
- Network
- Endpoint

All IP addresses are documentation-only examples.

## Detection summary
Total alerts: {len(alerts)}

""" + "\n".join(
        f"- {a['severity']} | {a['rule_id']} | {a['description']}"
        for a in alerts
    ) + """

## Assessment
The synthetic evidence contains suspicious authentication activity,
a privilege change, unusual database access, data export activity,
large outbound transfers, and endpoint processes requiring review.

These observations warrant investigation in this simulation. They do
not prove that the real FBI NCIC system experienced these events.

## Recommended response
1. Validate the identity and MFA events.
2. Review authorization for privilege changes.
3. Confirm the business purpose of database queries and exports.
4. Correlate network transfers with approved application activity.
5. Preserve endpoint and database audit evidence.
6. Restrict suspicious sessions only under approved response authority.
7. Document confirmed impact separately from investigative hypotheses.
"""
    (OUTPUT / "SOC-investigation-report.md").write_text(report_text)
    print("[PASS] SOC investigation report generated.")

def main():
    OUTPUT.mkdir(parents=True, exist_ok=True)
    generate_evidence()
    total = validate_evidence()
    alerts = analyze()
    test_benign()
    report()
    print("\n========== DAY 37 LAB SUMMARY ==========")
    print(f"Evidence records: {total}")
    print(f"Detection alerts: {len(alerts)}")
    print(f"Timeline: {TIMELINE / 'correlated-timeline.csv'}")
    print(f"Report: {OUTPUT / 'SOC-investigation-report.md'}")
    print("Lab execution completed.")

if __name__ == "__main__":
    main()
