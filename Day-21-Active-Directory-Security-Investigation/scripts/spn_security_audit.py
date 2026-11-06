#!/usr/bin/env python3

import csv
import sys


def audit_accounts(path):
    with open(path, newline="", encoding="utf-8") as file:
        accounts = list(csv.DictReader(file))

    print("========== SPN SECURITY AUDIT ==========")
    print(f"Accounts analysed: {len(accounts)}")

    spn_accounts = 0
    findings = []

    for account in accounts:
        username = account["Username"]
        spn = account["SPN"].strip()
        enabled = account["Enabled"].lower() == "true"
        privileged = account["Privileged"].lower() == "true"
        no_expiry = account["PasswordNeverExpires"].lower() == "true"

        if not spn:
            continue

        spn_accounts += 1
        risks = []

        if not enabled:
            risks.append("Account disabled - verify stale SPN")

        if privileged:
            risks.append("Privileged account has an SPN")

        if no_expiry:
            risks.append("Password never expires")

        print(f"\n[SPN ACCOUNT] {username}")
        print(f"  SPN: {spn}")

        if risks:
            for risk in risks:
                print(f"  [REVIEW] {risk}")
            findings.append((username, risks))
        else:
            print("  [INFO] No configured risk flags in this dataset")

    print("\n========== AUDIT SUMMARY ==========")
    print(f"SPN-associated accounts: {spn_accounts}")
    print(f"Accounts requiring review: {len(findings)}")

    for username, risks in findings:
        print(f"- {username}: {len(risks)} review indicator(s)")

    print("\nDataset status: SIMULATED TRAINING DATA")
    print("A risk indicator is not proof of compromise.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 spn_security_audit.py <inventory.csv>")
        sys.exit(1)

    audit_accounts(sys.argv[1])
