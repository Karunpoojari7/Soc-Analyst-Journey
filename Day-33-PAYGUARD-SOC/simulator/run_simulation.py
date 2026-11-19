#!/usr/bin/env python3
"""PAYGUARD SOC - Attack Simulation CLI Runner.

Simulates advanced FinTech and API cyberattack scenarios against the local
synthetic PAYGUARD SOC engine to demonstrate detection, containment, and audit logging.
"""

import sys
import os
import argparse
from typing import Dict, Any

# Ensure project root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.data.database import init_database
from backend.data.seed import seed_database
from backend.simulator.attack_scenarios import run_scenario


# ANSI Color Codes for terminal formatting
C_RESET = "\033[0m"
C_BOLD = "\033[1m"
C_RED = "\033[31m"
C_GREEN = "\033[32m"
C_YELLOW = "\033[33m"
C_BLUE = "\033[34m"
C_CYAN = "\033[36m"
C_MAGENTA = "\033[35m"


def print_banner():
    print(f"{C_CYAN}{C_BOLD}")
    print("=" * 78)
    print("  PAYGUARD SOC — Attack Simulation & Threat Emulation Engine")
    print("  Simulating I4C / CERT-In FinTech Cyberattack Patterns (Strictly Synthetic INR)")
    print("=" * 78)
    print(f"{C_RESET}")


def format_scenario_report(report: Dict[str, Any]):
    sc_id = report["scenario_id"]
    name = report["name"]
    rule = report["target_rule"]
    action = report["defensive_action"]
    detected = report["detected"]
    corr_id = report["correlation_id"]

    status_badge = f"{C_GREEN}[DETECTED & MITIGATED]{C_RESET}" if detected else f"{C_RED}[MISSED]{C_RESET}"
    
    print(f"\n{C_BOLD}▶ SCENARIO {sc_id}: {name}{C_RESET}")
    print(f"  Target Rule     : {C_YELLOW}{rule}{C_RESET}")
    print(f"  Attack Vector   : {report['attack_vector']}")
    print(f"  Correlation ID  : {C_BLUE}{corr_id}{C_RESET}")
    print(f"  Detection Status: {status_badge}")
    print(f"  Defensive Action: {C_MAGENTA}{action}{C_RESET}")
    if report.get("incident_id"):
        print(f"  SOC Incident ID : {C_RED}{report['incident_id']}{C_RESET}")

    print(f"\n  {C_BOLD}Execution Telemetry:{C_RESET}")
    for s in report["steps"]:
        print(f"   • Step {s.get('step', s.get('attempt', '-'))}: {s.get('description', s.get('result', ''))}")
        if "decision_reason" in s:
            print(f"     Reason       : {C_YELLOW}{s['decision_reason']}{C_RESET}")
        if "state" in s:
            print(f"     FSM State    : {C_CYAN}{s['state']}{C_RESET}")

    print(f"\n  {C_BOLD}Forensic Summary:{C_RESET}")
    print(f"  {report['summary']}\n")
    print("-" * 78)


def main():
    parser = argparse.ArgumentParser(description="PAYGUARD SOC Attack Simulation Runner")
    parser.add_argument(
        "--scenario",
        default="all",
        help="Scenario ID to run (1-7) or 'all' to run complete attack simulation suite"
    )
    parser.add_argument(
        "--seed",
        action="store_true",
        help="Re-seed synthetic database before running simulation"
    )
    args = parser.parse_args()

    print_banner()

    if args.seed:
        print(f"{C_YELLOW}[*] Seeding database with clean synthetic test records...{C_RESET}")
        seed_database()
        print(f"{C_GREEN}[✓] Database seeded successfully.{C_RESET}\n")

    if args.scenario.lower() == "all":
        print(f"{C_CYAN}[*] Running complete simulation suite (Scenarios 1 through 7)...{C_RESET}\n")
        passed = 0
        total = 7
        for sc_id in range(1, 8):
            rep = run_scenario(sc_id)
            format_scenario_report(rep)
            if rep["detected"]:
                passed += 1
        
        print(f"\n{C_BOLD}{C_GREEN}══════════════════════════════════════════════════════════════════════════════{C_RESET}")
        print(f"{C_BOLD} SIMULATION COMPLETE: {passed}/{total} Attack Scenarios Intercepted & Logged to SOC Ledger{C_RESET}")
        print(f"{C_BOLD}{C_GREEN}══════════════════════════════════════════════════════════════════════════════{C_RESET}\n")
    else:
        try:
            sc_id = int(args.scenario)
            if not (1 <= sc_id <= 7):
                raise ValueError()
        except ValueError:
            print(f"{C_RED}[!] Error: Invalid scenario ID '{args.scenario}'. Choose 1 through 7, or 'all'.{C_RESET}")
            sys.exit(1)

        rep = run_scenario(sc_id)
        format_scenario_report(rep)


if __name__ == "__main__":
    main()
