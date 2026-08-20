#!/usr/bin/env python3
"""
Firewall Rule Audit — CLI tool
NetZeal-style pre-audit prep for FortiGate firewall policies.

Usage:
    python3 firewall_rule_audit.py --current current_running.conf \\
                                    --baseline baseline_approved.conf \\
                                    [--out report.txt] [--csv worklist.csv]

What this does (and doesn't) do:
  - Phase 2 (obvious issues) and Phase 3 (diff) are fully mechanical —
    this tool does that work for you.
  - Phase 4 (ticket trace + relevance judgment) is NOT automated.
    This tool pre-stages a copy-paste-ready worklist so you're pasting
    into your ticketing system, not building the list by hand.
"""

import argparse
import csv
import sys
from datetime import date

from fw_parser import parse_policy_config
from fw_audit import (
    find_repeated_deny_all,
    find_duplicate_rules,
    find_weak_comments,
    diff_against_baseline,
    build_verification_worklist,
)


def rule_summary(r):
    return f"  Rule {r['id']} \"{r['name']}\" | {r['srcaddr']} -> {r['dstaddr']} | {r['service']} | action={r['action']}"


def generate_report(current_path, baseline_path):
    current_rules = parse_policy_config(current_path)
    baseline_rules = parse_policy_config(baseline_path)

    if not current_rules:
        print(f"ERROR: no firewall policy rules parsed from {current_path}. "
              f"Confirm it's a FortiGate config with a 'config firewall policy' block.",
              file=sys.stderr)
        sys.exit(1)

    lines = []
    lines.append("=" * 70)
    lines.append("FIREWALL RULE AUDIT — PRE-AUDIT PREP REPORT")
    lines.append(f"Generated: {date.today().isoformat()}")
    lines.append(f"Current config: {current_path} ({len(current_rules)} rules)")
    lines.append(f"Baseline config: {baseline_path} ({len(baseline_rules)} rules)")
    lines.append("=" * 70)

    # --- Phase 2: obvious issues ---
    lines.append("\nPHASE 2 — OBVIOUS ISSUES (manual-pass equivalent)\n")

    deny_all = find_repeated_deny_all(current_rules)
    lines.append(f"[Repeated deny-all entries: {len(deny_all)} found]")
    for r in deny_all:
        lines.append(rule_summary(r))
    if not deny_all:
        lines.append("  None found.")

    lines.append("")
    duplicates = find_duplicate_rules(current_rules)
    lines.append(f"[Duplicate rules (same effective rule, different ID): {len(duplicates)} group(s) found]")
    for group in duplicates:
        ids = ", ".join(r["id"] for r in group)
        lines.append(f"  Duplicate group — rule IDs {ids}:")
        for r in group:
            lines.append(rule_summary(r))
    if not duplicates:
        lines.append("  None found.")

    lines.append("")
    weak_comments = find_weak_comments(current_rules)
    lines.append(f"[Weak/missing comments: {len(weak_comments)} found]")
    for r, reason in weak_comments:
        lines.append(f"  ({reason})")
        lines.append(rule_summary(r))
    if not weak_comments:
        lines.append("  None found.")

    # --- Phase 3: diff against baseline ---
    lines.append("\n" + "=" * 70)
    lines.append("PHASE 3 — RULES ADDED SINCE LAST APPROVED BASELINE")
    lines.append("=" * 70)
    delta_rules = diff_against_baseline(current_rules, baseline_rules)
    lines.append(f"\n{len(delta_rules)} rule(s) in current config not present in baseline.")
    lines.append("These require Phase 4 verification (ticket trace + relevance check).\n")
    for r in delta_rules:
        lines.append(rule_summary(r))

    # --- Phase 4 pre-stage ---
    lines.append("\n" + "=" * 70)
    lines.append("PHASE 4 PRE-STAGE — VERIFICATION WORKLIST")
    lines.append("(Copy-paste these into your ticketing system search. This tool")
    lines.append(" does not verify tickets or judge relevance — that stays manual.)")
    lines.append("=" * 70 + "\n")

    worklist = build_verification_worklist(delta_rules)
    for w in worklist:
        lines.append(f"  Rule {w['rule_id']} \"{w['rule_name']}\"")
        lines.append(f"    src: {w['srcaddr']}   dst: {w['dstaddr']}   service: {w['service']}")
        lines.append(f"    comment: {w['comment']}")
        lines.append(f"    ticket ref: {w['ticket_ref']}")
        lines.append("")

    if not worklist:
        lines.append("  No delta rules — nothing to verify this cycle.")

    return "\n".join(lines), worklist


def write_csv(worklist, csv_path):
    fieldnames = ["rule_id", "rule_name", "srcaddr", "dstaddr", "service", "comment", "ticket_ref"]
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in worklist:
            writer.writerow(row)


def main():
    parser = argparse.ArgumentParser(description="Firewall Rule Audit — FortiGate pre-audit prep tool")
    parser.add_argument("--current", required=True, help="Path to current running config")
    parser.add_argument("--baseline", required=True, help="Path to last audit-approved baseline config")
    parser.add_argument("--out", default=None, help="Write full report to this text file (also prints to stdout)")
    parser.add_argument("--csv", default=None, help="Write Phase 4 verification worklist to this CSV file")
    args = parser.parse_args()

    report_text, worklist = generate_report(args.current, args.baseline)
    print(report_text)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(report_text)
        print(f"\n[Report written to {args.out}]")

    if args.csv:
        write_csv(worklist, args.csv)
        print(f"[Verification worklist written to {args.csv}]")


if __name__ == "__main__":
    main()
