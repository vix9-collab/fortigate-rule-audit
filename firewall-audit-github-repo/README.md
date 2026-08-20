# Firewall Rule Audit

A pre-audit prep framework and CLI tool for FortiGate firewall rule reviews. Turns a manual, multi-day rule-by-rule scroll into a structured, repeatable process.

Part of the [NetZeal Playbook Series](#) — built from real audit workflows.

## The problem

Most firewall audits happen the same chaotic way: an audit gets scheduled, and whoever has free cycles starts scrolling through hundreds of rules with no structure. It works, but it's slow, inconsistent between engineers, and easy to miss something under time pressure.

## The framework

| Phase | What happens | Automated? |
|---|---|---|
| 1 — Trigger | Audit scheduled, or free cycles ahead of one | N/A |
| 2 — Obvious Issues | Repeated deny-alls, duplicate rules, weak/missing comments | ✅ Yes |
| 3 — Baseline Diff | Diff current config against last audit-approved config | ✅ Yes |
| 4 — Verification | Trace each new rule to its ticket, confirm it's still needed | ⚠️ Pre-staged only — stays manual |

Phases 2 and 3 are mechanical — this tool automates both. Phase 4 requires real engineering judgment (ticket systems and approval workflows vary too much between orgs to safely automate), so the tool pre-stages it: it extracts ticket references from rule comments and builds a copy-paste-ready worklist, so you're verifying instead of building the list from scratch.

## Quick start

```bash
python3 firewall_rule_audit.py \
  --current samples/current_running.conf \
  --baseline samples/baseline_approved.conf \
  --out report.txt \
  --csv worklist.csv
```

No third-party dependencies — standard library only, Python 3.8+.

## What it checks

**Phase 2 (obvious issues):**
- Repeated deny-all rules (2+)
- Duplicate rules — same source/dest/service/action, different rule ID
- Weak or missing comments (blank, under 10 characters, or generic placeholders like "test"/"temp")

**Phase 3 (diff):**
- Rules in the current config that don't exist in the baseline, matched by functional identity (source interface, dest interface, source address, dest address, action, service) — not by rule ID or name, since those can change without the rule itself changing.

**Phase 4 (pre-stage only):**
- Extracts ticket references (INC/CHG/RITM/REQ/TASK + 4 digits) from comment fields where present.
- Flags rules with no ticket reference as "search manually by IP/object" — the tool doesn't guess.
- Ticket verification and relevance judgment stay entirely manual, by design.

## Sample output

```
[Repeated deny-all entries: 3 found]
  Rule 7 "Deny_All_Dup1" | all -> all | ALL | action=deny
  ...

PHASE 3 — RULES ADDED SINCE LAST APPROVED BASELINE
4 rule(s) in current config not present in baseline.

PHASE 4 PRE-STAGE — VERIFICATION WORKLIST
  Rule 4 "Allow_HR_App"
    ticket ref: INC0013410
  Rule 6 "Vendor_VPN_Access"
    ticket ref: NOT FOUND — search manually by IP/object
```

## Standalone binary (no Python required to run)

See [BUILD_INSTRUCTIONS.md](BUILD_INSTRUCTIONS.md) for building a native Windows `.exe` or macOS binary via PyInstaller. Note: PyInstaller doesn't cross-compile — build on the target OS.

## Repo structure

```
fw_parser.py              # FortiGate config parser
fw_audit.py                # Phase 2/3/4 audit logic
firewall_rule_audit.py     # CLI entry point
samples/                   # Sample configs for testing
BUILD_INSTRUCTIONS.md      # Standalone binary build steps
```

## Extending to other vendors

`fw_parser.py` is FortiGate-specific (`config firewall policy` / `set field value` syntax). Porting to Palo Alto or Cisco ASA means rewriting the parser for that vendor's config grammar — the Phase 2/3/4 audit logic in `fw_audit.py` is vendor-agnostic and reusable as-is.

Contributions for other vendor parsers welcome.

## License

MIT — see [LICENSE](LICENSE).
