"""
Firewall Rule Audit — audit engine.
Phase 2: obvious-issue scan (repeated deny-all, duplicate rules, weak comments)
Phase 3: diff current config against last audit-approved baseline
Phase 4 pre-stage: extract ticket references and build a copy-paste
                   verification worklist for the analyst.
"""

import re
from collections import defaultdict

from fw_parser import rule_identity

WEAK_COMMENT_TERMS = {"test", "temp", "tmp", "asdf", "delete me", "fix later", "xxx"}
TICKET_PATTERN = re.compile(r"\b(INC|CHG|RITM|REQ|TASK)\d{4,}\b", re.IGNORECASE)
MIN_COMMENT_LENGTH = 10


# ---------- Phase 2: obvious issues ----------

def find_repeated_deny_all(rules):
    """Flag deny-all rules (action=deny, src=all, dst=all, service=ALL)
    when there are 2 or more of them."""
    deny_all_rules = [
        r for r in rules
        if r["action"].strip().lower() == "deny"
        and r["srcaddr"].strip().lower() == "all"
        and r["dstaddr"].strip().lower() == "all"
        and r["service"].strip().lower() == "all"
    ]
    if len(deny_all_rules) >= 2:
        return deny_all_rules
    return []


def find_duplicate_rules(rules):
    """Flag rules that share the same functional identity (5-tuple)
    even if the rule id/name differs."""
    groups = defaultdict(list)
    for r in rules:
        groups[rule_identity(r)].append(r)

    duplicates = []
    for identity, group in groups.items():
        if len(group) >= 2:
            duplicates.append(group)
    return duplicates


def find_weak_comments(rules):
    """Flag rules with missing, too-short, or generic placeholder comments."""
    flagged = []
    for r in rules:
        comment = r["comments"].strip()
        if not comment:
            flagged.append((r, "missing comment"))
            continue
        if len(comment) < MIN_COMMENT_LENGTH:
            flagged.append((r, "comment too short to be descriptive"))
            continue
        if comment.lower() in WEAK_COMMENT_TERMS:
            flagged.append((r, "generic placeholder comment"))
            continue
    return flagged


# ---------- Phase 3: diff against baseline ----------

def diff_against_baseline(current_rules, baseline_rules):
    """
    Return rules present in current but not in baseline (by 5-tuple identity).
    These are the "added since last audit" rules requiring verification.
    """
    baseline_identities = {rule_identity(r) for r in baseline_rules}
    delta_rules = [
        r for r in current_rules
        if rule_identity(r) not in baseline_identities
    ]
    return delta_rules


# ---------- Phase 4 pre-stage: ticket extraction ----------

def extract_ticket_ref(rule):
    """Pull a ticket ID (INC/CHG/RITM/etc.) out of the comment field, if present."""
    m = TICKET_PATTERN.search(rule["comments"])
    return m.group(0).upper() if m else None


def build_verification_worklist(delta_rules):
    """
    Build the Phase 4 pre-stage table: for each delta rule, the
    identifiers an analyst needs to paste into the ticketing system,
    plus the ticket ID if one was found in the comment.
    """
    worklist = []
    for r in delta_rules:
        ticket = extract_ticket_ref(r)
        worklist.append({
            "rule_id": r["id"],
            "rule_name": r["name"],
            "srcaddr": r["srcaddr"],
            "dstaddr": r["dstaddr"],
            "service": r["service"],
            "comment": r["comments"] or "(none)",
            "ticket_ref": ticket if ticket else "NOT FOUND — search manually by IP/object",
        })
    return worklist
