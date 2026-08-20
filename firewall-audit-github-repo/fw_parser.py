"""
FortiGate firewall policy config parser.
Parses `config firewall policy ... end` blocks into a list of rule dicts.
"""

import re


def parse_policy_config(filepath):
    """
    Parse a FortiGate config file and return a list of rule dicts.
    Each rule: {id, name, srcintf, dstintf, srcaddr, dstaddr, action,
                service, comments, raw_block}
    """
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        text = f.read()

    # Isolate the firewall policy block
    match = re.search(
        r"config firewall policy(.*?)^end", text, re.DOTALL | re.MULTILINE
    )
    if not match:
        return []

    body = match.group(1)

    # Split into individual edit blocks
    edit_blocks = re.split(r"^\s*edit\s+(\d+)\s*$", body, flags=re.MULTILINE)[1:]

    rules = []
    # edit_blocks alternates [id, block_text, id, block_text, ...]
    for i in range(0, len(edit_blocks), 2):
        rule_id = edit_blocks[i].strip()
        block_text = edit_blocks[i + 1]

        rule = {
            "id": rule_id,
            "name": _extract_field(block_text, "name"),
            "srcintf": _extract_field(block_text, "srcintf"),
            "dstintf": _extract_field(block_text, "dstintf"),
            "srcaddr": _extract_field(block_text, "srcaddr"),
            "dstaddr": _extract_field(block_text, "dstaddr"),
            "action": _extract_field(block_text, "action"),
            "service": _extract_field(block_text, "service"),
            "comments": _extract_field(block_text, "comments"),
            "raw_block": block_text.strip(),
        }
        rules.append(rule)

    return rules


def _extract_field(block_text, field_name):
    """
    Extract a `set <field_name> ...` line's value(s).
    Handles quoted multi-value fields like: set service "HTTP" "HTTPS"
    Returns a space-joined string of all quoted/unquoted tokens, or ""
    if the field wasn't set.
    """
    pattern = rf'^\s*set\s+{re.escape(field_name)}\s+(.+)$'
    m = re.search(pattern, block_text, re.MULTILINE)
    if not m:
        return ""

    raw_value = m.group(1).strip()
    # Pull out quoted tokens if present, else use raw value as-is
    quoted = re.findall(r'"([^"]*)"', raw_value)
    if quoted:
        return " ".join(quoted)
    return raw_value


def rule_identity(rule):
    """
    Normalized 5-tuple identity used for diffing and duplicate detection.
    Deliberately excludes rule id and name, since those can differ
    between two rules that are functionally identical.
    """
    return (
        rule["srcintf"].strip().lower(),
        rule["dstintf"].strip().lower(),
        rule["srcaddr"].strip().lower(),
        rule["dstaddr"].strip().lower(),
        rule["action"].strip().lower(),
        rule["service"].strip().lower(),
    )
