"""
Core data models and helper functions for APE linter.
"""

import re
from typing import Any, Dict, List, Optional


class SecurityViolation:

    def __init__(
        self,
        rule_id: str,
        severity: str,
        file: str,
        line: int,
        agent: str,
        tool: str,
        message: str,
        remediation: str,
        suppressed: bool = False,
        fixable: bool = False,
    ):
        self.rule_id = rule_id
        self.severity = severity  # CRITICAL, HIGH, MEDIUM, LOW
        self.file = file
        self.line = line
        self.agent = agent
        self.tool = tool
        self.message = message
        self.remediation = remediation
        self.suppressed = suppressed
        self.fixable = fixable

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "file": self.file,
            "line": self.line,
            "agent": self.agent,
            "tool": self.tool,
            "message": self.message,
            "remediation": self.remediation,
            "suppressed": self.suppressed,
            "fixable": self.fixable,
        }


class Capability:

    def __init__(
        self, agent: str, cap_type: str, scope: str, file: str, line: int
    ):
        self.agent = agent
        self.cap_type = cap_type
        self.scope = scope
        self.file = file
        self.line = line

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent": self.agent,
            "type": self.cap_type,
            "scope": self.scope,
            "file": self.file,
            "line": self.line,
        }


def find_line_number(content: str, pattern: str) -> int:
    """Finds the 1-based line number for a substring or pattern in raw file content."""
    lines = content.splitlines()
    for idx, line in enumerate(lines, start=1):
        if pattern.lower() in line.lower():
            return idx
    return 1


def check_inline_suppression(
    raw_content: str, line_no: int, rule_id: str
) -> bool:
    """Checks if a developer added an inline suppression comment on or preceding a line.

    Supports:
      # ape:disable APE-001
      // ape:ignore APE-002
      <!-- ape:suppress ALL -->
    """
    lines = raw_content.splitlines()
    if not lines or line_no > len(lines):
        return False

    target_lines = []
    if line_no > 1:
        target_lines.append(lines[line_no - 2])  # Preceding line
    target_lines.append(lines[line_no - 1])  # Current line

    pattern = (
        r"(?:#|//|<!--|\*)\s*ape:(?:disable|ignore|suppress)\s+([A-Z0-9-,_ ]+)"
    )
    for l in target_lines:
        match = re.search(pattern, l, re.IGNORECASE)
        if match:
            rules_str = match.group(1).strip()
            ignored_rules = [
                r.strip().upper() for r in re.split(r"[, ]+", rules_str)
            ]
            if rule_id.upper() in ignored_rules or "ALL" in ignored_rules:
                return True
    return False


def resolve_field(
    data: Dict[str, Any],
    field_key: str,
    aliases_map: Dict[str, List[str]],
    default: Any = None,
) -> Any:
    aliases = aliases_map.get(field_key, [field_key])
    for alias in aliases:
        if alias in data:
            return data[alias]
    return default


def is_suppressed(
    rule_id: str,
    context: Dict[str, Any],
    aliases_map: Dict[str, List[str]],
    raw_content: Optional[str] = None,
    line_no: int = 1,
) -> bool:
    if raw_content and check_inline_suppression(raw_content, line_no, rule_id):
        return True

    ignored = resolve_field(context, "ignore_rules", aliases_map, [])
    if isinstance(ignored, str):
        ignored = [ignored]
    return rule_id in ignored or "ALL" in ignored

def compute_blast_radius(
    capabilities: List[Capability], violations: List[SecurityViolation]
) -> Dict[str, Any]:
    """Calculates exposure scope and blast radius based on granted capabilities."""
    impact_zones = set()
    risk_score = "LOW"

    for cap in capabilities:
        c_type = cap.cap_type.lower()
        if "shell" in c_type or "exec" in c_type:
            impact_zones.add("Host System / OS Infrastructure")
            risk_score = "CRITICAL"
        elif "stripe" in c_type or "payout" in c_type or "financial" in c_type:
            impact_zones.add("Financial & Payment Services")
            if risk_score != "CRITICAL":
                risk_score = "HIGH"
        elif "sql" in c_type or "db" in c_type:
            impact_zones.add("Data Store / Primary Database")
            if risk_score not in {"CRITICAL", "HIGH"}:
                risk_score = "MEDIUM"

    return {
        "level": risk_score,
        "impact_zones": list(impact_zones)
        if impact_zones
        else ["Isolated Workspace"],
    }
