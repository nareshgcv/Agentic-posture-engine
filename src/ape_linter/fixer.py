"""
Auto-Remediation Engine for APE security violations.
Modifies target files in-place while preserving comments/formatting, and provides unified diff generation for dry-runs.
"""
import difflib
import json
import os
import re
from typing import List, Tuple

try:
    from ruamel.yaml import YAML

    RUAMEL_AVAILABLE = True
except ImportError:
    import yaml

    RUAMEL_AVAILABLE = False

from ape_linter.core import SecurityViolation


def generate_diff(file_path: str, original: str, modified: str) -> str:
    """Generates a unified diff string comparing original vs auto-fixed file contents."""
    diff_lines = difflib.unified_diff(
        original.splitlines(keepends=True),
        modified.splitlines(keepends=True),
        fromfile=f"a/{file_path}",
        tofile=f"b/{file_path}",
    )
    return "".join(diff_lines)


def apply_auto_fixes(
    file_path: str, violations: List[SecurityViolation], dry_run: bool = False
) -> Tuple[int, str]:
    """
    Applies auto-fixes for fixable violations in file_path.
    Returns a tuple of (fixed_count, unified_diff_string).
    If dry_run is True, target files are not modified on disk.
    """
    fixable = [
        v for v in violations if v.fixable and not v.suppressed and v.file == file_path
    ]
    if not fixable:
        return 0, ""

    fixed_count = 0
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            raw_content = f.read()

        modified_content = raw_content

        # Route 1: Instruction Prompts Auto-Fix
        if file_path.endswith(
            (".prompt", ".instructions.md", ".cursorrules", ".clauderules")
        ):
            for v in fixable:
                if v.rule_id == "APE-101":
                    pattern = r"\b(bypass|ignore|override)\b[\s\S]*?\b(security|guardrails|safety|permissions?)\b"
                    modified_content = re.sub(
                        pattern, "", modified_content, flags=re.IGNORECASE
                    )
                    fixed_count += 1
                elif v.rule_id == "APE-103":
                    pattern = r"\bdo\s+not\s+ask\s+for\b[\s\S]*?\b(approval|confirmation|human)\b"
                    modified_content = re.sub(
                        pattern, "", modified_content, flags=re.IGNORECASE
                    )
                    fixed_count += 1

        # Route 2: Structured Configurations Auto-Fix (YAML / JSON)
        elif file_path.endswith((".yaml", ".yml", ".json")):
            if file_path.endswith(".json"):
                try:
                    data = json.loads(raw_content)
                except Exception:
                    return 0, ""
            else:
                if RUAMEL_AVAILABLE:
                    yaml_parser = YAML()
                    yaml_parser.preserve_quotes = True
                    yaml_parser.indent(mapping=2, sequence=4, offset=2)
                    data = yaml_parser.load(raw_content)
                else:
                    data = yaml.safe_load(raw_content) or {}

            if not isinstance(data, dict):
                return 0, ""

            modified_flag = False
            for v in fixable:
                target_agent = v.agent
                target_tool = v.tool

                # Fix APE-005: Unbounded max steps
                if (
                    v.rule_id == "APE-005"
                    and "agents" in data
                    and isinstance(data["agents"], dict)
                ):
                    if target_agent in data["agents"] and isinstance(
                        data["agents"][target_agent], dict
                    ):
                        data["agents"][target_agent]["max_steps"] = 15
                        fixed_count += 1
                        modified_flag = True

                # Tool specific fixes
                if "agents" in data and isinstance(data["agents"], dict):
                    agent_obj = data["agents"].get(target_agent, {})
                    if isinstance(agent_obj, dict):
                        tools = agent_obj.get("tools", [])
                        if isinstance(tools, list):
                            for tool in tools:
                                if (
                                    isinstance(tool, dict)
                                    and tool.get("name") == target_tool
                                ):
                                    if v.rule_id in {"APE-001", "APE-006"}:
                                        tool["require_human_approval"] = True
                                        fixed_count += 1
                                        modified_flag = True
                                    elif v.rule_id == "APE-002":
                                        tool["sandboxed"] = True
                                        fixed_count += 1
                                        modified_flag = True
                                    elif v.rule_id == "APE-003":
                                        tool["max_limit"] = 500
                                        fixed_count += 1
                                        modified_flag = True

            if modified_flag:
                from io import StringIO

                stream = StringIO()
                if file_path.endswith(".json"):
                    json.dump(data, stream, indent=2)
                elif RUAMEL_AVAILABLE:
                    yaml_parser.dump(data, stream)
                else:
                    yaml.dump(
                        data, stream, default_flow_style=False, sort_keys=False
                    )
                modified_content = stream.getvalue()

        # Compute diff and save if not dry run
        diff_str = ""
        if modified_content != raw_content:
            diff_str = generate_diff(file_path, raw_content, modified_content)
            if not dry_run:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(modified_content)

        return fixed_count, diff_str

    except Exception as e:
        print(f"Error applying auto-fix on {file_path}: {e}")

    return 0, "”
