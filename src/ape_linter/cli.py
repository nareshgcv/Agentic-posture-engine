"""
Main CLI Entrypoint for APE scanner (ape init / ape scan / ape fix).
"""

import argparse
import json
import os
import sys
from typing import Any, Dict, List

from ape_linter.core import Capability, SecurityViolation
from ape_linter.discovery import analyze_path, discover_repo_files
from ape_linter.fixer import apply_auto_fixes
from ape_linter.init_wizard import run_init_wizard
from ape_linter.policy import load_policy
from ape_linter.reporters.json_reporter import generate_json
from ape_linter.reporters.markdown import generate_markdown
from ape_linter.reporters.sarif import generate_sarif


def compute_delta(
    base_v: List[SecurityViolation],
    head_v: List[SecurityViolation],
    base_c: List[Capability],
    head_c: List[Capability],
) -> Dict[str, Any]:
    base_v_keys = {
        (v.rule_id, v.agent, v.tool) for v in base_v if not v.suppressed
    }
    new_violations = [
        v
        for v in head_v
        if not v.suppressed and (v.rule_id, v.agent, v.tool) not in base_v_keys
    ]

    base_c_keys = {(c.agent, c.cap_type, c.scope) for c in base_c}
    new_capabilities = [
        c
        for c in head_c
        if (c.agent, c.cap_type, c.scope) not in base_c_keys
    ]

    return {
        "new_violations": new_violations,
        "new_capabilities": new_capabilities,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Agentic Posture Engine (APE) Static Scanner & Auto-Fixer"
    )
    subparsers = parser.add_subparsers(dest="command", help="APE Subcommands")

    # Command 1: ape init
    init_parser = subparsers.add_parser(
        "init", help="Initialize APE policy and setup local pre-commit hooks"
    )

    # Command 2 & 3: ape check / ape scan / default
    scan_parser = subparsers.add_parser(
        "scan", help="Scan files or repository for agent security risks"
    )
    scan_parser.add_argument(
        "target",
        nargs="?",
        default=".",
        help="Path to file or directory to scan",
    )
    scan_parser.add_argument(
        "--base",
        help="Path to base version of file for PR diff capability analysis",
        default=None,
    )
    scan_parser.add_argument(
        "--policy", help="Path to custom policy YAML file", default=None
    )
    scan_parser.add_argument(
        "--fix",
        action="store_true",
        help="Automatically fix fixable violations in-place",
    )
    scan_parser.add_argument(
        "--output-json", help="Path to write JSON output dump", default=None
    )
    scan_parser.add_argument(
        "--output-markdown",
        help="Path to write PR Markdown comment",
        default=None,
    )
    scan_parser.add_argument(
        "--output-sarif", help="Path to write SARIF JSON report", default=None
    )

    # Fallback positioning for backward compatibility (e.g. ape file.yaml)
    parser.add_argument("file", nargs="?", default=None, help=argparse.SUPPRESS)
    parser.add_argument(
        "--fix",
        action="store_true",
        dest="global_fix",
        help=argparse.SUPPRESS,
    )

    args = parser.parse_args()

    if args.command == "init":
        run_init_wizard()
        sys.exit(0)

    target_path = getattr(args, "target", None) or args.file or "."
    should_fix = getattr(args, "fix", False) or getattr(args, "global_fix", False)

    policy = load_policy(getattr(args, "policy", None))

    # Auto-discover if directory passed
    files_to_scan = []
    if os.path.isdir(target_path):
        files_to_scan = discover_repo_files(target_path)
    else:
        files_to_scan = [target_path]

    all_violations: List[SecurityViolation] = []
    all_capabilities: List[Capability] = []

    for file_p in files_to_scan:
        v_list, c_list = analyze_path(file_p, policy)

        if should_fix:
            fixed_cnt = apply_auto_fixes(file_p, v_list)
            if fixed_cnt > 0:
                print(f"🔧 Auto-fixed {fixed_cnt} violation(s) in {file_p}")
                # Re-scan file after fix
                v_list, c_list = analyze_path(file_p, policy)

        all_violations.extend(v_list)
        all_capabilities.extend(c_list)

    delta = None
    if getattr(args, "base", None):
        base_violations, base_capabilities = analyze_path(args.base, policy)
        delta = compute_delta(
            base_violations,
            all_violations,
            base_capabilities,
            all_capabilities,
        )

    summary_md = generate_markdown(all_violations, all_capabilities, delta)
    print(summary_md)

    if getattr(args, "output_markdown", None):
        with open(args.output_markdown, "w", encoding="utf-8") as f:
            f.write(summary_md)

    if getattr(args, "output_sarif", None):
        sarif_data = generate_sarif(all_violations, target_path)
        with open(args.output_sarif, "w", encoding="utf-8") as f:
            json.dump(sarif_data, f, indent=2)

    if getattr(args, "output_json", None):
        json_payload = generate_json(
            target_path, all_violations, all_capabilities, delta
        )
        with open(args.output_json, "w", encoding="utf-8") as f:
            json.dump(json_payload, f, indent=2)

    blocking = [
        v
        for v in all_violations
        if v.severity in {"CRITICAL", "HIGH"} and not v.suppressed
    ]
    sys.exit(1 if blocking else 0)


if __name__ == "__main__":
    main()
