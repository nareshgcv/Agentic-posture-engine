"""
Interactive initialization wizard (`ape init`).
Discovers project agent files, writes baseline policies, and sets up pre-commit hooks.
"""

import os
import sys
import yaml
from ape_linter.discovery import discover_repo_files


DEFAULT_PRE_COMMIT_HOOK = """# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: ape-check
        name: Agentic Posture Engine (APE) Scan
        entry: ape check
        language: python
        types_or: [yaml, json, python, javascript, markdown]
        pass_filenames: true
"""

DEFAULT_POLICY_YAML = """# .ape-policy.yml - Organization Agentic Security Policy
destructive_tools:
  - exec_shell
  - bash
  - execute_sql
  - delete_record
  - stripe_refund
  - file_write
  - terminal
  - cmd

spawn_tools:
  - spawn_agent
  - delegate_task
  - invoke_agent

financial_tools:
  - stripe_refund
  - bank_transfer
  - crypto_payout

field_aliases:
  human_approval:
    - require_human_approval
    - hitl
    - human_in_the_loop
  sandboxed:
    - sandboxed
    - containerized
"""


def run_init_wizard(target_dir: str = "."):
    print("🚀 Initializing Agentic Posture Engine (APE) for project...\n")

    # Step 1: Auto-discover files
    discovered = discover_repo_files(target_dir)
    print(f"🔍 Discovered {len(discovered)} agentic config/instruction files:")
    for f in discovered[:10]:
        print(f"  • {f}")
    if len(discovered) > 10:
        print(f"  ... and {len(discovered) - 10} more.")

    # Step 2: Create .ape-policy.yml
    policy_path = os.path.join(target_dir, ".ape-policy.yml")
    if not os.path.exists(policy_path):
        with open(policy_path, "w", encoding="utf-8") as f:
            f.write(DEFAULT_POLICY_YAML)
        print("\n✅ Created baseline organization policy: .ape-policy.yml")
    else:
        print("\nℹ️ Policy file .ape-policy.yml already exists.")

    # Step 3: Setup Pre-Commit Hooks
    pre_commit_path = os.path.join(target_dir, ".pre-commit-config.yaml")
    if not os.path.exists(pre_commit_path):
        with open(pre_commit_path, "w", encoding="utf-8") as f:
            f.write(DEFAULT_PRE_COMMIT_HOOK)
        print("✅ Created local pre-commit hook configuration: .pre-commit-config.yaml")
    else:
        print("ℹ️ Existing .pre-commit-config.yaml detected.")

    print("\n🎉 Setup Complete! Run 'ape scan .' to perform your first full security scan.")
