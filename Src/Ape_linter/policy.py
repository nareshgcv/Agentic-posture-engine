"""
Policy loader, default tool classifications, and field alias resolution.
"""
import os
from typing import Any, Dict, Optional, Set
import yaml

DEFAULT_DESTRUCTIVE_TOOLS: Set[str] = {
    "exec_shell",
    "bash",
    "execute_sql",
    "delete_record",
    "stripe_refund",
    "file_write",
    "terminal",
    "cmd",
    "drop_table",
}

DEFAULT_SPAWN_TOOLS: Set[str] = {
    "spawn_agent",
    "delegate_task",
    "invoke_agent",
    "create_subagent",
}

DEFAULT_FINANCIAL_TOOLS: Set[str] = {
    "stripe_refund",
    "bank_transfer",
    "crypto_payout",
    "charge_card",
    "issue_payout",
}

DEFAULT_NETWORK_TOOLS: Set[str] = {
    "fetch_url",
    "http_request",
    "web_scrape",
    "curl",
    "api_call",
}

DEFAULT_FIELD_ALIASES: Dict[str, list[str]] = {
    "human_approval": [
        "require_human_approval",
        "human_approval",
        "hitl",
        "human_in_the_loop",
        "approval_required",
        "admin_approval",
    ],
    "read_only": ["read_only", "readonly", "is_readonly"],
    "sandboxed": ["sandboxed", "is_sandboxed", "sandbox", "containerized"],
    "max_limit": [
        "max_limit",
        "limit",
        "amount_limit",
        "max_amount",
        "spending_limit",
    ],
    "allowed_tables": [
        "allowed_tables",
        "table_whitelist",
        "allowed_schemas",
        "tables",
    ],
    "allowed_domains": [
        "allowed_domains",
        "domain_whitelist",
        "allowed_hosts",
        "hosts",
    ],
    "max_steps": [
        "max_steps",
        "max_iterations",
        "max_iters",
        "step_limit",
        "max_consecutive_auto_reply",
    ],
    "ignore_rules": ["ape_ignore", "ignore_rules", "suppress", "skip_rules"],
}


def load_policy(policy_path: Optional[str]) -> Dict[str, Any]:
    policy = {
        "destructive_tools": DEFAULT_DESTRUCTIVE_TOOLS,
        "spawn_tools": DEFAULT_SPAWN_TOOLS,
        "financial_tools": DEFAULT_FINANCIAL_TOOLS,
        "network_tools": DEFAULT_NETWORK_TOOLS,
        "field_aliases": DEFAULT_FIELD_ALIASES,
    }

    if policy_path and os.path.exists(policy_path):
        try:
            with open(policy_path, "r", encoding="utf-8") as f:
                user_policy = yaml.safe_load(f) or {}
                if "destructive_tools" in user_policy:
                    policy["destructive_tools"] = set(user_policy["destructive_tools"])
                if "spawn_tools" in user_policy:
                    policy["spawn_tools"] = set(user_policy["spawn_tools"])
                if "financial_tools" in user_policy:
                    policy["financial_tools"] = set(user_policy["financial_tools"])
                if "network_tools" in user_policy:
                    policy["network_tools"] = set(user_policy["network_tools"])
                if "field_aliases" in user_policy:
                    policy["field_aliases"].update(user_policy["field_aliases"])
        except Exception as e:
            print(f"Warning: Could not parse policy file {policy_path}: {e}. Using defaults.")

    return policy
