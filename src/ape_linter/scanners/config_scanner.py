"""
Structured & Markdown configuration scanner.
Supports JSON, YAML, MCP server configs, AutoGen, CrewAI, LangChain, LangGraph,
Windsurf (.windsurfrules), and Cline (.clinerules).
"""
import json
import re
from typing import Any, Dict, List, Tuple
import yaml

from ape_linter.core import (
    Capability,
    SecurityViolation,
    find_line_number,
    is_suppressed,
    resolve_field,
)

SECRET_REGEX = re.compile(
    r"("
    r"sk-proj-[A-Za-z0-9_\-]{40,}"        # Modern OpenAI Project Keys
    r"|sk-ant-[A-Za-z0-9_\-]{40,}"       # Anthropic API Keys
    r"|github_pat_[A-Za-z0-9_]{22,}"    # GitHub Fine-Grained PATs
    r"|AIza[0-9A-Za-z-_]{35}"           # Google API Keys
    r"|xox[b-aprs]-[0-9A-Za-z-]{10,}"   # Slack Tokens
    r"|sk-[A-Za-z0-9]{32,}"              # Legacy OpenAI / Generic Keys
    r"|AKIA[0-9A-Z]{16}"                # AWS Access Key ID
    r")",
    re.IGNORECASE,
)


def parse_markdown_frontmatter(raw_content: str) -> Tuple[Dict[str, Any], str]:
    """Extracts YAML frontmatter from Markdown rule files (Cline/Windsurf)."""
    frontmatter = {}
    content = raw_content
    
    if raw_content.startswith("---"):
        parts = raw_content.split("---", 2)
        if len(parts) >= 3:
            try:
                parsed = yaml.safe_load(parts[1])
                if isinstance(parsed, dict):
                    frontmatter = parsed
                content = parts[2]
            except Exception:
                pass
    return frontmatter, content


def extract_all_secrets_and_env(data: Any, raw_content: str) -> List[Tuple[str, str, int]]:
    """Recursively walks dictionary trees and raw content to find secrets."""
    results = []

    def _walk(node: Any, path: str = ""):
        if isinstance(node, dict):
            for k, v in node.items():
                current_path = f"{path}.{k}" if path else k
                if isinstance(v, str):
                    if SECRET_REGEX.search(v):
                        line_no = find_line_number(raw_content, v)
                        results.append((current_path, v, line_no))
                else:
                    _walk(v, current_path)
        elif isinstance(node, list):
            for idx, item in enumerate(node):
                _walk(item, f"{path}[{idx}]")

    if isinstance(data, (dict, list)):
        _walk(data)

    # Secondary raw text scan for plain text secrets (Markdown, unparsed lines)
    for match in SECRET_REGEX.finditer(raw_content):
        secret_str = match.group(0)
        line_no = find_line_number(raw_content, secret_str)
        if not any(s[1] == secret_str for s in results):
            results.append(("raw_text", secret_str, line_no))

    return results


def normalize_agents(data: Dict[str, Any], raw_content: str = "") -> Dict[str, Dict[str, Any]]:
    """
    Normalizes framework-specific schemas into a uniform dictionary of agents and tools.
    Supports MCP, AutoGen, CrewAI, LangChain, LangGraph, Windsurf, and Cline.
    """
    agents = {}

    if isinstance(data, dict):
        # 1. Standard Top-Level "agents" key
        if "agents" in data:
            if isinstance(data["agents"], dict):
                for agent_id, agent_item in data["agents"].items():
                    if isinstance(agent_item, dict):
                        name = agent_item.get("name") or agent_item.get("role") or agent_id
                        agents[name] = agent_item
            elif isinstance(data["agents"], list):
                for idx, agent_item in enumerate(data["agents"]):
                    if isinstance(agent_item, dict):
                        name = agent_item.get("name") or agent_item.get("role") or f"Agent_{idx}"
                        agents[name] = agent_item

        # 2. MCP Server Configurations (mcpServers or cline_mcp_settings)
        mcp_data = data.get("mcpServers") or data.get("mcp_servers")
        if isinstance(mcp_data, dict):
            for server_name, server_cfg in mcp_data.items():
                if isinstance(server_cfg, dict):
                    tools = server_cfg.get("tools", [])
                    agents[server_name] = {
                        "name": server_name,
                        "tools": tools if isinstance(tools, (list, dict)) else [],
                        "sandboxed": server_cfg.get("sandboxed", False),
                        "env": server_cfg.get("env", {}),
                    }

        # 3. AutoGen Configs
        if any(k in data for k in ("config_list", "llm_config", "human_input_mode")):
            agent_name = data.get("name") or "AutoGenAgent"
            tools = data.get("tools") or data.get("function_map") or []
            agents[agent_name] = {
                "name": agent_name,
                "tools": tools,
                "max_consecutive_auto_reply": data.get("max_consecutive_auto_reply"),
                "max_steps": data.get("max_consecutive_auto_reply") or data.get("max_steps"),
                "human_input_mode": data.get("human_input_mode"),
                "env": data.get("env", {}),
            }

        # 4. LangChain / LangGraph Node & Agent Schemas
        if any(k in data for k in ("nodes", "graphs", "_type")):
            nodes = data.get("nodes", {})
            if isinstance(nodes, dict):
                for node_name, node_cfg in nodes.items():
                    if isinstance(node_cfg, dict):
                        agents[node_name] = node_cfg
            else:
                agent_name = data.get("name") or data.get("_type") or "LangChainAgent"
                agents[agent_name] = data

        # 5. Windsurf / Cline Rules Configuration
        if any(k in data for k in ("windsurf", "cline", "tools_allowed", "rules")):
            rule_name = data.get("name") or "IDERuleAgent"
            tools = data.get("tools") or data.get("tools_allowed") or []
            agents[rule_name] = {
                "name": rule_name,
                "tools": tools,
                "sandboxed": data.get("sandboxed", False),
                "max_steps": data.get("max_steps"),
            }

        # 6. CrewAI YAML Schema
        if not agents:
            for agent_id, agent_item in data.items():
                if isinstance(agent_item, dict) and ("role" in agent_item or "goal" in agent_item):
                    name = agent_item.get("name") or agent_id
                    agents[name] = agent_item

        # 7. Fallback Root Object
        if not agents and any(k in data for k in ("name", "role", "tools")):
            name = data.get("name") or data.get("role") or "DefaultAgent"
            agents = {name: data}

    # 8. Text heuristic fallback for unstructured Windsurf (.windsurfrules) and Cline (.clinerules)
    if not agents and raw_content:
        detected_tools = []
        for tool_keyword in ["bash", "terminal", "exec_shell", "cmd", "scrape", "sql"]:
            if re.search(r"\b" + tool_keyword + r"\b", raw_content, re.IGNORECASE):
                detected_tools.append({"name": tool_keyword})
        
        if detected_tools:
            agents["IDERuleAgent"] = {
                "name": "IDERuleAgent",
                "tools": detected_tools,
                "sandboxed": False,
            }

    return agents


def scan_structured_config(
    file_path: str, raw_content: str, policy: Dict[str, Any]
) -> Tuple[List[SecurityViolation], List[Capability]]:
    violations = []
    capabilities = []

    if not raw_content or not raw_content.strip():
        return violations, capabilities

    data = {}
    is_markdown_rule = file_path.endswith((".windsurfrules", ".clinerules", ".md"))

    if is_markdown_rule:
        frontmatter, _ = parse_markdown_frontmatter(raw_content)
        data = frontmatter
    else:
        try:
            if file_path.endswith(".json"):
                try:
                    data = json.loads(raw_content)
                except json.JSONDecodeError:
                    data = yaml.safe_load(raw_content)
            else:
                data = yaml.safe_load(raw_content)
        except Exception as e:
            print(f"Warning: Failed to parse configuration in {file_path}: {e}")

    if not isinstance(data, dict):
        data = {}

    agents = normalize_agents(data, raw_content=raw_content)
    aliases = policy.get("field_aliases", {})
    destructive_tools = policy.get("destructive_tools", set())
    spawn_tools = policy.get("spawn_tools", set())
    financial_tools = policy.get("financial_tools", set())
    network_tools = policy.get("network_tools", set())

    # 1. Comprehensive Secret Scanning (APE-008)
    secrets_found = extract_all_secrets_and_env(data, raw_content)
    for key_path, secret_val, secret_line in secrets_found:
        suppressed = is_suppressed("APE-008", {}, aliases, raw_content, secret_line)
        violations.append(
            SecurityViolation(
                rule_id="APE-008",
                severity="CRITICAL",
                file=file_path,
                line=secret_line,
                agent="global_config",
                tool="env_config",
                message=f"Hardcoded secret token detected in field/content path '{key_path}'.",
                remediation="Extract credentials to environment variables or secret vaults.",
                suppressed=suppressed,
                fixable=False,
            )
        )

    # 2. Scan normalized agent definitions
    for agent_name, agent_cfg in agents.items():
        if not isinstance(agent_cfg, dict):
            continue

        agent_line = find_line_number(raw_content, str(agent_name))

        # APE-005: Unbounded execution step limit
        max_steps = resolve_field(agent_cfg, "max_steps", aliases)
        if max_steps is None or (
            isinstance(max_steps, (int, float)) and max_steps <= 0
        ):
            human_mode = str(agent_cfg.get("human_input_mode", "")).upper()
            if human_mode != "NEVER":
                suppressed = is_suppressed(
                    "APE-005", agent_cfg, aliases, raw_content=raw_content, line_no=agent_line
                )
                violations.append(
                    SecurityViolation(
                        rule_id="APE-005",
                        severity="HIGH",
                        file=file_path,
                        line=agent_line,
                        agent=str(agent_name),
                        tool="agent_runtime",
                        message=f"Agent '{agent_name}' lacks a bounded 'max_steps' execution limit.",
                        remediation="Define a positive integer for 'max_steps' (e.g., max_steps: 15).",
                        suppressed=suppressed,
                        fixable=True,
                    )
                )

        # Normalize tools structure
        tools = agent_cfg.get("tools", [])
        if isinstance(tools, dict):
            tools = [
                {"name": k, **v} for k, v in tools.items() if isinstance(v, dict)
            ]
        elif isinstance(tools, list):
            normalized_tools = []
            for t in tools:
                if isinstance(t, str):
                    normalized_tools.append({"name": t})
                elif isinstance(t, dict):
                    normalized_tools.append(t)
            tools = normalized_tools

        for tool in tools:
            if not isinstance(tool, dict):
                continue

            tool_name = str(tool.get("name") or tool.get("function") or "unknown")
            tool_line = find_line_number(raw_content, tool_name)

            requires_hitl = resolve_field(tool, "human_approval", aliases, False)
            read_only = resolve_field(tool, "read_only", aliases, False)
            sandboxed = resolve_field(
                tool, "sandboxed", aliases, False
            ) or resolve_field(agent_cfg, "sandboxed", aliases, False)
            max_limit = resolve_field(tool, "max_limit", aliases, None)
            allowed_tables = resolve_field(tool, "allowed_tables", aliases, None)
            allowed_domains = resolve_field(tool, "allowed_domains", aliases, None)

            capabilities.append(
                Capability(
                    str(agent_name),
                    f"ToolAccess:{tool_name}",
                    "read-write" if not read_only else "read",
                    file_path,
                    tool_line,
                )
            )

            # APE-001: Destructive Tool missing HITL
            if tool_name in destructive_tools and not requires_hitl:
                suppressed = is_suppressed(
                    "APE-001", tool, aliases, raw_content, tool_line
                ) or is_suppressed("APE-001", agent_cfg, aliases)
                violations.append(
                    SecurityViolation(
                        rule_id="APE-001",
                        severity="CRITICAL",
                        file=file_path,
                        line=tool_line,
                        agent=str(agent_name),
                        tool=tool_name,
                        message=f"Destructive tool '{tool_name}' missing mandatory human approval flag.",
                        remediation=f"Set 'require_human_approval: true' for tool '{tool_name}'.",
                        suppressed=suppressed,
                        fixable=True,
                    )
                )

            # APE-002: Unsandboxed Shell Execution Tool
            if (
                tool_name in {"exec_shell", "bash", "terminal", "cmd", "code_interpreter"}
                and not sandboxed
            ):
                suppressed = is_suppressed(
                    "APE-002", tool, aliases, raw_content, tool_line
                ) or is_suppressed("APE-002", agent_cfg, aliases)
                violations.append(
                    SecurityViolation(
                        rule_id="APE-002",
                        severity="CRITICAL",
                        file=file_path,
                        line=tool_line,
                        agent=str(agent_name),
                        tool=tool_name,
                        message=f"System execution tool '{tool_name}' is not running in a sandboxed environment.",
                        remediation="Add 'sandboxed: true' or restrict container execution scope.",
                        suppressed=suppressed,
                        fixable=True,
                    )
                )

            # APE-003: Financial Tool missing max transaction threshold
            if tool_name in financial_tools and max_limit is None:
                suppressed = is_suppressed(
                    "APE-003", tool, aliases, raw_content, tool_line
                ) or is_suppressed("APE-003", agent_cfg, aliases)
                violations.append(
                    SecurityViolation(
                        rule_id="APE-003",
                        severity="HIGH",
                        file=file_path,
                        line=tool_line,
                        agent=str(agent_name),
                        tool=tool_name,
                        message=f"Financial tool '{tool_name}' missing max transaction limit ('max_limit').",
                        remediation="Define a maximum threshold (e.g., max_limit: 500).",
                        suppressed=suppressed,
                        fixable=True,
                    )
                )

            # APE-004: DB Write Tool missing table whitelist
            if "sql" in tool_name.lower() or "db_query" in tool_name.lower():
                if not read_only and not allowed_tables:
                    suppressed = is_suppressed(
                        "APE-004", tool, aliases, raw_content, tool_line
                    ) or is_suppressed("APE-004", agent_cfg, aliases)
                    violations.append(
                        SecurityViolation(
                            rule_id="APE-004",
                            severity="HIGH",
                            file=file_path,
                            line=tool_line,
                            agent=str(agent_name),
                            tool=tool_name,
                            message=f"Database write tool '{tool_name}' lacks 'allowed_tables' scope whitelist.",
                            remediation="Define 'allowed_tables: [table_a, table_b]' or set 'read_only: true'.",
                            suppressed=suppressed,
                            fixable=True,
                        )
                    )

            # APE-006: Sub-agent Spawning without HITL
            if tool_name in spawn_tools or tool.get("can_spawn_agents", False):
                if not requires_hitl:
                    suppressed = is_suppressed(
                        "APE-006", tool, aliases, raw_content, tool_line
                    ) or is_suppressed("APE-006", agent_cfg, aliases)
                    violations.append(
                        SecurityViolation(
                            rule_id="APE-006",
                            severity="CRITICAL",
                            file=file_path,
                            line=tool_line,
                            agent=str(agent_name),
                            tool=tool_name,
                            message=f"Spawning tool '{tool_name}' can instantiate sub-agents without approval.",
                            remediation="Require approval or set 'require_human_approval: true'.",
                            suppressed=suppressed,
                            fixable=True,
                        )
                    )

            # APE-007: Unconstrained Network / Web Scrape Tool
            if tool_name in network_tools or "scrape" in tool_name or "fetch" in tool_name:
                if not allowed_domains:
                    suppressed = is_suppressed(
                        "APE-007", tool, aliases, raw_content, tool_line
                    ) or is_suppressed("APE-007", agent_cfg, aliases)
                    violations.append(
                        SecurityViolation(
                            rule_id="APE-007",
                            severity="MEDIUM",
                            file=file_path,
                            line=tool_line,
                            agent=str(agent_name),
                            tool=tool_name,
                            message=f"Network tool '{tool_name}' lacks 'allowed_domains' scope whitelist.",
                            remediation="Define 'allowed_domains: [api.example.com]' to bound outbound requests.",
                            suppressed=suppressed,
                            fixable=False,
                        )
                    )

    return violations, capabilities
                "sandboxed": server_cfg.get("sandboxed", False),
                "env": server_cfg.get("env", {}),
            }
    elif isinstance(data, dict) and (
        "name" in data or "role" in data or "tools" in data
    ):
        name = data.get("name") or data.get("role") or "DefaultAgent"
        agents = {name: data}
    return agents


def scan_structured_config(
    file_path: str, raw_content: str, policy: Dict[str, Any]
) -> Tuple[List[SecurityViolation], List[Capability]]:
    violations = []
    capabilities = []

    if not raw_content or not raw_content.strip():
        return violations, capabilities

    try:
        if file_path.endswith(".json"):
            try:
                data = json.loads(raw_content)
            except json.JSONDecodeError:
                data = yaml.safe_load(raw_content)
        else:
            data = yaml.safe_load(raw_content)
    except Exception as e:
        print(f"Warning: Failed to parse configuration in {file_path}: {e}")
        return violations, capabilities

    if not isinstance(data, dict):
        return violations, capabilities

    agents = normalize_agents(data)
    aliases = policy["field_aliases"]
    destructive_tools = policy["destructive_tools"]
    spawn_tools = policy["spawn_tools"]
    financial_tools = policy["financial_tools"]
    network_tools = policy.get("network_tools", set())

    for agent_name, agent_cfg in agents.items():
        if not isinstance(agent_cfg, dict):
            continue

        agent_line = find_line_number(raw_content, str(agent_name))

        # APE-005: Unbounded execution step limit
        max_steps = resolve_field(agent_cfg, "max_steps", aliases)
        if max_steps is None or (
            isinstance(max_steps, (int, float)) and max_steps <= 0
        ):
            suppressed = is_suppressed(
                "APE-005", agent_cfg, aliases, raw_content=raw_content, line_no=agent_line
            )
            violations.append(
                SecurityViolation(
                    rule_id="APE-005",
                    severity="HIGH",
                    file=file_path,
                    line=agent_line,
                    agent=str(agent_name),
                    tool="agent_runtime",
                    message=f"Agent '{agent_name}' lacks a bounded 'max_steps' execution limit.",
                    remediation="Define a positive integer for 'max_steps' (e.g., max_steps: 15).",
                    suppressed=suppressed,
                    fixable=True,
                )
            )

        # APE-008: Hardcoded Sensitive Credentials in Configuration
        env_vars = agent_cfg.get("env", {})
        if isinstance(env_vars, dict):
            for env_key, env_val in env_vars.items():
                if isinstance(env_val, str) and re.search(
                    r"(sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{20,}|akia[a-z0-9]{16})",
                    env_val,
                    re.IGNORECASE,
                ):
                    secret_line = find_line_number(raw_content, env_key)
                    suppressed = is_suppressed(
                        "APE-008", agent_cfg, aliases, raw_content, secret_line
                    )
                    violations.append(
                        SecurityViolation(
                            rule_id="APE-008",
                            severity="CRITICAL",
                            file=file_path,
                            line=secret_line,
                            agent=str(agent_name),
                            tool="env_config",
                            message=f"Hardcoded secret token detected in environment variable '{env_key}'.",
                            remediation="Extract credentials to environment variables or secret vaults.",
                            suppressed=suppressed,
                            fixable=False,
                        )
                    )

        tools = agent_cfg.get("tools", [])
        if isinstance(tools, dict):
            tools = [
                {"name": k, **v} for k, v in tools.items() if isinstance(v, dict)
            ]

        for tool in tools:
            if not isinstance(tool, dict):
                continue

            tool_name = str(tool.get("name", "unknown"))
            tool_line = find_line_number(raw_content, tool_name)

            requires_hitl = resolve_field(tool, "human_approval", aliases, False)
            read_only = resolve_field(tool, "read_only", aliases, False)
            sandboxed = resolve_field(
                tool, "sandboxed", aliases, False
            ) or resolve_field(agent_cfg, "sandboxed", aliases, False)
            max_limit = resolve_field(tool, "max_limit", aliases, None)
            allowed_tables = resolve_field(tool, "allowed_tables", aliases, None)
            allowed_domains = resolve_field(tool, "allowed_domains", aliases, None)

            capabilities.append(
                Capability(
                    str(agent_name),
                    f"ToolAccess:{tool_name}",
                    "read-write" if not read_only else "read",
                    file_path,
                    tool_line,
                )
            )

            # APE-001: Destructive Tool missing HITL
            if tool_name in destructive_tools and not requires_hitl:
                suppressed = is_suppressed(
                    "APE-001", tool, aliases, raw_content, tool_line
                ) or is_suppressed("APE-001", agent_cfg, aliases)
                violations.append(
                    SecurityViolation(
                        rule_id="APE-001",
                        severity="CRITICAL",
                        file=file_path,
                        line=tool_line,
                        agent=str(agent_name),
                        tool=tool_name,
                        message=f"Destructive tool '{tool_name}' missing mandatory human approval flag.",
                        remediation=f"Set 'require_human_approval: true' for tool '{tool_name}'.",
                        suppressed=suppressed,
                        fixable=True,
                    )
                )

            # APE-002: Unsandboxed Shell Execution Tool
            if (
                tool_name in {"exec_shell", "bash", "terminal", "cmd"}
                and not sandboxed
            ):
                suppressed = is_suppressed(
                    "APE-002", tool, aliases, raw_content, tool_line
                ) or is_suppressed("APE-002", agent_cfg, aliases)
                violations.append(
                    SecurityViolation(
                        rule_id="APE-002",
                        severity="CRITICAL",
                        file=file_path,
                        line=tool_line,
                        agent=str(agent_name),
                        tool=tool_name,
                        message=f"System execution tool '{tool_name}' is not running in a sandboxed environment.",
                        remediation="Add 'sandboxed: true' or restrict container execution scope.",
                        suppressed=suppressed,
                        fixable=True,
                    )
                )

            # APE-003: Financial Tool missing max transaction threshold
            if tool_name in financial_tools and max_limit is None:
                suppressed = is_suppressed(
                    "APE-003", tool, aliases, raw_content, tool_line
                ) or is_suppressed("APE-003", agent_cfg, aliases)
                violations.append(
                    SecurityViolation(
                        rule_id="APE-003",
                        severity="HIGH",
                        file=file_path,
                        line=tool_line,
                        agent=str(agent_name),
                        tool=tool_name,
                        message=f"Financial tool '{tool_name}' missing max transaction limit ('max_limit').",
                        remediation="Define a maximum threshold (e.g., max_limit: 500).",
                        suppressed=suppressed,
                        fixable=True,
                    )
                )

            # APE-004: DB Write Tool missing table whitelist
            if "sql" in tool_name.lower() or "db_query" in tool_name.lower():
                if not read_only and not allowed_tables:
                    suppressed = is_suppressed(
                        "APE-004", tool, aliases, raw_content, tool_line
                    ) or is_suppressed("APE-004", agent_cfg, aliases)
                    violations.append(
                        SecurityViolation(
                            rule_id="APE-004",
                            severity="HIGH",
                            file=file_path,
                            line=tool_line,
                            agent=str(agent_name),
                            tool=tool_name,
                            message=f"Database write tool '{tool_name}' lacks 'allowed_tables' scope whitelist.",
                            remediation="Define 'allowed_tables: [table_a, table_b]' or set 'read_only: true'.",
                            suppressed=suppressed,
                            fixable=True,
                        )
                    )

            # APE-006: Sub-agent Spawning without HITL
            if tool_name in spawn_tools or tool.get("can_spawn_agents", False):
                if not requires_hitl:
                    suppressed = is_suppressed(
                        "APE-006", tool, aliases, raw_content, tool_line
                    ) or is_suppressed("APE-006", agent_cfg, aliases)
                    violations.append(
                        SecurityViolation(
                            rule_id="APE-006",
                            severity="CRITICAL",
                            file=file_path,
                            line=tool_line,
                            agent=str(agent_name),
                            tool=tool_name,
                            message=f"Spawning tool '{tool_name}' can instantiate sub-agents without approval.",
                            remediation="Require approval or set 'require_human_approval: true'.",
                            suppressed=suppressed,
                            fixable=True,
                        )
                    )

            # APE-007: Unconstrained Network / Web Scrape Tool
            if tool_name in network_tools or "scrape" in tool_name or "fetch" in tool_name:
                if not allowed_domains:
                    suppressed = is_suppressed(
                        "APE-007", tool, aliases, raw_content, tool_line
                    ) or is_suppressed("APE-007", agent_cfg, aliases)
                    violations.append(
                        SecurityViolation(
                            rule_id="APE-007",
                            severity="MEDIUM",
                            file=file_path,
                            line=tool_line,
                            agent=str(agent_name),
                            tool=tool_name,
                            message=f"Network request tool '{tool_name}' lacks 'allowed_domains' scope whitelist.",
                            remediation="Define 'allowed_domains: [api.example.com]' to bound outbound requests.",
                            suppressed=suppressed,
                            fixable=False,
                        )
                    )

    return violations, capabilities
