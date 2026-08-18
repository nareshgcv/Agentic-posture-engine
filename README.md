<div align="center">

# 🦍 Agentic Posture Engine (APE)
### Static Linter, Auto-Fixer, and PR Capability-Delta Analyzer for AI Agents

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg?style=flat-square)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg?style=flat-square)](https://www.python.org/downloads/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](CONTRIBUTING.md)

*Static security linter, auto-fixer, and PR capability-delta analyzer for AI agent configurations, Model Context Protocol (MCP) servers, prompt instructions (`.cursorrules`), and source code tool bindings.*

</div>

---

## ⚡ Overview

**Agentic Posture Engine (APE)** scans agent definitions, instruction files, and source code tool execution points to enforce security guardrails, detect privilege escalation, and compute permission deltas across pull requests—**100% offline and air-gapped**.

As enterprise teams adopt AI agents, `.cursorrules`, and MCP server tools, traditional static analysis tools (like SonarQube or Bandit) remain blind to **Agentic Risks**. APE checks what static analysis misses: unconstrained execution loops, missing Human-in-the-Loop approvals, unsandboxed execution tools, and defensive prompt overrides.

---

## ✨ Key Features

- 🧠 **Config & Instruction Coverage:** Scans structured configs (`.mcp/config.json`, CrewAI, AutoGen) alongside prompt instruction files (`.cursorrules`, `.clauderules`, `.windsurfrules`, `.clinerules`, system prompts) using paragraph-level context windows to prevent false positive negations.
- 🌳 **AST Code Scanning:** Detects unconstrained shell and dynamic execution calls directly in Python (`.py`) and JavaScript/TypeScript (`.js`, `.ts`, `.jsx`, `.tsx`) source code.
- 🔀 **PR Capability Delta Analysis:** Calculates permission and reachability diffs between a PR branch and a base branch (`--base`).
- 🔒 **100% Offline & Air-Gapped:** Inner-loop executable tool with zero reliance on external LLM APIs or cloud connections.
- 🔧 **Preservative Auto-Fixes (`ape fix`):** Safely updates non-compliant YAML/JSON files while preserving comments, inline notes, and formatting via `ruamel.yaml`.
- 📊 **Multi-Format Reporting:** Supports interactive CLI Terminal output, raw JSON, OASIS SARIF v1.0.0 (for GitHub Code Scanning), and PR Markdown summaries.

---

## 🚀 Installation & Quickstart

### Installation

Clone the repository and install locally:

```bash
git clone [https://github.com/nareshgcv/Agentic-posture-engine.git](https://github.com/nareshgcv/Agentic-posture-engine.git)

cd Agentic-posture-engine

pip install -e .

Basic Usage :-
Run a security scan across your codebase:

ape scan .

Run PR capability-delta analysis against a base branch:

ape scan . --base main

Automatically apply fixable remediations:

ape fix .

Preview changes before writing to disk (Unified Diff):

ape fix . --diff


📊 Sample CLI Output

🦍 APE Security Scan Results:

[CRITICAL] APE-101 (instruction_prompt)
  File: .cursorrules:14
  Agent: system_prompt
  Message: Instruction explicitly overrides or disables security guardrails.
  Remediation: Remove prompt directives that bypass security checks.

[HIGH] APE-001 (config)
  File: config/agents.yaml:28
  Agent: DatabaseAgent | Tool: execute_sql
  Message: Dangerous execution tool is missing mandatory human approval flag.
  Remediation: Set 'require_human_approval: true' in agent configuration.

✖ Found 2 violations (1 Critical, 1 High). Run 'ape fix .' to resolve 1 auto-fixable issue.



### Project structure

agentic-posture-engine/
├── .github/
│   └── workflows/
│       └── ape-posture.yml          # Optional: GitHub Actions PR scan workflow
├── src/
│   └── ape_linter/                  # Core Python package
│       ├── __init__.py              # Package exports & version
│       ├── cli.py                   # Main CLI entrypoint (init/scan/check/fix)
│       ├── core.py                  # SecurityViolation, Capability & Blast Radius models
│       ├── policy.py                # Policy loader, tool lists & aliases
│       ├── discovery.py             # File auto-discovery engine
│       ├── fixer.py                 # Auto-Remediation Engine (--fix)
│       ├── init_wizard.py           # Interactive onboarding wizard (ape init)
│       ├── scanners/                # Modular scanners
│       │   ├── __init__.py
│       │   ├── config_scanner.py    # MCP, YAML, JSON scanner
│       │   ├── instruction_scanner.py # .cursorrules & system prompts
│       │   └── ast_scanner.py       # Python AST & JS/TS scanner
│       └── reporters/               # Report generators
│           ├── __init__.py
│           ├── markdown.py          # PR Markdown & Blast Radius generator
│           ├── sarif.py             # SARIF v2.1.0 generator
│           └── json_reporter.py     # JSON output generator
|
│  
├── tests/                           Pytest suite
│   ├── conftest.py
│   ├── test_cli.py
│   ├── test_config_rules.py
│   ├── test_instruction_rules.py
│   ├── test_code_ast_rules.py
│   ├── test_fixer.py
│   
├── .ape-policy.yml                  # Default organization policy file
├── .pre-commit-hooks.yaml           # Local Git pre-commit hook manifest
├── action.yml                       # Reusable GitHub Action manifest
├── pyproject.toml                   # PEP 517 build config & binary entrypoint
├── README.md                        # Documentation & setup guide
└── LICENSE                         

### GitHub Action Integration

Add APE to your repository as a workflow inside .github/workflows/ape-posture.yml:



name: Agentic Security Posture Check

on:
  pull_request:
    paths:
      - '**/*mcp*.json'
      - '**/agent_config.yml'

jobs:
  ape-static-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.10'

      - name: Install APE
        run: pip install .

      - name: Run APE Linter
        run: |
          ape scan . \
            --policy .ape-policy.yml \
            --output-sarif ape_results.sarif \
            --output-markdown ape_report.md


## Default Security Rules

| Rule ID | Severity | Scope | Description |
| :--- | :--- | :--- | :--- |
| **APE-001** | `CRITICAL` | Config | Destructive tools (`exec_shell`, `file_write`, etc.) missing mandatory human approval flag (`require_human_approval`). |
| **APE-002** | `CRITICAL` | Config | System execution tool (`exec_shell`, `bash`, `terminal`, `cmd`) is not marked as sandboxed. |
| **APE-003** | `HIGH` | Config | Financial/Payout tool (`stripe_refund`, `bank_transfer`, etc.) missing maximum transaction limit (`max_limit`). |
| **APE-004** | `HIGH` | Config | Database write tool lacking an `allowed_tables` scope whitelist or `read_only` flag. |
| **APE-005** | `HIGH` | Config | Agent runtime missing a bounded `max_steps` execution limit. |
| **APE-006** | `CRITICAL` | Config | Sub-agent spawning tool (`spawn_agent`, `delegate_task`, etc.) lacks human approval flag. |
| **APE-101** | `CRITICAL` | Prompt | Prompt instruction explicitly waives or overrides security guardrails (`bypass security`, `ignore approval`). |
| **APE-102** | `HIGH` | Prompt | Unconstrained command/terminal execution permission granted in prompt instruction (`run any command`). |
| **APE-103** | `HIGH` | Prompt | Instruction explicitly waives human confirmation for sensitive tasks (`without human approval`). |
| **APE-104** | `MEDIUM` | Prompt | Broad file or data access directive granted in prompt instruction (`read all files`, `delete all data`). |
| **APE-201** | `CRITICAL` | AST (Py) | Dynamic Python shell execution call detected in code (`os.system`, `subprocess.run`, `eval`, `exec`). |
| **APE-202** | `CRITICAL` | AST (JS/TS) | Node.js `child_process` execution detected in JavaScript/TypeScript (`child_process.exec`, `spawn`). |
| **APE-203** | `HIGH` | AST (JS/TS) | Dynamic JavaScript `eval()` execution detected in code. |



###Customizing Policy(.ape-policy.yml)
Override default rule categories and framework aliases by providing a custom policy file:


# .ape-policy.yml - Custom Organization Agentic Security Policy
destructive_tools:
  - "custom_db_drop"
  - "wipe_s3_bucket"
  - "exec_shell"
  - "file_write"

spawn_tools:
  - "spawn_agent"
  - "delegate_task"
  - "invoke_agent"

financial_tools:
  - "wire_transfer"
  - "crypto_payout"
  - "stripe_refund"

field_aliases:
  human_approval:
    - "require_human_approval"
    - "hitl"
    - "human_in_the_loop"
    - "needs_human_signoff"
  sandboxed:
    - "sandboxed"
    - "containerized"

**Suppressing Findings**

suppress rules by adding inline comment markers or configuration keys:


In YAML/JSON Agent Configs

ape_ignore:
  - "APE-005"

In Prompts and Code

# ape:disable APE-201
os.system("ls -la")

javascript
// ape:ignore APE-203
eval("2 + 2");
