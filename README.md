# 🦍 Agentic Posture Engine (APE)

**Static Linter, Auto-Fixer, and PR Capability-Delta Analyzer for AI Agents**

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://www.python.org/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/nareshgcv/Agentic-posture-engine/pulls)

> Static security linter, auto-fixer, and PR capability-delta analyzer for AI agent configurations, Model Context Protocol (MCP) servers, prompt instructions (`.cursorrules`), and source code tool bindings — **100% offline and air-gapped**.

---

## Why APE?

Traditional static analysis tools (SonarQube, Bandit, etc.) are blind to **Agentic Risks**.

APE detects what they miss:
- Missing Human-in-the-Loop approvals
- Unsandboxed execution tools
- Unconstrained agent loops
- Dangerous prompt overrides
- Privilege escalation in agent configs

---

## Quick Start

```bash
pip install agentic-posture-engine

Scan your project:

ape scan .

Apply automatic fixes:

ape fix .

Preview fixes without writing to disk:

ape fix . --diff

Run PR capability-delta analysis:

Bash
ape scan . --base main

Run PR capability-delta analysis against a base branch:

ape scan . --base main



## Supported Frameworks & Formats

| Type                      | Supported                                              |
|---------------------------|--------------------------------------------------------|
| **MCP**                   | `mcpServers` / `mcp_servers` configs                   |
| **CrewAI**                | YAML agent definitions                                 |
| **AutoGen**               | Agent configs with `llm_config`, `human_input_mode`    |
| **LangChain / LangGraph** | Nodes, graphs, agent schemas                           |
| **IDE Rules**             | `.cursorrules`, `.clauderules`, `.windsurfrules`, `.clinerules` |
| **Source Code**           | Python (`.py`) and JavaScript/TypeScript (`.js`, `.ts`, `.jsx`, `.tsx`) |

## Key Features

| Feature                        | Description                                                                 |
|--------------------------------|-----------------------------------------------------------------------------|
| **Config & Instruction Scanning** | Detects risky tools and missing guardrails in agent configs and prompt files |
| **AST Code Scanning**          | Finds unconstrained `os.system`, `subprocess`, `eval`, `child_process`, etc. |
| **PR Capability Delta**        | Shows what new permissions a pull request introduces                        |
| **Preservative Auto-Fix**      | Safely updates YAML/JSON while keeping comments and formatting              |
| **Multiple Report Formats**    | CLI, JSON, SARIF (GitHub Code Scanning), and Markdown                       |
| **100% Offline**               | No external LLM or cloud dependency                                         |

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
