# Agentic Posture Engine (APE)

Static linter, auto-fixer, and PR capability-delta analyzer for AI agent configurations, Model Context Protocol (MCP) servers, prompt instructions (.cursorrules), and source code tool bindings.

APE scans agent definitions, instruction files, and source code tool execution points to enforce security guardrails, detect privilege escalation, and compute permission deltas across pull requests—100% offline and air-gapped.

**Key Features:**

**Config & Instruction Coverage:**
Scans structured configs (.mcp/config.json, CrewAI, AutoGen) alongside prompt instruction files (.cursorrules, .clauderules, .windsurfrules, .clinerules, system prompts).

**AST Code Scanning:** Detects unconstrained shell and dynamic execution calls in Python (.py) and JavaScript/TypeScript (.js, .ts, .jsx, .tsx).  

**PR Capability Delta Analysis:** Calculates permission and reachability diffs between a PR branch and base branch (--base).  

**Offline-First:** Executable inner-loop tool with zero reliance on external LLM APIs.

**Multi-Format Output:** Supports CLI Terminal output, raw JSON, SARIF v2.1.0 (for GitHub Code Scanning), and PR Markdown reports.

**Installation**

git clone https://github.com/your-org/agentic-posture-engine.git

cd agentic-posture-engine

pip install .

CLI Usage

Interactive Setup

Initialize policy files and set up local pre-commit hooks:

ape init

**Basic Scan**
Scan a single configuration, prompt, directory, or source code file:

ape scan agent_config.yml

**Auto-Remediation**
Automatically fix fixable security violations in-place:  

ape scan agent_config.yml --fix

**PR Branch Capability Diff**
Compare a PR branch file against its base branch equivalent to detect newly granted permissions:

ape scan agent_config.yml --base base_agent_config.yml

**Multi-Format Output Reports**

Output SARIF for the GitHub Security tab, JSON for scripting, and Markdown for PR comments:

ape scan .mcp/config.json \
  --policy .ape-policy.yml \
  --output-sarif ape_results.sarif \
  --output-json ape_dump.json \
  --output-markdown ape_report.md

**GitHub Action Integration**

Add APE to your repository as a workflow inside
.github/workflows/ape-posture.yml:

name: Agentic Security Posture Check
on:
  pull_request:
    paths:
      - '**/*mcp*.json'
      - '.cursorrules'
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


**Default Security Rules**
Rule ID   Severity    Scope   Description





**Customizing Policy**(.ape-policy.yml)
Override default rule categories and framework aliases by providing a custom policy file:

.ape-policy.yml

destructive_tools:
  - "custom_db_drop"
  - "wipe_s3_bucket"

spawn_tools:
  - "spawn_agent"
  - "delegate_task"

financial_tools:
  - "wire_transfer"
  - "crypto_payout"

field_aliases:
  human_approval:
    - "require_approval"
    - "needs_human_signoff"
  sandboxed:
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
