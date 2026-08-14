# Agentic Posture Engine (APE)
Static linter and PR capability-delta analyzer for AI agent configurations, Model Context Protocol (MCP) servers, `.cursorrules`, and source code tool bindings.

APE scans agent definitions, instruction files, and source code tool execution points to enforce safety guardrails, detect privilege escalation, and compute permission deltas across pull requests—100% offline and air-gapped.

---

## Key Features

* **Config & Instruction Coverage:** Scans structured configs (`.mcp/config.json`, CrewAI, AutoGen) alongside prompt instruction files (`.cursorrules`, `.clauderules`, system prompts).
* **AST Code Scanning:** Detects unconstrained shell and dynamic execution calls in Python (`.py`) and JavaScript/TypeScript (`.js`, `.ts`).
* **PR Capability Delta Analysis:** Calculates permission and reachability diffs between a PR branch and base branch (`--base`).
* **Offline-First:** Executable inner-loop tool with zero reliance on external LLM APIs.
* **Multi-Format Output:** Supports CLI Terminal output, raw JSON, SARIF v2.1.0 (for GitHub Code Scanning), and PR Markdown reports.

---

## Installation

```bash
https://github.com/nareshgcv/Agentic-posture-engine.git
cd agentic-posture-engine
pip install -r requirements.txt

CLI Usage
Basic Scan
Scan a single configuration, prompt, or source code file:

python ape_linter.py agent_config.yml

PR Branch Capability Diff
Compare a PR branch file against its base branch equivalent to detect newly granted permissions:
python ape_linter.py agent_config.yml --base base_agent_config.yml

Output Formats


# Output SARIF for GitHub Security Tab and JSON for scripting
python ape_linter.py .mcp/config.json \
  --policy .ape-policy.yml \
  --output-sarif ape_results.sarif \
  --output-json ape_dump.json \
  --output-markdown ape_report.md

GitHub Action Integration
Add APE to your repository as a composite action inside .github/workflows/ape-posture.yml:

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

      - name: Run APE Linter
        uses: ./
        with:
          config_file: "agent_config.yml"
          policy_file: ".ape-policy.yml"
          sarif_output: "ape_results.sarif"
          markdown_output: "ape_report.md”

Default Security RulesRuleID SeverityScope Description
APE-001 CRITICAL ConfigDestructive tools (exec_shell, file_write) missing require_human_approval.
APE-002 CRITICAL ConfigShell tool execution is not marked sandboxed: true.
APE-003 HIGH ConfigFinancial/Payout tool lacking max_limit parameter.
APE-004 HIGH ConfigDatabase write tool lacking allowed_tables whitelist or read_only flag.

APE-005 HIGH ConfigAgent missing bounded max_steps iteration limits.

APE-006 CRITICAL ConfigSub-agent spawning tool lacks human approval flag.

APE-101 CRITICAL PromptInstruction explicitly waives or overrides security guardrails.

APE-102 HIGH PromptPrompt grants unconstrained shell or terminal execution authority.
APE-201 CRITICAL ASTDynamic Python shell call (os.system, subprocess.run, eval).
APE-202 CRITICAL ASTCustomizing Policy (.ape-policy.yml)
Override default rule categories and framework aliases by providing a custom policy file

destructive_tools:
  - "custom_db_drop"
  - "wipe_s3_bucket"

financial_tools:
  - "wire_transfer"

field_aliases:
  human_approval:
    - "require_approval"
    - "needs_human_signoff”

Suppressing Findings
Suppress rules locally by adding an inline rule comment or configuration key:

# In YAML/JSON agent configs:
ape_ignore:
  - "APE-005”
