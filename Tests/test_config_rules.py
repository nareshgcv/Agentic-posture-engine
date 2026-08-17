from unittest.mock import patch
import pytest

from ape_linter.core import Capability, SecurityViolation
from ape_linter.scanners.config_scanner import (
    normalize_agents,
    scan_structured_config,
)


# ==============================================================================
# Fixtures
# ==============================================================================


@pytest.fixture
def sample_policy():
    """Provides a standard policy dictionary for tests."""
    return {
        "field_aliases": {
            "max_steps": ["max_steps", "step_limit"],
            "human_approval": ["require_human_approval", "human_approval", "hitl"],
            "read_only": ["read_only", "readonly"],
            "sandboxed": ["sandboxed", "is_sandboxed"],
            "max_limit": ["max_limit", "threshold"],
            "allowed_tables": ["allowed_tables", "table_whitelist"],
            "allowed_domains": ["allowed_domains", "domain_whitelist"],
        },
        "destructive_tools": {"delete_file", "drop_db", "rm_rf"},
        "spawn_tools": {"spawn_agent", "fork_process"},
        "financial_tools": {"transfer_funds", "crypto_payout"},
        "network_tools": {"http_request", "fetch_url"},
    }


# ==============================================================================
# Helper Function Tests: normalize_agents
# ==============================================================================


class TestNormalizeAgents:
    def test_normalize_dict_of_agents(self):
        data = {
            "agents": {
                "agent_alpha": {"tools": ["search"]},
                "agent_beta": {"tools": ["exec"]},
            }
        }
        normalized = normalize_agents(data)
        assert "agent_alpha" in normalized
        assert "agent_beta" in normalized

    def test_normalize_list_of_agents(self):
        data = {
            "agents": [
                {"name": "NamedAgent", "tools": []},
                {"role": "RoleAgent", "tools": []},
                {"tools": []},  # Should default to Agent_2
            ]
        }
        normalized = normalize_agents(data)
        assert "NamedAgent" in normalized
        assert "RoleAgent" in normalized
        assert "Agent_2" in normalized

    def test_normalize_mcp_servers(self):
        data = {
            "mcpServers": {
                "filesystem_server": {
                    "tools": ["read_file", "write_file"],
                    "sandboxed": True,
                    "env": {"KEY": "VAL"},
                }
            }
        }
        normalized = normalize_agents(data)
        assert "filesystem_server" in normalized
        assert normalized["filesystem_server"]["sandboxed"] is True
        assert normalized["filesystem_server"]["tools"] == ["read_file", "write_file"]

    def test_normalize_single_top_level_agent(self):
        data = {"name": "SoloAgent", "tools": ["ping"]}
        normalized = normalize_agents(data)
        assert "SoloAgent" in normalized
        assert normalized["SoloAgent"] == data

    def test_normalize_empty_or_unrecognized_dict(self):
        data = {"random_key": "random_value"}
        normalized = normalize_agents(data)
        assert normalized == {}


# ==============================================================================
# Main Scanner Tests: scan_structured_config
# ==============================================================================


class TestScanStructuredConfig:
    def test_empty_or_whitespace_returns_empty(self, sample_policy):
        violations, capabilities = scan_structured_config("config.yaml", "", sample_policy)
        assert violations == []
        assert capabilities == []

    def test_invalid_syntax_handled_gracefully(self, sample_policy):
        invalid_json = "{"
        violations, capabilities = scan_structured_config("bad.json", invalid_json, sample_policy)
        assert violations == []
        assert capabilities == []

    def test_non_dict_parsed_content_returns_empty(self, sample_policy):
        yaml_list = "- item1\n- item2"
        violations, capabilities = scan_structured_config("list.yaml", yaml_list, sample_policy)
        assert violations == []
        assert capabilities == []

    # --------------------------------------------------------------------------
    # Rule Violation Tests
    # --------------------------------------------------------------------------

    @patch("ape_linter.scanners.config_scanner.is_suppressed", return_value=False)
    @patch("ape_linter.scanners.config_scanner.find_line_number", return_value=1)
    def test_ape_005_unbounded_max_steps(self, mock_line, mock_suppressed, sample_policy):
        yaml_content = """
        agents:
          worker:
            max_steps: 0
        """
        violations, _ = scan_structured_config("config.yaml", yaml_content, sample_policy)
        ape_005 = [v for v in violations if v.rule_id == "APE-005"]
        assert len(ape_005) == 1
        assert ape_005[0].severity == "HIGH"
        assert "max_steps" in ape_005[0].message

    @pytest.mark.parametrize(
        "secret_token",
        [
            "sk-1234567890abcdef1234567890",
            "ghp_1234567890abcdef1234567890",
            "AKIA1234567890ABCDEF",
        ],
    )
    @patch("ape_linter.scanners.config_scanner.is_suppressed", return_value=False)
    @patch("ape_linter.scanners.config_scanner.find_line_number", return_value=2)
    def test_ape_008_hardcoded_secrets(self, mock_line, mock_suppressed, secret_token, sample_policy):
        json_content = f"""
        {{
          "agents": {{
            "bot": {{
              "max_steps": 10,
              "env": {{
                "API_KEY": "{secret_token}"
              }}
            }}
          }}
        }}
        """
        violations, _ = scan_structured_config("config.json", json_content, sample_policy)
        ape_008 = [v for v in violations if v.rule_id == "APE-008"]
        assert len(ape_008) == 1
        assert ape_008[0].severity == "CRITICAL"
        assert "Hardcoded secret token" in ape_008[0].message

    @patch("ape_linter.scanners.config_scanner.is_suppressed", return_value=False)
    @patch("ape_linter.scanners.config_scanner.find_line_number", return_value=1)
    def test_ape_001_destructive_tool_missing_hitl(self, mock_line, mock_suppressed, sample_policy):
        yaml_content = """
        agents:
          cleaner:
            max_steps: 5
            tools:
              - name: delete_file
                require_human_approval: false
        """
        violations, _ = scan_structured_config("config.yaml", yaml_content, sample_policy)
        ape_001 = [v for v in violations if v.rule_id == "APE-001"]
        assert len(ape_001) == 1
        assert ape_001[0].severity == "CRITICAL"

    @patch("ape_linter.scanners.config_scanner.is_suppressed", return_value=False)
    @patch("ape_linter.scanners.config_scanner.find_line_number", return_value=1)
    def test_ape_002_unsandboxed_shell_execution(self, mock_line, mock_suppressed, sample_policy):
        yaml_content = """
        agents:
          runner:
            max_steps: 10
            tools:
              - name: bash
                sandboxed: false
        """
        violations, _ = scan_structured_config("config.yaml", yaml_content, sample_policy)
        ape_002 = [v for v in violations if v.rule_id == "APE-002"]
        assert len(ape_002) == 1
        assert ape_002[0].severity == "CRITICAL"

    @patch("ape_linter.scanners.config_scanner.is_suppressed", return_value=False)
    @patch("ape_linter.scanners.config_scanner.find_line_number", return_value=1)
    def test_ape_003_financial_tool_missing_max_limit(self, mock_line, mock_suppressed, sample_policy):
        yaml_content = """
        agents:
          fintech:
            max_steps: 10
            tools:
              - name: transfer_funds
        """
        violations, _ = scan_structured_config("config.yaml", yaml_content, sample_policy)
        ape_003 = [v for v in violations if v.rule_id == "APE-003"]
        assert len(ape_003) == 1
        assert ape_003[0].severity == "HIGH"

    @patch("ape_linter.scanners.config_scanner.is_suppressed", return_value=False)
    @patch("ape_linter.scanners.config_scanner.find_line_number", return_value=1)
    def test_ape_004_db_write_missing_allowed_tables(self, mock_line, mock_suppressed, sample_policy):
        yaml_content = """
        agents:
          db_agent:
            max_steps: 10
            tools:
              - name: sql_writer
                read_only: false
        """
        violations, _ = scan_structured_config("config.yaml", yaml_content, sample_policy)
        ape_004 = [v for v in violations if v.rule_id == "APE-004"]
        assert len(ape_004) == 1
        assert ape_004[0].severity == "HIGH"

    @patch("ape_linter.scanners.config_scanner.is_suppressed", return_value=False)
    @patch("ape_linter.scanners.config_scanner.find_line_number", return_value=1)
    def test_ape_006_subagent_spawning_without_hitl(self, mock_line, mock_suppressed, sample_policy):
        yaml_content = """
        agents:
          orchestrator:
            max_steps: 10
            tools:
              - name: spawn_agent
                require_human_approval: false
        """
        violations, _ = scan_structured_config("config.yaml", yaml_content, sample_policy)
        ape_006 = [v for v in violations if v.rule_id == "APE-006"]
        assert len(ape_006) == 1
        assert ape_006[0].severity == "CRITICAL"

    @patch("ape_linter.scanners.config_scanner.is_suppressed", return_value=False)
    @patch("ape_linter.scanners.config_scanner.find_line_number", return_value=1)
    def test_ape_007_network_tool_missing_allowed_domains(self, mock_line, mock_suppressed, sample_policy):
        yaml_content = """
        agents:
          scraper:
            max_steps: 10
            tools:
              - name: web_scrape_tool
        """
        violations, _ = scan_structured_config("config.yaml", yaml_content, sample_policy)
        ape_007 = [v for v in violations if v.rule_id == "APE-007"]
        assert len(ape_007) == 1
        assert ape_007[0].severity == "MEDIUM"

    # --------------------------------------------------------------------------
    # Capability & Dictionary Tools Format Tests
    # --------------------------------------------------------------------------

    @patch("ape_linter.scanners.config_scanner.is_suppressed", return_value=False)
    def test_capability_extraction_and_dict_formatted_tools(self, mock_suppressed, sample_policy):
        yaml_content = """
        agents:
          helper:
            max_steps: 10
            tools:
              reader:
                read_only: true
              writer:
                read_only: false
        """
        _, capabilities = scan_structured_config("config.yaml", yaml_content, sample_policy)

        assert len(capabilities) == 2
        cap_names = {c.name for c in capabilities}
        cap_access_types = {c.name: c.type for c in capabilities}

        assert cap_names == {"ToolAccess:reader", "ToolAccess:writer"}
        assert cap_access_types["ToolAccess:reader"] == "read"
        assert cap_access_types["ToolAccess:writer"] == "read-write"
