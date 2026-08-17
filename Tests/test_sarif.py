import json
from unittest.mock import MagicMock, patch
import pytest

from ape_linter.core import SecurityViolation
from ape_linter.reporters.sarif_exporter import export_sarif


@pytest.fixture
def sample_violation():
    """Returns a basic non-suppressed SecurityViolation."""
    return SecurityViolation(
        rule_id="APE-201",
        severity="CRITICAL",
        file="src/utils.py",
        line=15,
        agent="SourceCode",
        tool="os.system",
        message="Dynamic shell execution call 'os.system' detected in code.",
        remediation="Sanitize inputs and avoid raw dynamic shell invocation.",
        suppressed=False,
        fixable=False,
    )


# ============================================================================
# Unit Tests for export_sarif
# ============================================================================

def test_export_sarif_empty_violations():
    """Ensures empty violations list outputs valid SARIF document with empty rules and results."""
    sarif_json = export_sarif([])
    doc = json.loads(sarif_json)

    assert doc["$schema"] == "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
    assert doc["version"] == "1.0.0"

    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == "APE-Linter"
    assert driver["rules"] == []
    assert doc["runs"][0]["results"] == []


def test_export_sarif_single_violation(sample_violation):
    """Verifies rules and results structure for a single violation."""
    sarif_json = export_sarif([sample_violation])
    doc = json.loads(sarif_json)

    run = doc["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    results = run["results"]

    # Rule registration check
    assert len(rules) == 1
    assert rules[0]["id"] == "APE-201"
    assert rules[0]["name"] == "APE_201"
    assert rules[0]["defaultConfiguration"]["level"] == "error"
    assert "security" in rules[0]["properties"]["tags"]

    # Result structure check
    assert len(results) == 1
    res = results[0]
    assert res["ruleId"] == "APE-201"
    assert res["level"] == "error"
    assert "Dynamic shell execution" in res["message"]["text"]
    assert res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "src/utils.py"
    assert res["locations"][0]["physicalLocation"]["region"]["startLine"] == 15


def test_export_sarif_suppressed_violation_ignored(sample_violation):
    """Suppressed violations must not appear in output SARIF rules or results."""
    sample_violation.suppressed = True
    sarif_json = export_sarif([sample_violation])
    doc = json.loads(sarif_json)

    assert doc["runs"][0]["tool"]["driver"]["rules"] == []
    assert doc["runs"][0]["results"] == []


def test_export_sarif_rule_deduplication():
    """Multiple violations with the same rule_id should register rule definition only once."""
    v1 = SecurityViolation(
        rule_id="APE-201",
        severity="CRITICAL",
        file="file1.py",
        line=10,
        agent="SourceCode",
        tool="os.system",
        message="Dynamic execution",
        remediation="Fix it",
        suppressed=False,
        fixable=False,
    )
    v2 = SecurityViolation(
        rule_id="APE-201",
        severity="CRITICAL",
        file="file2.py",
        line=20,
        agent="SourceCode",
        tool="exec",
        message="Dynamic execution",
        remediation="Fix it",
        suppressed=False,
        fixable=False,
    )

    sarif_json = export_sarif([v1, v2])
    doc = json.loads(sarif_json)

    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    results = doc["runs"][0]["results"]

    assert len(rules) == 1  # Deduplicated
    assert len(results) == 2  # Both findings recorded


def test_export_sarif_windows_path_normalization():
    """Ensures backslashes in file paths are converted to forward slashes for cross-platform SARIF specs."""
    v = SecurityViolation(
        rule_id="APE-202",
        severity="HIGH",
        file="src\\scanners\\ast_scanner.js",
        line=5,
        agent="SourceCode",
        tool="eval",
        message="Eval call",
        remediation="Remove eval",
        suppressed=False,
        fixable=False,
    )

    sarif_json = export_sarif([v])
    doc = json.loads(sarif_json)

    uri = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "src/scanners/ast_scanner.js"


def test_export_sarif_line_number_clamping():
    """Line numbers lower than 1 (0 or negative) must clamp to 1."""
    v = SecurityViolation(
        rule_id="APE-101",
        severity="MEDIUM",
        file="config.json",
        line=0,
        agent="ConfigScanner",
        tool="parser",
        message="Config issue",
        remediation="Update config",
        suppressed=False,
        fixable=False,
    )

    sarif_json = export_sarif([v])
    doc = json.loads(sarif_json)

    start_line = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"]
    assert start_line == 1


@pytest.mark.parametrize(
    "severity, expected_sarif_level",
    [
        ("CRITICAL", "error"),
        ("HIGH", "error"),
        ("MEDIUM", "warning"),
        ("LOW", "note"),
        ("INFO", "note"),
        ("UNKNOWN_SEVERITY", "warning"),  # Default fallback
    ],
)
def test_export_sarif_severity_mapping(severity, expected_sarif_level):
    """Checks mapping from linter severity string to SARIF level."""
    v = SecurityViolation(
        rule_id="APE-300",
        severity=severity,
        file="main.py",
        line=1,
        agent="SourceCode",
        tool="tool",
        message="Test message",
        remediation="Test remediation",
        suppressed=False,
        fixable=False,
    )

    sarif_json = export_sarif([v])
    doc = json.loads(sarif_json)

    assert doc["runs"][0]["results"][0]["level"] == expected_sarif_level


@patch("ape_linter.reporters.sarif_exporter.__version__", "v1.0.0")
def test_export_sarif_semantic_version():
    """Verifies version v1.0.0 is accurately reflected in tool driver metadata."""
    sarif_json = export_sarif([])
    doc = json.loads(sarif_json)

    semantic_version = doc["runs"][0]["tool"]["driver"]["semanticVersion"]
    assert semantic_version == "v1.0.0"
