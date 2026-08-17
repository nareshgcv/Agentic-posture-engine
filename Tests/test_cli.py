import json
import sys
from unittest.mock import MagicMock, patch

import pytest

from ape_linter.cli import compute_delta, main
from ape_linter.core import Capability, SecurityViolation


# ---------------------------------------------------------------------------
# Core Logic Unit Tests
# ---------------------------------------------------------------------------

def test_compute_delta_filters_and_compares():
    """Verify compute_delta correctly calculates new violations and capabilities."""
    base_v = [
        SecurityViolation(rule_id="RULE_001", agent="agent_a", tool="tool_x", severity="HIGH", suppressed=False),
        SecurityViolation(rule_id="RULE_002", agent="agent_a", tool="tool_y", severity="LOW", suppressed=True),
    ]
    head_v = [
        # Existing violation
        SecurityViolation(rule_id="RULE_001", agent="agent_a", tool="tool_x", severity="HIGH", suppressed=False),
        # New violation
        SecurityViolation(rule_id="RULE_003", agent="agent_b", tool="tool_z", severity="CRITICAL", suppressed=False),
        # Suppressed new violation (should be ignored)
        SecurityViolation(rule_id="RULE_004", agent="agent_b", tool="tool_w", severity="HIGH", suppressed=True),
    ]

    base_c = [
        Capability(agent="agent_a", cap_type="EXEC", scope="local"),
    ]
    head_c = [
        Capability(agent="agent_a", cap_type="EXEC", scope="local"),
        Capability(agent="agent_b", cap_type="NET", scope="global"),
    ]

    delta = compute_delta(base_v, head_v, base_c, head_c)

    assert len(delta["new_violations"]) == 1
    assert delta["new_violations"][0].rule_id == "RULE_003"

    assert len(delta["new_capabilities"]) == 1
    assert delta["new_capabilities"][0].cap_type == "NET"


# ---------------------------------------------------------------------------
# CLI Command Flow Tests
# ---------------------------------------------------------------------------

@patch("ape_linter.cli.run_init_wizard")
def test_cli_init_command(mock_run_init):
    """Test `ape init` triggers wizard and exits with 0."""
    with patch.object(sys, "argv", ["ape", "init"]):
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 0
        mock_run_init.assert_called_once()


@patch("ape_linter.cli.os.path.isdir", return_value=False)
@patch("ape_linter.cli.load_policy")
@patch("ape_linter.cli.analyze_path")
@patch("ape_linter.cli.generate_markdown", return_value="## Summary")
def test_cli_scan_passing_run(
    mock_markdown, mock_analyze, mock_load_policy, mock_isdir, capsys
):
    """Test a basic scan on a file with no blocking violations."""
    mock_analyze.return_value = ([], [])
    
    with patch.object(sys, "argv", ["ape", "scan", "test_file.py"]):
        with pytest.raises(SystemExit) as exc_info:
            main()
            
        assert exc_info.value.code == 0
        captured = capsys.readouterr()
        assert "## Summary" in captured.out


@patch("ape_linter.cli.os.path.isdir", return_value=False)
@patch("ape_linter.cli.load_policy")
@patch("ape_linter.cli.analyze_path")
@patch("ape_linter.cli.generate_markdown", return_value="## Summary")
def test_cli_scan_blocking_violations(
    mock_markdown, mock_analyze, mock_load_policy, mock_isdir
):
    """Test that HIGH/CRITICAL unsuppressed violations result in exit code 1."""
    high_violation = SecurityViolation(
        rule_id="R001", agent="a", tool="t", severity="HIGH", suppressed=False
    )
    mock_analyze.return_value = ([high_violation], [])

    with patch.object(sys, "argv", ["ape", "scan", "vulnerable.py"]):
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1


@patch("ape_linter.cli.os.path.isdir", return_value=False)
@patch("ape_linter.cli.load_policy")
@patch("ape_linter.cli.analyze_path")
@patch("ape_linter.cli.apply_auto_fixes", return_value=1)
@patch("ape_linter.cli.generate_markdown", return_value="## Summary")
def test_cli_auto_fix_flag(
    mock_markdown, mock_fix, mock_analyze, mock_load_policy, mock_isdir, capsys
):
    """Test that --fix runs auto-fixer and re-analyzes files."""
    mock_analyze.side_effect = [
        ([SecurityViolation(rule_id="R1", agent="a", tool="t", severity="LOW", suppressed=False)], []),
        ([], [])  # Re-scan after fix returns clean
    ]

    with patch.object(sys, "argv", ["ape", "scan", "file.py", "--fix"]):
        with pytest.raises(SystemExit) as exc_info:
            main()

        assert exc_info.value.code == 0
        mock_fix.assert_called_once_with("file.py", pytest.any(list))
        assert mock_analyze.call_count == 2
        
        captured = capsys.readouterr()
        assert "🔧 Auto-fixed 1 violation(s) in file.py" in captured.out


@patch("ape_linter.cli.os.path.isdir", return_value=False)
@patch("ape_linter.cli.load_policy")
@patch("ape_linter.cli.analyze_path")
@patch("ape_linter.cli.generate_markdown", return_value="MD Report")
@patch("ape_linter.cli.generate_sarif", return_value={"version": "1.0.0"})
@patch("ape_linter.cli.generate_json", return_value={"status": "ok"})
def test_cli_output_file_generation(
    mock_gen_json,
    mock_gen_sarif,
    mock_gen_md,
    mock_analyze,
    mock_load_policy,
    mock_isdir,
    tmp_path,
):
    """Verify that output reports (Markdown, SARIF, JSON) are correctly written to disk."""
    mock_analyze.return_value = ([], [])

    md_file = tmp_path / "report.md"
    sarif_file = tmp_path / "report.sarif"
    json_file = tmp_path / "report.json"

    args = [
        "ape",
        "scan",
        "file.py",
        "--output-markdown",
        str(md_file),
        "--output-sarif",
        str(sarif_file),
        "--output-json",
        str(json_file),
    ]

    with patch.object(sys, "argv", args):
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 0

    # Verify generated contents
    assert md_file.read_text() == "MD Report"
    assert json.loads(sarif_file.read_text()) == {"version": "2.1.0"}
    assert json.loads(json_file.read_text()) == {"status": "ok"}


@patch("ape_linter.cli.os.path.isdir", return_value=False)
@patch("ape_linter.cli.load_policy")
@patch("ape_linter.cli.analyze_path")
@patch("ape_linter.cli.generate_markdown")
def test_cli_base_diff_analysis(
    mock_markdown, mock_analyze, mock_load_policy, mock_isdir
):
    """Verify delta computation runs when --base argument is provided."""
    mock_analyze.side_effect = [
        ([], []),  # Head scan
        ([], []),  # Base scan
    ]

    with patch.object(sys, "argv", ["ape", "scan", "head.py", "--base", "base.py"]):
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 0

    assert mock_analyze.call_count == 2
    # Verify generate_markdown received non-None delta arg
    assert mock_markdown.call_args[0][2] is not None

