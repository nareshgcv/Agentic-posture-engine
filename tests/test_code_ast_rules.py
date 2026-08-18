from unittest.mock import patch
import pytest

from ape_linter.scanners.ast_scanner import (
    _strip_js_comments_and_strings,
    scan_source_code,
)


# ============================================================================
# Unit Tests for Helper: _strip_js_comments_and_strings
# ============================================================================

def test_strip_js_single_line_comments():
    code = "const x = 10; // inline comment"
    result = _strip_js_comments_and_strings(code)
    assert result == [(1, "const x = 10;")]


def test_strip_js_inline_multiline_comments():
    code = "const x = /* inline block */ 10;"
    result = _strip_js_comments_and_strings(code)
    assert result == [(1, "const x =  10;")]


def test_strip_js_multiline_block_comments():
    code = "const a = 1;\n/* comment start\nmiddle line\ncomment end */\nconst b = 2;"
    result = _strip_js_comments_and_strings(code)
    assert result == [
        (1, "const a = 1;"),
        (2, ""),
        (3, ""),
        (4, ""),
        (5, "const b = 2;"),
    ]


def test_strip_js_string_literals():
    """Ensures code inside string literals is replaced to prevent false positives."""
    code = 'const codeStr = "eval(x) and child_process.exec(y)";'
    result = _strip_js_comments_and_strings(code)
    # Quotes remain, but content inside is sanitized to ''
    assert "eval" not in result[0][1]
    assert "child_process" not in result[0][1]


# ============================================================================
# Unit Tests for Python AST Scanning (.py)
# ============================================================================

@patch("ape_linter.scanners.ast_scanner.is_suppressed", return_value=False)
def test_scan_python_dangerous_calls(mock_is_suppressed):
    py_code = """
import os
import subprocess

os.system('ls')
subprocess.Popen(['ls'])
subprocess.run(['ls'])
subprocess.call(['ls'])
eval('1 + 1')
exec('import sys')
"""
    violations, capabilities = scan_source_code("script.py", py_code)

    assert len(violations) == 6
    assert len(capabilities) == 6

    tools = [v.tool for v in violations]
    assert "os.system" in tools
    assert "subprocess.Popen" in tools
    assert "subprocess.run" in tools
    assert "subprocess.call" in tools
    assert "eval" in tools
    assert "exec" in tools

    # Check structure of a violation
    v = violations[0]
    assert v.rule_id == "APE-201"
    assert v.severity == "CRITICAL"
    assert v.file == "script.py"
    assert v.agent == "SourceCode"


@patch("ape_linter.scanners.ast_scanner.is_suppressed", return_value=False)
def test_scan_python_safe_code(mock_is_suppressed):
    py_code = """
def calculate_sum(a, b):
    print(f"Calculating sum for {a} and {b}")
    return a + b
"""
    violations, capabilities = scan_source_code("safe.py", py_code)
    assert len(violations) == 0
    assert len(capabilities) == 0


def test_scan_python_syntax_error_handled_gracefully():
    """Invalid Python syntax should not crash the scanner."""
    invalid_py = "def broken_func(:"
    violations, capabilities = scan_source_code("invalid.py", invalid_py)
    assert violations == []
    assert capabilities == []


@patch("ape_linter.scanners.ast_scanner.is_suppressed", return_value=True)
def test_scan_python_suppressed_violation(mock_is_suppressed):
    py_code = "os.system('ls')"
    violations, _ = scan_source_code("script.py", py_code)

    assert len(violations) == 1
    assert violations[0].suppressed is True


# ============================================================================
# Unit Tests for JS / TS Scanning (.js, .ts, .jsx, .tsx)
# ============================================================================

@pytest.mark.parametrize("ext", [".js", ".ts", ".jsx", ".tsx"])
@patch("ape_linter.scanners.ast_scanner.is_suppressed", return_value=False)
def test_scan_js_child_process_detection(mock_is_suppressed, ext):
    js_code = """
const cp = require('child_process');
child_process.exec('ls');
child_process.spawn('ls');
"""
    file_path = f"app{ext}"
    violations, capabilities = scan_source_code(file_path, js_code)

    assert len(violations) == 2
    assert len(capabilities) == 2
    assert all(v.rule_id == "APE-202" for v in violations)
    assert all(v.severity == "CRITICAL" for v in violations)


@patch("ape_linter.scanners.ast_scanner.is_suppressed", return_value=False)
def test_scan_js_eval_detection(mock_is_suppressed):
    js_code = "eval('console.log(1)');"
    violations, capabilities = scan_source_code("app.js", js_code)

    assert len(violations) == 1
    assert violations[0].rule_id == "APE-203"
    assert violations[0].severity == "HIGH"
    # APE-203 does not append to capabilities in the source implementation
    assert len(capabilities) == 0


@patch("ape_linter.scanners.ast_scanner.is_suppressed", return_value=False)
def test_scan_js_ignores_comments_and_strings(mock_is_suppressed):
    """Ensures commented-out code or string matches are ignored."""
    js_code = """
// child_process.exec('ls');
/* eval('1 + 1'); */
const message = "Do not trigger child_process.exec() here";
const code = 'eval(x)';
"""
    violations, capabilities = scan_source_code("clean.js", js_code)
    assert len(violations) == 0
    assert len(capabilities) == 0


# ============================================================================
# Unit Tests for Unsupported File Types
# ============================================================================

def test_scan_unsupported_file_extension():
    code = "eval('something')"
    violations, capabilities = scan_source_code("readme.txt", code)
    assert violations == []
    assert capabilities == []
