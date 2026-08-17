"""
Source Code AST scanner for Python and JS/TS files.
Eliminates false positives by inspecting syntactic nodes rather than raw regex matches.
"""
import ast
import re
from typing import List, Tuple
from ape_linter.core import (
    Capability,
    SecurityViolation,
    find_line_number,
    is_suppressed,
)


def _strip_js_comments_and_strings(code: str) -> List[Tuple[int, str]]:
    """Splits JS code into line-by-line executable code tokens, excluding string comments/literals."""
    lines = code.splitlines()
    cleaned = []
    in_multiline_comment = False

    for idx, line in enumerate(lines, start=1):
        s = line.strip()
        if in_multiline_comment:
            if "*/" in s:
                s = s.split("*/", 1)[1]
                in_multiline_comment = False
            else:
                cleaned.append((idx, ""))
                continue

        if "/*" in s:
            if "*/" in s:
                s = re.sub(r"/\*.*?\*/", "", s)
            else:
                s = s.split("/*", 1)[0]
                in_multiline_comment = True

        # Strip single line comment
        if "//" in s:
            s = s.split("//", 1)[0]

        # Strip strings to avoid flagging comments inside quotes
        s_no_str = re.sub(r"(['\"])(?:(?!\1|\\).|\\.)*\1", "''", s)
        cleaned.append((idx, s_no_str))

    return cleaned


def scan_source_code(
    file_path: str, raw_content: str
) -> Tuple[List[SecurityViolation], List[Capability]]:
    violations = []
    capabilities = []

    if file_path.endswith(".py"):
        try:
            tree = ast.parse(raw_content, filename=file_path)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    func_name = ""
                    if isinstance(node.func, ast.Attribute):
                        func_name = f"{getattr(node.func.value, 'id', '')}.{node.func.attr}"
                    elif isinstance(node.func, ast.Name):
                        func_name = node.func.id

                    if func_name in {
                        "os.system",
                        "subprocess.Popen",
                        "subprocess.run",
                        "subprocess.call",
                        "eval",
                        "exec",
                    }:
                        suppressed = is_suppressed(
                            "APE-201",
                            {},
                            {},
                            raw_content=raw_content,
                            line_no=node.lineno,
                        )
                        violations.append(
                            SecurityViolation(
                                rule_id="APE-201",
                                severity="CRITICAL",
                                file=file_path,
                                line=node.lineno,
                                agent="SourceCode",
                                tool=func_name,
                                message=f"Dynamic shell execution call '{func_name}' detected in code.",
                                remediation="Sanitize inputs and avoid raw dynamic shell invocation.",
                                suppressed=suppressed,
                                fixable=False,
                            )
                        )
                        capabilities.append(
                            Capability(
                                "SourceCode",
                                "CodeShellExec",
                                func_name,
                                file_path,
                                node.lineno,
                            )
                        )
        except Exception:
            pass

    elif file_path.endswith((".js", ".ts", ".jsx", ".tsx")):
        lines = _strip_js_comments_and_strings(raw_content)

        for line_no, code_line in lines:
            if not code_line:
                continue

            # APE-202: Node.js child process execution
            if re.search(r"\bchild_process\.(exec|spawn)\s*\(", code_line):
                suppressed = is_suppressed(
                    "APE-202", {}, {}, raw_content=raw_content, line_no=line_no
                )
                violations.append(
                    SecurityViolation(
                        rule_id="APE-202",
                        severity="CRITICAL",
                        file=file_path,
                        line=line_no,
                        agent="SourceCode",
                        tool="child_process.exec",
                        message="Node.js child process execution found.",
                        remediation="Use safe parameterized execution APIs.",
                        suppressed=suppressed,
                        fixable=False,
                    )
                )
                capabilities.append(
                    Capability(
                        "SourceCode",
                        "CodeShellExec",
                        "child_process.exec",
                        file_path,
                        line_no,
                    )
                )

            # APE-203: Dynamic JavaScript eval execution
            if re.search(r"\beval\s*\(", code_line):
                suppressed = is_suppressed(
                    "APE-203", {}, {}, raw_content=raw_content, line_no=line_no
                )
                violations.append(
                    SecurityViolation(
                        rule_id="APE-203",
                        severity="HIGH",
                        file=file_path,
                        line=line_no,
                        agent="SourceCode",
                        tool="eval",
                        message="Dynamic JavaScript eval() execution detected.",
                        remediation="Avoid dynamic eval() invocations.",
                        suppressed=suppressed,
                        fixable=False,
                    )
                )

    return violations, capabilities
