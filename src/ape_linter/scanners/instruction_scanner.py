"""
Instruction rules scanner (.cursorrules, system prompts, etc.).
Parses instruction text in multi-line blocks/paragraphs so defensive negations carry across wrapped lines and bullet lists.
"""
import os
import re
from typing import List, Tuple
from ape_linter.core import (
    Capability,
    SecurityViolation,
    find_line_number,
    is_suppressed,
)

# Prefixes indicating defensive enforcement rather than malicious directives
NEGATION_PREFIXES = r"(?:do\s+not|don't|never|must\s+not|shall\s+not|prohibit|prevent|refuse\s+to|under\s+no\s+circumstances|forbidden|banned|disallowed)"


def _strip_non_instruction_context(content: str) -> str:
    """Removes code snippets to prevent false positives in markdown code blocks."""
    content = re.sub(r"```[\s\S]*?```", "", content)
    content = re.sub(r"`[^`\n]+`", "", content)
    return content


def _split_into_blocks(content: str) -> List[Tuple[str, int]]:
    """
    Splits content into logical multi-line paragraphs or markdown section blocks.
    Returns a list of tuples: (block_text, starting_line_number).
    """
    blocks = []
    lines = content.splitlines()
    current_block_lines = []
    block_start_line = 1

    for line_idx, line in enumerate(lines, start=1):
        # Empty line or markdown header signals end of current block
        if not line.strip() or line.strip().startswith("#"):
            if current_block_lines:
                blocks.append(("\n".join(current_block_lines), block_start_line))
                current_block_lines = []
            if line.strip().startswith("#"):
                # Treat headers as their own single-line block
                blocks.append((line, line_idx))
                block_start_line = line_idx + 1
            else:
                block_start_line = line_idx + 1
        else:
            if not current_block_lines:
                block_start_line = line_idx
            current_block_lines.append(line)

    if current_block_lines:
        blocks.append(("\n".join(current_block_lines), block_start_line))

    return blocks


def is_defensive_negation_in_block(block_text: str, match_str: str) -> bool:
    """Checks if a matched pattern is preceded by a defensive negation anywhere within the multi-line block."""
    match_idx = block_text.lower().find(match_str.lower())
    if match_idx == -1:
        return False

    prefix_text = block_text[:match_idx]
    return bool(re.search(NEGATION_PREFIXES, prefix_text, re.IGNORECASE))


def scan_instruction_file(
    file_path: str, raw_content: str
) -> Tuple[List[SecurityViolation], List[Capability]]:
    violations = []
    capabilities = []
    agent_name = os.path.basename(file_path)

    clean_content = _strip_non_instruction_context(raw_content)
    blocks = _split_into_blocks(clean_content)

    instruction_rules = [
        (
            r"\b(bypass|ignore|override)\b[\s\S]*?\b(security|guardrails|safety|permissions?)\b",
            "APE-101",
            "CRITICAL",
            "Instruction explicitly overrides or disables security guardrails.",
            "Remove prompt directives that bypass security checks.",
            True,
        ),
        (
            r"\b(you\s+are\s+allowed\s+to|you\s+may)\b[\s\S]*?\b(execute|run)\s+any\s+(command|shell|terminal|bash)\b",
            "APE-102",
            "HIGH",
            "Unconstrained command execution permission in agent instruction.",
            "Restrict agent execution capabilities to specific approved tools.",
            False,
        ),
        (
            r"\bdo\s+not\s+ask\s+for\b[\s\S]*?\b(approval|confirmation|human)\b",
            "APE-103",
            "HIGH",
            "Instruction explicitly waives human confirmation for tasks.",
            "Enforce Human-in-the-Loop requirement for sensitive actions.",
            True,
        ),
        (
            r"\bgranted\s+full\s+access\b[\s\S]*?\b(files|data|databases)\b",
            "APE-104",
            "MEDIUM",
            "Broad file/data access directive granted in prompt.",
            "Narrow resource scopes to explicitly allowed directory paths.",
            False,
        ),
    ]

    for block_text, block_start_line in blocks:
        if not block_text.strip():
            continue

        for (
            pattern,
            rule_id,
            severity,
            msg,
            remediation,
            fixable,
        ) in instruction_rules:
            match = re.search(pattern, block_text, re.IGNORECASE)
            if match:
                # Block-level negation check across multi-line paragraphs/lists
                if rule_id == "APE-101" and is_defensive_negation_in_block(
                    block_text, match.group(0)
                ):
                    continue

                raw_line_no = find_line_number(raw_content, match.group(0)) or block_start_line
                suppressed = is_suppressed(
                    rule_id, {}, {}, raw_content=raw_content, line_no=raw_line_no
                )
                violations.append(
                    SecurityViolation(
                        rule_id=rule_id,
                        severity=severity,
                        file=file_path,
                        line=raw_line_no,
                        agent=agent_name,
                        tool="instruction_prompt",
                        message=msg,
                        remediation=remediation,
                        suppressed=suppressed,
                        fixable=fixable,
                    )
                )

    if re.search(r"\b(execute|run)\s+(shell|bash|terminal)\b", clean_content, re.I):
        capabilities.append(
            Capability(
                agent_name,
                "UnrestrictedInstructionShell",
                "system",
                file_path,
                1,
            )
        )

    return violations, capabilities
