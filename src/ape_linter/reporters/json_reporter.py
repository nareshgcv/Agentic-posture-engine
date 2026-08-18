"""
Structured JSON report generator.
"""

from typing import Any, Dict, List, Optional

from ape_linter.core import Capability, SecurityViolation


def generate_json(
    target_file: str,
    violations: List[SecurityViolation],
    capabilities: List[Capability],
    delta: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    return {
        "scanned_file": target_file,
        "violations": [v.to_dict() for v in violations],
        "capabilities": [c.to_dict() for c in capabilities],
        "delta": (
            {
                "new_violations": [
                    v.to_dict() for v in delta["new_violations"]
                ],
                "new_capabilities": [
                    c.to_dict() for c in delta["new_capabilities"]
                ],
            }
            if delta
            else None
        ),
    }
