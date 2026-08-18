"""
SARIF v1.0.0 Reporter Exporter.
Converts SecurityViolation finding objects into standard SARIF JSON for GitHub Code Scanning and CI pipelines.
"""
import json
from typing import Dict, List
from ape_linter import __version__
from ape_linter.core import SecurityViolation

SEVERITY_TO_SARIF_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
}


def export_sarif(violations: List[SecurityViolation]) -> str:
    """Exports findings list into OASIS SARIF v1.0.0 compliant JSON string."""
    rules_map: Dict[str, dict] = {}
    sarif_results = []

    for v in violations:
        if v.suppressed:
            continue

        # Register rule definition once
        if v.rule_id not in rules_map:
            rules_map[v.rule_id] = {
                "id": v.rule_id,
                "name": v.rule_id.replace("-", "_"),
                "shortDescription": {"text": v.message},
                "fullDescription": {"text": f"{v.message} {v.remediation}"},
                "defaultConfiguration": {
                    "level": SEVERITY_TO_SARIF_LEVEL.get(v.severity, "warning")
                },
                "properties": {
                    "tags": ["security", "ai-agent", "ape-linter"],
                    "precision": "high",
                },
            }

        # Format result object
        sarif_results.append(
            {
                "ruleId": v.rule_id,
                "level": SEVERITY_TO_SARIF_LEVEL.get(v.severity, "warning"),
                "message": {
                    "text": f"[{v.rule_id}] {v.message} Remediation: {v.remediation}"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": v.file.replace("\\", "/"),
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {
                                "startLine": max(1, v.line),
                                "startColumn": 1,
                            },
                        }
                    }
                ],
            }
        )

    sarif_doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-1.0.0.json",
        "version": "1.0.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "APE-Linter",
                        "semanticVersion": getattr(__version__, "__version__", "1.0.0"),
                        "informationUri": "https://github.com/nareshgcv/Agentic-posture-engine/tree/main/src/ape-linter",
                        "rules": list(rules_map.values()),
                    }
                },
                "results": sarif_results,
            }
        ],
    }

    return json.dumps(sarif_doc, indent=2)
