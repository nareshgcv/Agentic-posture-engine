from typing import Any, Dict, List, Optional
from ape_linter.core import Capability, SecurityViolation, compute_blast_radius


def generate_markdown(
    violations: List[SecurityViolation],
    capabilities: List[Capability],
    delta: Optional[Dict[str, Any]] = None,
) -> str:
    active = [v for v in violations if not v.suppressed]
    blast = compute_blast_radius(capabilities, active)

    md = "### 🛡️ Agentic Posture Engine (APE) Security & Diff Report\n\n"

    # --- Blast Radius Section ---
    md += f"💥 **Overall Agent Blast Radius:** `{blast['level']}`\n"
    md += (
        f"🎯 **Affected Systems/Scope:** {', '.join(blast['impact_zones'])}\n\n"
    )

    # --- Configuration Diff & Capability Delta ---
    if delta and (delta["new_violations"] or delta["new_capabilities"]):
        md += "#### 🔀 Capability & Risk Delta Analysis\n\n"

        if delta["new_capabilities"]:
            md += "✨ **Newly Introduced Capabilities:**\n"
            for cap in delta["new_capabilities"]:
                md += f"- Agent `{cap.agent}` granted `{cap.cap_type}` (Scope: `{cap.scope}`) in `{cap.file}:{cap.line}`\n"
            md += "\n"

        if delta["new_violations"]:
            md += f"⚠️ **{len(delta['new_violations'])} New Security Risks Introduced in this PR!**\n\n"

    # --- Violations Table ---
    if not active:
        md += (
            "✅ **APE Security Gate Passed:** No active security risks found.\n"
        )
    else:
        md += "⛔ **APE Security Gate Failed**\n\n"
        md += "| Severity | Location | Agent | Tool | Affected Workflow / Risk | Fix |\n"
        md += "| :--- | :--- | :--- | :--- | :--- | :--- |\n"
        for v in sorted(active, key=lambda x: x.severity):
            badge = (
                "🔴 **CRITICAL**"
                if v.severity == "CRITICAL"
                else "🟡 **HIGH**" if v.severity == "HIGH" else "🔵 **MEDIUM**"
            )
            fix_badge = "💡 `ape fix`" if v.fixable else "Manual"
            md += f"| {badge} | `{v.file}:{v.line}` | `{v.agent}` | `{v.tool}` | **{v.message}** | {fix_badge} |\n"

    return md
