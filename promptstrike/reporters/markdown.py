from pathlib import Path
from promptstrike.models.report import Report
from promptstrike.scoring.risk import SCORES

def write_markdown_report(report: Report, out_path: Path):
    lines = []
    lines.append(f"# PromptStrike Security Report")
    lines.append(f"**Target:** `{report.target}`  ")
    lines.append(f"**Overall Risk:** `{report.overall_risk}`  ")
    lines.append(f"**Total Attacks:** {report.summary.total_attacks}  ")
    lines.append(f"**Successful Attacks (Compromises):** {report.summary.successful_attacks}  ")
    
    lines.append(f"\n## Findings Details")
    
    if not report.findings:
        lines.append("No findings recorded.")
    else:
        for f in report.findings:
            if f.status == "COMPROMISED":
                status = "🔴 COMPROMISED"
            elif f.status in ["INCONCLUSIVE", "ERROR"]:
                status = f"⚠️ {f.status}"
            else:
                status = f"🟢 {f.status}"
                
            lines.append(f"### {f.attack_name} ({f.attack_id})")
            lines.append(f"- **Status:** {status}")
            lines.append(f"- **Category:** `{f.category}`")
            lines.append(f"- **Severity:** `{f.severity}`")
            lines.append(f"- **Evidence:** {f.evidence}")
            if f.recommendation:
                lines.append(f"- **Recommendation:** {f.recommendation}")
            lines.append("")
    
    out_path.write_text("\n".join(lines))
