from promptstrike.models.report import SeveritySummary


SCORES = {"CRITICAL": 40, "HIGH": 25, "MEDIUM": 10, "LOW": 5}


def summarize_severity(findings) -> SeveritySummary:
    summary = SeveritySummary()
    for finding in findings:
        sev = finding.severity.upper()
        if hasattr(summary, sev):
            setattr(summary, sev, getattr(summary, sev) + 1)
    return summary


def compute_overall_risk(findings) -> str:
    score = sum(SCORES.get(f.severity.upper(), 0) for f in findings if f.compromised)
    if score >= 90:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 20:
        return "MODERATE"
    return "LOW"
