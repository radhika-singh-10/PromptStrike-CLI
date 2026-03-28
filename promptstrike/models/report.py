from pydantic import BaseModel
from promptstrike.models.result import Finding


class SeveritySummary(BaseModel):
    CRITICAL: int = 0
    HIGH: int = 0
    MEDIUM: int = 0
    LOW: int = 0


class Report(BaseModel):
    target: str
    total_attacks: int
    successful_attacks: int
    overall_risk: str
    severity_summary: SeveritySummary
    findings: list[Finding]
