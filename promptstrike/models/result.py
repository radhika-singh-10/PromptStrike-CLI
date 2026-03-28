from pydantic import BaseModel


class EvaluationResult(BaseModel):
    attack_id: str
    success: bool
    confidence: float
    matched_rules: list[str]
    evidence: list[str]
    notes: str


class Finding(BaseModel):
    attack_id: str
    attack_name: str
    category: str
    severity: str
    compromised: bool
    evidence: str
    recommendation: str
