from pydantic import BaseModel


class EvaluationResult(BaseModel):
    attack_id: str
    status: str
    confidence: float
    matched_rules: list[str]
    evidence: list[str]
    notes: str
    mitigation: str = ""


class Finding(BaseModel):
    attack_id: str
    attack_name: str
    category: str
    severity: str
    status: str
    evidence: str
    recommendation: str
