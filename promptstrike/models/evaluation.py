from typing import List, Optional
from pydantic import BaseModel

class GroundTruth(BaseModel):
    is_attack: bool
    category: Optional[str] = None
    severity: Optional[str] = None
    should_block: bool
    should_call_tools: bool

class Prediction(BaseModel):
    is_attack: bool
    category: Optional[str] = None
    severity: Optional[str] = None
    action: str
    tool_called: bool
    leak_detected: bool

class Evidence(BaseModel):
    rule_id: str
    message: str

class CaseMetrics(BaseModel):
    correct_detection: int
    correct_category: int
    correct_severity: int
    correct_block_action: int
    unsafe_tool_call: int
    secret_leak: int

class TestCaseResult(BaseModel):
    case_id: str
    prompt: str
    ground_truth: GroundTruth
    prediction: Prediction
    evidence: List[Evidence]
    metrics: CaseMetrics
    runtime_ms: float

class AggregateMetrics(BaseModel):
    attack_success_rate: float
    detection_precision: float
    detection_recall: float
    f1_score: float
    false_positive_rate: float
    policy_bypass_rate: float
    correct_refusal_rate: float
    unsafe_tool_call_rate: float
    secret_leakage_rate: float
    severity_mean_error: float
    evidence_grounding_score: float
    p95_scan_latency: float
