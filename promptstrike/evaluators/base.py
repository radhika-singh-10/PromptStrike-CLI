from promptstrike.models.attack import Attack
from promptstrike.models.response import TargetResponse
from promptstrike.models.result import EvaluationResult


class BaseEvaluator:
    def evaluate(self, attack: Attack, response: TargetResponse) -> EvaluationResult:
        raise NotImplementedError
