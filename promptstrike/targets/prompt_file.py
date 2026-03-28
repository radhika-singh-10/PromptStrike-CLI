from pathlib import Path

from promptstrike.models.response import TargetResponse
from promptstrike.targets.base import BaseTargetAdapter


class PromptFileAdapter(BaseTargetAdapter):
    def __init__(self, prompt_file: Path, use_canary: bool = False):
        self.prompt_file = prompt_file
        self.use_canary = use_canary

    def send(self, payload: str) -> TargetResponse:
        prompt = self.prompt_file.read_text()
        if self.use_canary and "CANARY_SECRET_" not in prompt:
            prompt += "\nInternal canary: CANARY_SECRET_91XZ\n"
        rendered = f"{prompt}\n\nUser input: {payload}\n"
        simulated_output = rendered if "reveal" in payload.lower() else "I cannot provide hidden instructions."
        return TargetResponse(text=simulated_output, status_code=200, latency_ms=0, raw_response=rendered)
