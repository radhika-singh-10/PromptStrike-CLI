import ollama
from typing import Optional
from promptstrike.models.response import TargetResponse

class OllamaTargetAdapter:
    def __init__(self, model: str = "llama3", system_prompt: Optional[str] = None):
        self.url = f"ollama/{model}"
        self.model = model
        self.system_prompt = system_prompt

    def send(self, payload: str) -> TargetResponse:
        messages = []
        if self.system_prompt:
            messages.append({"role": "system", "content": self.system_prompt})
        messages.append({"role": "user", "content": payload})

        try:
            resp = ollama.chat(model=self.model, messages=messages)
            content = resp["message"]["content"]
            return TargetResponse(status_code=200, raw_response=content, text=content)
        except ollama.ResponseError as e:
            return TargetResponse(status_code=e.status_code, raw_response=str(e), text=str(e))
        except Exception as e:
            return TargetResponse(status_code=500, raw_response=str(e), text=str(e))
