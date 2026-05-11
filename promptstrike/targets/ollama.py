import openai
from typing import Optional
from promptstrike.models.response import TargetResponse

class OllamaTargetAdapter:
    def __init__(self, model: str = "gpt-4o", system_prompt: Optional[str] = None):
        self.url = f"openai/{model}"
        self.model = model
        self.system_prompt = system_prompt
        self._client = openai.OpenAI()

    def send(self, payload: str) -> TargetResponse:
        messages = []
        if self.system_prompt:
            messages.append({"role": "system", "content": self.system_prompt})
        messages.append({"role": "user", "content": payload})

        try:
            resp = self._client.chat.completions.create(model=self.model, messages=messages)
            content = resp.choices[0].message.content
            return TargetResponse(status_code=200, raw_response=content, text=content)
        except openai.APIStatusError as e:
            return TargetResponse(status_code=e.status_code, raw_response=str(e), text=str(e))
        except Exception as e:
            return TargetResponse(status_code=500, raw_response=str(e), text=str(e))
