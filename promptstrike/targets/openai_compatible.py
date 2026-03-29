import json
import httpx
from typing import Optional
from promptstrike.models.response import TargetResponse

class OpenAITargetAdapter:
    def __init__(self, endpoint_url: str, api_key: str, model_id: str = "gpt-3.5-turbo", system_prompt: Optional[str] = None):
        self.url = endpoint_url
        self.api_key = api_key
        self.model_id = model_id
        self.system_prompt = system_prompt

    def send(self, payload: str) -> TargetResponse:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        messages = []
        if self.system_prompt:
            messages.append({"role": "system", "content": self.system_prompt})
        messages.append({"role": "user", "content": payload})

        data = {
            "model": self.model_id,
            "messages": messages,
            "temperature": 0.0
        }

        try:
            resp = httpx.post(self.url, headers=headers, json=data, timeout=30.0)
            resp.raise_for_status()
            
            resp_data = resp.json()
            # Extract content from typical OpenAI response
            content = resp_data.get("choices", [{}])[0].get("message", {}).get("content", "")
            return TargetResponse(status_code=resp.status_code, raw_response=resp.text, text=content)
            
        except httpx.HTTPError as e:
            msg = f"HTTP Error: {e}"
            if hasattr(e, "response") and e.response:
                msg += f" | Response: {e.response.text}"
            return TargetResponse(status_code=getattr(e.response, 'status_code', 500), raw_response=msg, text=msg)
