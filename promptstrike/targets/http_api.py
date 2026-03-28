import time
import httpx

from promptstrike.models.response import TargetResponse
from promptstrike.targets.base import BaseTargetAdapter


class HttpApiAdapter(BaseTargetAdapter):
    def __init__(self, url: str, message_field: str = "message", timeout: int = 20):
        self.url = url
        self.message_field = message_field
        self.timeout = timeout

    def send(self, payload: str) -> TargetResponse:
        start = time.perf_counter()
        try:
            response = httpx.post(self.url, json={self.message_field: payload}, timeout=self.timeout)
            latency_ms = int((time.perf_counter() - start) * 1000)
            text = self._extract_text(response)
            return TargetResponse(
                text=text,
                status_code=response.status_code,
                latency_ms=latency_ms,
                raw_response=response.text,
            )
        except Exception as exc:
            latency_ms = int((time.perf_counter() - start) * 1000)
            return TargetResponse(text="", status_code=None, latency_ms=latency_ms, error=str(exc))

    @staticmethod
    def _extract_text(response: httpx.Response) -> str:
        try:
            data = response.json()
            for key in ("response", "text", "answer", "message"):
                if key in data and isinstance(data[key], str):
                    return data[key]
            return str(data)
        except Exception:
            return response.text
