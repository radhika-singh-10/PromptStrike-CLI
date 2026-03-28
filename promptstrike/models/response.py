from pydantic import BaseModel


class TargetResponse(BaseModel):
    text: str
    status_code: int | None = None
    latency_ms: int = 0
    raw_response: dict | str | None = None
    error: str | None = None
