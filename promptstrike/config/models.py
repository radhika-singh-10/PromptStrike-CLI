from pydantic import BaseModel, Field


class RuntimeConfig(BaseModel):
    timeout_seconds: int = Field(default=20)
    max_retries: int = Field(default=1)
    concurrency: int = Field(default=1)
