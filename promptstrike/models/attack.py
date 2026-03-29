from pydantic import BaseModel


class Attack(BaseModel):
    id: str
    name: str
    category: str
    payload: str
    description: str
    severity: str
    expected_behavior: str = "REFUSE"
    tags: list[str] = []
