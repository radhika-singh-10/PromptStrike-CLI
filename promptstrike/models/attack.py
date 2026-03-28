from pydantic import BaseModel


class Attack(BaseModel):
    id: str
    name: str
    category: str
    payload: str
    description: str
    severity: str
    tags: list[str] = []
