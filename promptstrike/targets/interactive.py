from rich import print as rprint
from rich.prompt import Prompt

from promptstrike.models.response import TargetResponse
from promptstrike.targets.base import BaseTargetAdapter


class InteractiveTargetAdapter(BaseTargetAdapter):
    def __init__(self):
        self.url = "human-cli-user"

    def send(self, payload: str) -> TargetResponse:
        rprint("\n[bold yellow]⚠️ ATTACK INCOMING:[/bold yellow]")
        rprint(f"[white]{payload}[/white]\n")
        
        user_response = Prompt.ask("[bold cyan]Enter your defense response as the Target[/bold cyan]")
        
        return TargetResponse(
            text=user_response,
            status_code=200,
            latency_ms=0,
            raw_response=user_response,
        )
