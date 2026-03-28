from promptstrike.models.response import TargetResponse


class BaseTargetAdapter:
    def send(self, payload: str) -> TargetResponse:
        raise NotImplementedError
