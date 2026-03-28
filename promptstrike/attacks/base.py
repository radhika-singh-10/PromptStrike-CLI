from promptstrike.models.attack import Attack


class BaseAttackGenerator:
    def generate(self) -> list[Attack]:
        raise NotImplementedError
