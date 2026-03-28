import re


def mask_canaries(text: str) -> str:
    return re.sub(r"CANARY_SECRET_[A-Z0-9_]+", "CANARY_SECRET_[REDACTED]", text)
