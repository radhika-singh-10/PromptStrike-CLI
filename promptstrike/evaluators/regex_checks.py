import re


SECRET_PATTERNS = [
    r"sk-[A-Za-z0-9]{10,}",
    r"AKIA[0-9A-Z]{16}",
    r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9._-]+\.[A-Za-z0-9._-]+",
]


def find_secret_like_strings(text: str) -> list[str]:
    hits = []
    for pattern in SECRET_PATTERNS:
        hits.extend(re.findall(pattern, text))
    return hits
