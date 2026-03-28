from pathlib import Path
import yaml


def load_target_config(path: Path) -> dict:
    return yaml.safe_load(path.read_text()) or {}
