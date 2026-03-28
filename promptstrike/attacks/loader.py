from pathlib import Path
import yaml

from promptstrike.models.attack import Attack

BUILTIN_ATTACK_DIR = Path(__file__).parent / "builtin"


def list_available_packs() -> dict[str, int]:
    packs = {}
    for file in BUILTIN_ATTACK_DIR.glob("*.yaml"):
        data = yaml.safe_load(file.read_text()) or {}
        packs[file.stem] = len(data.get("attacks", []))
    return packs


def load_attack_pack(pack_name: str) -> list[Attack]:
    file_path = BUILTIN_ATTACK_DIR / f"{pack_name}.yaml"
    if not file_path.exists():
        raise FileNotFoundError(f"Unknown attack pack: {pack_name}")
    data = yaml.safe_load(file_path.read_text()) or {}
    return [Attack(**attack) for attack in data.get("attacks", [])]
