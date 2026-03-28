from promptstrike.attacks.loader import load_attack_pack


def test_load_attack_pack():
    attacks = load_attack_pack("basic")
    assert len(attacks) >= 1
    assert attacks[0].id.startswith("PI-")
