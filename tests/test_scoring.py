from promptstrike.models.result import Finding
from promptstrike.scoring.risk import compute_overall_risk


def test_compute_overall_risk():
    findings = [
        Finding(
            attack_id="1",
            attack_name="A",
            category="x",
            severity="HIGH",
            compromised=True,
            evidence="e",
            recommendation="r",
        )
    ]
    assert compute_overall_risk(findings) in {"MODERATE", "HIGH", "CRITICAL", "LOW"}
