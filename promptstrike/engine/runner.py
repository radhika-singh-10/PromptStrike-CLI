from pathlib import Path
from typing import Iterable

from promptstrike.evaluators.rules import evaluate_response
from promptstrike.models.attack import Attack
from promptstrike.models.report import Report
from promptstrike.models.result import Finding
from promptstrike.scoring.risk import compute_overall_risk, summarize_severity
from promptstrike.targets.http_api import HttpApiAdapter
from promptstrike.targets.prompt_file import PromptFileAdapter


def run_api_tests(url: str, attacks: Iterable[Attack]) -> Report:
    adapter = HttpApiAdapter(url=url)
    findings = []
    for attack in attacks:
        response = adapter.send(attack.payload)
        result = evaluate_response(attack, response)
        findings.append(
            Finding(
                attack_id=attack.id,
                attack_name=attack.name,
                category=attack.category,
                severity=attack.severity,
                compromised=result.success,
                evidence="; ".join(result.evidence) if result.evidence else result.notes,
                recommendation="Add stronger prompt boundaries and output filtering.",
            )
        )
    return _build_report(target=url, findings=findings)


def run_prompt_tests(prompt_file: Path, attacks: Iterable[Attack], use_canary: bool = False) -> Report:
    adapter = PromptFileAdapter(prompt_file=prompt_file, use_canary=use_canary)
    findings = []
    for attack in attacks:
        response = adapter.send(attack.payload)
        result = evaluate_response(attack, response)
        findings.append(
            Finding(
                attack_id=attack.id,
                attack_name=attack.name,
                category=attack.category,
                severity=attack.severity,
                compromised=result.success,
                evidence="; ".join(result.evidence) if result.evidence else result.notes,
                recommendation="Mask hidden instructions and isolate secrets from prompt context.",
            )
        )
    return _build_report(target=str(prompt_file), findings=findings)


def _build_report(target: str, findings: list[Finding]) -> Report:
    successful = sum(1 for f in findings if f.compromised)
    return Report(
        target=target,
        total_attacks=len(findings),
        successful_attacks=successful,
        overall_risk=compute_overall_risk(findings),
        severity_summary=summarize_severity(findings),
        findings=findings,
    )
