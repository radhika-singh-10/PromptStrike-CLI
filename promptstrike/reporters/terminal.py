from rich.console import Console
from rich.table import Table

console = Console()


def print_attack_catalog(packs: dict[str, int]) -> None:
    table = Table(title="Available Attack Packs")
    table.add_column("Pack")
    table.add_column("Attacks", justify="right")
    for pack, count in sorted(packs.items()):
        table.add_row(pack, str(count))
    console.print(table)


def print_report(report) -> None:
    summary = Table(title="PromptStrike Report")
    summary.add_column("Target")
    summary.add_column("Total")
    summary.add_column("Successful")
    summary.add_column("Risk")
    summary.add_row(report.target, str(report.total_attacks), str(report.successful_attacks), report.overall_risk)
    console.print(summary)

    table = Table(title="Findings")
    table.add_column("ID")
    table.add_column("Category")
    table.add_column("Severity")
    table.add_column("Status")
    table.add_column("Evidence")
    for finding in report.findings:
        table.add_row(
            finding.attack_id,
            finding.category,
            finding.severity,
            f"🔴 {finding.status}" if finding.status == "COMPROMISED" else (f"⚠️ {finding.status}" if finding.status in ["INCONCLUSIVE", "ERROR"] else f"🟢 {finding.status}"),
            finding.evidence[:80],
        )
    console.print(table)
