from pathlib import Path


def write_json_report(report, output_path: Path) -> None:
    output_path.write_text(report.model_dump_json(indent=2))
