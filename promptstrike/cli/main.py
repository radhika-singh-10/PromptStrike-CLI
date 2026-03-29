import json
from pathlib import Path
from typing import Optional

import typer

from promptstrike.attacks.loader import load_attack_pack, list_available_packs
from promptstrike.config.loader import load_target_config
from promptstrike.engine.runner import run_api_tests, run_prompt_tests
from promptstrike.engine.agent import run_agentic_tests
from promptstrike.engine.multi_turn_runner import MultiTurnAgenticRunner
from promptstrike.engine.indirect_runner import IndirectAttackRunner
from promptstrike.reporters.json_reporter import write_json_report
from promptstrike.reporters.markdown import write_markdown_report
from promptstrike.reporters.terminal import print_attack_catalog, print_report
from promptstrike.targets.http_api import HttpApiAdapter
from promptstrike.targets.ollama import OllamaTargetAdapter
from promptstrike.targets.openai_compatible import OpenAITargetAdapter
from promptstrike.targets.interactive import InteractiveTargetAdapter

app = typer.Typer(help="PromptStrike CLI: red-team LLM apps for prompt injection risk.")


@app.command("list-attacks")
def list_attacks() -> None:
    packs = list_available_packs()
    print_attack_catalog(packs)


@app.command("test-api")
def test_api(
    url: str,
    pack: str = typer.Option("basic", help="Built-in attack pack name."),
    concurrency: int = typer.Option(5, "--concurrency", "-c", help="Number of concurrent API requests."),
    out: Optional[Path] = typer.Option(None, help="Write JSON report to file."),
) -> None:
    attacks = load_attack_pack(pack)
    report = run_api_tests(url=url, attacks=attacks, concurrency=concurrency)
    print_report(report)
    if out:
        write_json_report(report, out)
        typer.echo(f"Saved report to {out}")


@app.command("test-prompt")
def test_prompt(
    prompt_file: Path,
    pack: str = typer.Option("basic", help="Built-in attack pack name."),
    canary: bool = typer.Option(False, help="Inject a canary secret into prompt context."),
    out: Optional[Path] = typer.Option(None, help="Write JSON report to file."),
) -> None:
    attacks = load_attack_pack(pack)
    report = run_prompt_tests(prompt_file=prompt_file, attacks=attacks, use_canary=canary)
    print_report(report)
    if out:
        write_json_report(report, out)
        typer.echo(f"Saved report to {out}")


@app.command("test-agentic")
def test_agentic(
    url: str,
    model: str = typer.Option("llama3", help="Ollama model to use as the red-team agent."),
    iterations: int = typer.Option(5, help="Maximum number of attack attempts."),
    objective: str = typer.Option("exfiltration", help="Attack category focus (e.g. exfiltration or override)."),
    target_type: str = typer.Option("http", help="Type of target: 'http', 'ollama', 'openai', or 'interactive'"),
    out_json: Optional[Path] = typer.Option(None, help="Write JSON report to file."),
    out_md: Optional[Path] = typer.Option(None, help="Write Markdown report to file."),
) -> None:
    typer.echo(f"Starting multi-turn agentic red-teaming...")
    
    if target_type == "ollama":
        target = OllamaTargetAdapter(model=url)
    elif target_type == "openai":
        target = OpenAITargetAdapter(endpoint_url=url, api_key="dummy")
    elif target_type == "interactive":
        target = InteractiveTargetAdapter()
    else:
        target = HttpApiAdapter(url=url)
        
    runner = MultiTurnAgenticRunner(target_adapter=target, attacker_model=model, max_turns=iterations)
    report = runner.run(objective=objective)
    
    print_report(report)
    if out_json:
        write_json_report(report, out_json)
        typer.echo(f"Saved JSON report to {out_json}")
    if out_md:
        write_markdown_report(report, out_md)
        typer.echo(f"Saved Markdown report to {out_md}")

@app.command("test-indirect")
def test_indirect(
    url: str,
    model: str = typer.Option("llama3", help="Ollama model to use as the red-team agent."),
    objective: str = typer.Option("Bypass safety filters", help="Indirect attack goal."),
    instances: int = typer.Option(3, help="Number of documents to generate."),
    target_type: str = typer.Option("http", help="Type of target: 'http', 'ollama', or 'openai'"),
    out_md: Optional[Path] = typer.Option(None, help="Write Markdown report to file."),
) -> None:
    typer.echo(f"Starting indirect RAG injection testing...")
    
    if target_type == "ollama":
        target = OllamaTargetAdapter(model=url)
    else:
        target = HttpApiAdapter(url=url)
        
    runner = IndirectAttackRunner(target_adapter=target, attacker_model=model)
    report = runner.run(objective=objective, instances=instances)
    
    print_report(report)
    if out_md:
        write_markdown_report(report, out_md)
        typer.echo(f"Saved Markdown report to {out_md}")


@app.command("show-report")
def show_report(report_file: Path) -> None:
    typer.echo(report_file.read_text())


@app.command("show-config")
def show_config(config_file: Path) -> None:
    config = load_target_config(config_file)
    typer.echo(json.dumps(config, indent=2))


@app.command("analyze-workflow")
def analyze_workflow(
    directory: str = typer.Argument(..., help="Path to the AI agent's source code directory."),
) -> None:
    from promptstrike.engine.sast import analyze_directory
    from rich.tree import Tree
    from rich import print as rprint
    from rich.panel import Panel

    typer.echo(f"Running graph-based SAST analysis on {directory}...\n")
    graph = analyze_directory(directory)
    
    if not graph.vulnerabilities:
        rprint("[bold green]✅ No AI security vulnerabilities found in workflow![/bold green]")
    else:
        rprint(f"[bold red]❌ Found {len(graph.vulnerabilities)} Vulnerabilities:[/bold red]")
        for i, vuln in enumerate(graph.vulnerabilities, 1):
            rprint(Panel(
                f"[bold]Risk:[/bold] {vuln.risk}\n[bold]File:[/bold] {vuln.file}:{vuln.line}\n[bold]Description:[/bold] {vuln.description}\n[bold]Mitigation:[/bold] [green]{vuln.mitigation}[/green]",
                title=f"Vulnerability #{i}",
                border_style="red"
            ))
            
    rprint("\n[bold cyan]Dependency Call Graph[/bold cyan]")
    # Group edges by caller
    adjacency = {}
    for caller, callee in graph.edges:
        if caller not in adjacency:
            adjacency[caller] = []
        if callee not in adjacency[caller]:
            adjacency[caller].append(callee)
            
    tree = Tree(directory)
    for caller, callees in adjacency.items():
        node = tree.add(f"[bold yellow]{caller}[/bold yellow]")
        for callee in callees:
            node.add(f"[blue]{callee}[/blue]")
            
    rprint(tree)


@app.command("evaluate")
def evaluate_cmd(
    dataset: str = typer.Argument(..., help="Path to the JSON dataset array for evaluation."),
    model: str = typer.Option("llama3", help="Ollama model to use as the guardrail evaluator."),
    out: Optional[Path] = typer.Option(None, help="Save evaluation metrics and case outputs to a JSON file.")
) -> None:
    from rich import print as rprint
    import json
    from promptstrike.scoring.benchmark import evaluate_test_cases

    typer.echo(f"Evaluating {dataset} using model {model}...")
    
    try:
        results, aggregate = evaluate_test_cases(dataset, model)
    except Exception as e:
        rprint(f"[bold red]Error running evaluation:[bold red] {e}")
        raise typer.Exit(code=1)

    rprint("\n[bold cyan]--- Aggregate Metrics ---[/bold cyan]")
    rprint(json.dumps(aggregate.model_dump(), indent=2))
    
    if out:
        final_output = {
            "aggregate_metrics": aggregate.model_dump(),
            "case_results": [r.model_dump() for r in results]
        }
        out.write_text(json.dumps(final_output, indent=2))
        typer.echo(f"Saved thorough evaluation output to {out}")

@app.command("check")
def check_prompt(
    prompt: str = typer.Argument(..., help="The prompt to evaluate for safety."),
    model: str = typer.Option("llama3", help="Ollama model to use as the evaluator.")
) -> None:
    from rich import print as rprint
    from promptstrike.evaluators.guardrail_agent import evaluate_prompt
    
    rprint(f"[dim]Analyzing via {model}...[/dim]")
    prediction, evidence = evaluate_prompt(prompt, model)
    
    if prediction.is_attack:
        rprint("\n[bold red]🚨 ATTACK DETECTED 🚨[/bold red]")
        rprint(f"[bold red]Action:[/bold red] {prediction.action.upper()}")
        rprint(f"[bold red]Category:[/bold red] {prediction.category}")
        rprint(f"[bold red]Severity:[/bold red] {prediction.severity}")
    else:
        rprint("\n[bold green]✅ SAFE[/bold green]")
        rprint(f"[bold green]Action:[/bold green] {prediction.action.upper()}")
        
    rprint("\n[bold cyan]Evidence/Reasoning:[/bold cyan]")
    if evidence:
        for e in evidence:
            rprint(f"  - [{e.rule_id}]: {e.message}")
    else:
        rprint("  - None")

@app.command("build-dataset")
def build_dataset(
    dataset_file: Path = typer.Argument(..., help="Path to the JSON test suite file to append to."),
    model: str = typer.Option("llama3", help="Ollama model to use as the evaluator.")
) -> None:
    from rich import print as rprint
    from promptstrike.cli.dataset_builder import run_interactive_dataset_builder
    try:
        run_interactive_dataset_builder(model, dataset_file)
    except KeyboardInterrupt:
        rprint("\n[bold magenta]Session ended by user.[/bold magenta]")

if __name__ == "__main__":
    app()
