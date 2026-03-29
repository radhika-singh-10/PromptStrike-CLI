import json
from pathlib import Path
from uuid import uuid4
from rich import print as rprint
from rich.prompt import Prompt, Confirm

from promptstrike.evaluators.guardrail_agent import evaluate_prompt

def run_interactive_dataset_builder(model: str, output_file: Path) -> None:
    dataset = []
    
    if output_file.exists():
        try:
            content = output_file.read_text()
            if content.strip():
                dataset = json.loads(content)
                rprint(f"[dim]Loaded {len(dataset)} existing cases from {output_file}[/dim]")
        except Exception as e:
            rprint(f"[bold red]Failed to load existing dataset. Starting fresh. Error: {e}[/bold red]")
            
    rprint(f"[bold magenta]PromptStrike Interactive Dataset Builder[/bold magenta]")
    rprint("Type your prompt to evaluate and add it to the dataset! Type [bold red]'exit'[/bold red] to finish.")
    
    added_count = 0
    
    while True:
        rprint("\n" + "-"*50)
        user_input = Prompt.ask("[bold cyan]Prompt[/bold cyan]")
        
        if user_input.strip().lower() in ["exit", "q", "quit"]:
            break
            
        if not user_input.strip():
            continue
            
        rprint(f"[dim]Evaluating against {model}...[/dim]")
        
        prediction, evidence = evaluate_prompt(user_input, model)
        
        status_color = "red" if prediction.is_attack else "green"
        rprint(f"[{status_color}]Detected as Attack:[/{status_color}] {prediction.is_attack}")
        if prediction.is_attack:
            rprint(f"[{status_color}]Category:[/{status_color}] {prediction.category}")
            rprint(f"[{status_color}]Severity:[/{status_color}] {prediction.severity}")
        
        # Human-in-the-loop override
        is_correct = Confirm.ask("[bold yellow]Is this classification correct?[/bold yellow]", default=True)
        
        final_is_attack = prediction.is_attack
        final_category = prediction.category
        final_severity = prediction.severity
        
        if not is_correct:
            final_is_attack = Confirm.ask("[white]Is it actually an attack?[/white]", default=not prediction.is_attack)
            if final_is_attack:
                final_category = Prompt.ask("[white]What is the correct category? (e.g. prompt_exfiltration)[/white]", default=prediction.category or "unknown_attack")
                final_severity = Prompt.ask("[white]What is the severity? (low/medium/high/critical)[/white]", default="medium")
            else:
                final_category = None
                final_severity = None
                
        # Structure payload
        case_id = f"CUSTOM-{uuid4().hex[:6].upper()}"
        new_case = {
            "id": case_id,
            "prompt": user_input,
            "is_attack": final_is_attack,
            "category": final_category,
            "severity": final_severity,
            "should_block": final_is_attack,
            "expected_behavior": "REFUSE" if final_is_attack else "ANSWER",
            "source": "cli_builder"
        }
        
        dataset.append(new_case)
        added_count += 1
        rprint(f"[bold green]Added {case_id} to dataset![/bold green]")
        
        # Save dynamically so data isn't lost if it crashes
        try:
            output_file.write_text(json.dumps(dataset, indent=2))
        except Exception as e:
            rprint(f"[bold red]Failed to save to {output_file}: {e}[/bold red]")
            
    rprint(f"\n[bold magenta]Session ended.[/bold magenta] Added {added_count} new cases to {output_file}")
