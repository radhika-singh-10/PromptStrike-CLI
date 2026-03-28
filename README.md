# PromptStrike CLI

PromptStrike CLI is a Python-based red-teaming framework for testing LLM applications against prompt injection, prompt exfiltration, secret leakage, jailbreak-style instruction override, and unsafe tool-triggering behavior.

## MVP Features
- Built-in YAML attack packs
- HTTP API target adapter
- Prompt-file target adapter
- Rule-based evaluator
- Rich terminal output
- JSON report export
- Canary secret leakage testing

## Project Structure
```text
PromptStrikeCLI/
├── examples/
├── promptstrike/
│   ├── attacks/
│   ├── cli/
│   ├── config/
│   ├── engine/
│   ├── evaluators/
│   ├── models/
│   ├── reporters/
│   ├── scoring/
│   ├── targets/
│   └── utils/
├── tests/
├── pyproject.toml
└── README.md
```

## Quick Start
```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
promptstrike list-attacks
promptstrike test-api http://localhost:8000/chat --pack basic
```

## Example Commands
```bash
promptstrike list-attacks
promptstrike test-api http://localhost:8000/chat --pack basic --out report.json
promptstrike test-prompt examples/vulnerable_prompt.txt --pack exfiltration --canary
```

## Notes
This scaffold includes all major files and folders needed for the MVP. Many files contain starter implementations and TODO comments so you can build features incrementally.
