# PromptStrike Architecture

This document provides visual overviews of the PromptStrike CLI architecture, detailing the system components and the execution flows for both static and agentic run modes.

## Graphical Diagrams

You can find the high-resolution, uncolored SVG graphical files for these diagrams located in the `/docs` folder:
- [System Architecture (Graphical SVG)](docs/system_architecture.svg)
- [Agentic Flow (Graphical SVG)](docs/agentic_flow.svg)
- [Static Flow (Graphical SVG)](docs/static_flow.svg)

## 5-State Enum Evaluation & Dataset Builder Flowcharts
*New robust diagrams built native in Mermaid detailing our latest updates:*
- [The 5-State Measurement Enum Lifecycle](docs/enum_evaluation_flow.md)
- [Interactive Dataset Builder REPL Flow](docs/dataset_builder_flow.md)

---

## 1. System Architecture

```mermaid
graph TD
    User((User))
    CLI["CLI (Typer)\n`main.py`"]
    
    subgraph Engine Layer
        StaticRunner["Static Runner\n`runner.py`"]
        AgentRunner["MultiTurnAgenticRunner\n`multi_turn_runner.py`"]
        AttackLoader["Attack Loader\n(YAML)"]
    end

    subgraph Evaluation Layer
        RulesEvaluator["Rules Evaluator\n(Regex/Static)"]
        LLMJudge["Enum Measurement Engine\n(5-State Status)"]
    end
    
    subgraph Target Adapters
        APIAdapter["HTTP API Adapter"]
        PromptAdapter["Prompt File Adapter"]
        OllamaAdapter["Ollama Native Adapter"]
        OpenAIAdapter["OpenAI API Adapter"]
        InteractiveAdapter["Human CLI Adapter"]
    end

    LocalOllama(("Ollama (Local LLM)"))
    ExternalTarget(("Target App / API"))
    HumanUser(("Human Target"))

    User -->|Runs Commands| CLI
    CLI -->|test-api/test-prompt| StaticRunner
    CLI -->|test-agentic| AgentRunner
    
    StaticRunner -->|Loads| AttackLoader
    
    AgentRunner -->|Generates Attack| LocalOllama
    
    StaticRunner -->|Sends Payload| APIAdapter
    StaticRunner -->|Sends Payload| PromptAdapter
    
    AgentRunner -->|Sends Payload| APIAdapter
    AgentRunner -->|Sends Payload| OllamaAdapter
    AgentRunner -->|Sends Payload| OpenAIAdapter
    AgentRunner -->|Interactive Defense| InteractiveAdapter
    
    APIAdapter -->|HTTP Request| ExternalTarget
    ExternalTarget -->|Response| APIAdapter
    InteractiveAdapter -->|Prompts CLI| HumanUser
    
    StaticRunner -->|Validates| RulesEvaluator
    AgentRunner -->|Extracts Status Enum| LLMJudge
    LLMJudge -->|Chat| LocalOllama
```

## 2. Abstract Flow Diagrams

### Agentic Flow (`test-agentic`)

```mermaid
sequenceDiagram
    actor User
    participant CLI as main.py
    participant Agent as AgentRunner
    participant Ollama as Local Ollama
    participant Target as External API
    participant Judge as LLM Judge (Ollama)

    User->>CLI: promptstrike test-agentic --objective "Leak Data"
    CLI->>Agent: run_agentic_tests(objective, iterations)
    
    loop Max Iterations
        Agent->>Ollama: Generate Attack Payload (History + Objective)
        Ollama-->>Agent: JSON (Payload, Technique)
        
        Agent->>Target: Send Attack Payload
        Target-->>Agent: Target Response
        
        Agent->>Judge: evaluate_with_llm(Attack, Response, ExpectedBehavior)
        Judge-->>Agent: Status Enum (COMPROMISED, SECURE, INCONCLUSIVE)
        
        alt State: INCONCLUSIVE
            Agent->>Agent: Network Error / Target Down. Break Loop Early!
        else State: COMPROMISED
            Agent->>Agent: Objective Achieved. Break Loop Early!
        else State: SECURE
            Agent->>Agent: Safely Rejected. Append failure to History.
        end
    end
    
    Agent-->>CLI: Final Status Report
    CLI-->>User: Rich Terminal Tables 
```

### Static Execution Flow (`test-api` with --concurrency)

```mermaid
sequenceDiagram
    actor User
    participant CLI as main.py
    participant Runner as StaticRunner
    participant ThreadPool as ThreadPoolExecutor
    participant ExtTarget as Target API
    participant RuleEval as Rules Evaluator

    User->>CLI: promptstrike test-api --pack basic -c 5
    CLI->>Runner: run_api_tests(attacks, concurrency=5)
    
    Runner->>ThreadPool: Submit Attacks (max 5 workers)
    
    par Attack 1
        ThreadPool->>ExtTarget: Send Payload 1
        ExtTarget-->>ThreadPool: Response 1
        ThreadPool->>RuleEval: evaluate_response(1)
        RuleEval-->>ThreadPool: Result 1
    and Attack 2
        ThreadPool->>ExtTarget: Send Payload 2
        ExtTarget-->>ThreadPool: Response 2
        ThreadPool->>RuleEval: evaluate_response(2)
        RuleEval-->>ThreadPool: Result 2
    end
    
    ThreadPool-->>Runner: Collect all Findings
    Runner-->>CLI: Final Aggregate Report
    CLI-->>User: Terminal Output
```
