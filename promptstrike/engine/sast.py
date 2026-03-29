import ast
import os
from pathlib import Path
from pydantic import BaseModel
from collections import defaultdict


class Vulnerability(BaseModel):
    file: str
    line: int
    risk: str
    description: str
    mitigation: str


class DependencyGraph:
    def __init__(self):
        self.nodes = set()
        self.edges = []
        self.vulnerabilities = []

    def add_edge(self, caller, callee):
        self.nodes.add(caller)
        self.nodes.add(callee)
        self.edges.append((caller, callee))


class CodeAnalyzer(ast.NodeVisitor):
    def __init__(self, filepath, graph):
        self.filepath = filepath
        self.graph = graph
        self.current_function = "<module>"

    def visit_FunctionDef(self, node):
        prev_func = self.current_function
        self.current_function = node.name
        self.generic_visit(node)
        self.current_function = prev_func

    def visit_Call(self, node):
        func_name = None
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                func_name = f"{node.func.value.id}.{node.func.attr}"
            else:
                func_name = node.func.attr

        if func_name:
            self.graph.add_edge(self.current_function, func_name)
            self._check_security_rules(func_name, node)

        self.generic_visit(node)

    def _check_security_rules(self, func_name: str, node: ast.Call):
        # Rule 1: LLM Call Detected (Graph building and basic hygiene check)
        llm_calls = ["ollama.chat", "ollama.generate", "ChatCompletion.create", "openai.completions"]
        if any(call in func_name for call in llm_calls):
            self.graph.vulnerabilities.append(
                Vulnerability(
                    file=self.filepath,
                    line=node.lineno,
                    risk="Prompt Injection Surface",
                    description=f"LLM invocation found ({func_name}). Ensure user inputs are sanitized before being passed into the prompt context.",
                    mitigation="Implement prompt boundaries (e.g., XML tags) and validate output formats."
                )
            )

        # Rule 2: Unsafe Execution Tool
        unsafe_calls = ["os.system", "os.popen", "subprocess.run", "subprocess.Popen", "eval", "exec"]
        if any(call in func_name for call in unsafe_calls):
            self.graph.vulnerabilities.append(
                Vulnerability(
                    file=self.filepath,
                    line=node.lineno,
                    risk="Unsafe Tool Execution",
                    description=f"Dangerous system call detected ({func_name}). If an unauthorized LLM instructs the agent to run this tool, it could lead to Remote Code Execution.",
                    mitigation="Use sandboxed execution environments, isolate the process, or restrict available commands using an allowlist."
                )
            )
            
        # Rule 3: Data Leakage (Writing to sensitive streams without redaction)
        leakage_calls = ["open", "json.dump", "logging.info", "print"]
        # In a real tool this would track taint from LLM outputs, here we just flag them if they share a function with an LLM call
        # We handle this simpler by just tracking nodes

def analyze_directory(directory: str) -> DependencyGraph:
    graph = DependencyGraph()
    path = Path(directory)
    
    for py_file in path.rglob("*.py"):
        if "venv" in str(py_file) or ".tox" in str(py_file):
            continue
            
        try:
            tree = ast.parse(py_file.read_text("utf-8"))
            analyzer = CodeAnalyzer(str(py_file.relative_to(path)), graph)
            analyzer.visit(tree)
        except Exception:
            # Skip files that can't be parsed
            pass
            
    return graph
