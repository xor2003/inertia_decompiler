"""Build bounded navigation context for the existing focused-test selector.

Layer: Tooling/gates.
Responsibility: show declared owners, public interfaces, source symbols and
known consumers while keeping test selection in its authoritative router.
"""

from __future__ import annotations

import ast
from pathlib import Path

from .component_catalog import ROOT, Component, load_components

SYMBOL_LIMIT: int = 32


def components_for_files(files: tuple[str, ...]) -> tuple[Component, ...]:
    """Select the most specific declared owners, preserving shared ownership."""
    components = load_components()
    selected: dict[str, Component] = {}
    for path in files:
        matches = [(component, max(len(source) for source in component.sources
                                  if path == source or path.startswith(source + "/")))
                   for component in components if component.owns(path)]
        if matches:
            longest = max(length for _, length in matches)
            for component, length in matches:
                if length == longest:
                    selected[component.name] = component
    return tuple(selected[name] for name in sorted(selected))


def component_focused_tests(files: tuple[str, ...]) -> tuple[str, ...]:
    """Return declared focused controls for owners selected by the existing router."""
    return tuple(dict.fromkeys(target for component in components_for_files(files) for target in component.focus))


def _source_symbols(path: Path) -> dict[str, object]:
    """Read owned definition coordinates without injecting whole module bodies."""
    if not path.is_file() or path.suffix != ".py":
        return {"symbols": [], "symbol_count": 0}
    module = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    definitions = [node for node in module.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
    return {
        "symbols": [{"name": node.name, "line": node.lineno, "end_line": node.end_lineno}
                    for node in definitions[:SYMBOL_LIMIT]],
        "symbol_count": len(definitions),
        "symbols_truncated": len(definitions) > SYMBOL_LIMIT,
    }


def build_task_context(files: tuple[str, ...], tests: tuple[str, ...]) -> dict[str, object]:
    """Describe task scope without changing its tests or claiming exhaustive impact."""
    components = components_for_files(files)
    return {
        "required_contracts": ["AGENTS.md", "reference/agent-execution.md"],
        "owners": [{"name": component.name, "purpose": component.description,
                    "guide": component.guide, "public_api": component.public_api,
                    "dependencies": component.dependencies, "known_consumers": component.consumers}
                   for component in components],
        "sources": [{"path": path, **_source_symbols(ROOT / path)} for path in files],
        "selected_tests": tests,
        "consumer_coverage": "declared consumers only; use graph and source checks before interface changes",
        "focused_command": ["nice", "-n", "10", "env", "PYTHON_JIT=1", ".venv/bin/python", "-m", "pytest",
                            "-q", "--tb=short", "--durations=10", *tests],
    }
