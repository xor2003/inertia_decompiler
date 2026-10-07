"""Build a reusable AST index for pytest ownership checks.

Layer: Tooling/gates.
Responsibility: parse each test source once per content version and expose its
collectable nodes and skip/xfail call locations.
"""

from __future__ import annotations

import ast
import hashlib
from dataclasses import dataclass, replace
from pathlib import Path

from tools.dev.pytest_assertion_facts import PytestNodeFacts, expectation_kind, resolve_local_helper_facts
from tools.dev.pytest_call_hints import extract_pytest_call_hints
from tools.dev.pytest_source_structure import (
    PytestFactsByNode,
    PytestFactsProvider,
    PytestSourceIndex,
    build_pytest_structure_index,
)
from tools.dev.pytest_source_structure_cache import (
    CachedPytestStructure,
    load_cached_pytest_structure,
    store_cached_pytest_structure,
)

_INPUT_SUFFIXES = (
    ".asm",
    ".c",
    ".cod",
    ".com",
    ".exe",
    ".json",
    ".lst",
    ".map",
    ".pat",
)


@dataclass(slots=True)
class _MutableNodeFacts:
    """Mutable visitor state used to build immutable node facts."""

    call_names: set[str]
    assertion_count: int
    assertion_kinds: set[str]
    expectation_count: int
    expectation_kinds: set[str]
    evidence_hints: set[str]
    module_hints: set[str]
    function_address_hints: set[int]
    input_hints: set[str]
    option_hints: set[str]
    subprocess_call_count: int

    @classmethod
    def empty(cls) -> _MutableNodeFacts:
        """Create empty facts for one selected scope."""

        return cls(set(), 0, set(), 0, set(), set(), set(), set(), set(), set(), 0)

    def freeze(self) -> PytestNodeFacts:
        """Return deterministic immutable facts."""

        return PytestNodeFacts(
            call_names=tuple(sorted(self.call_names)),
            effective_call_names=tuple(sorted(self.call_names)),
            assertion_count=self.assertion_count,
            effective_assertion_count=self.assertion_count,
            assertion_kinds=tuple(sorted(self.assertion_kinds)),
            expectation_count=self.expectation_count,
            effective_expectation_count=self.expectation_count,
            expectation_kinds=tuple(sorted(self.expectation_kinds)),
            evidence_hints=tuple(sorted(self.evidence_hints)),
            module_hints=tuple(sorted(self.module_hints)),
            function_address_hints=tuple(sorted(self.function_address_hints)),
            effective_function_address_hints=tuple(sorted(self.function_address_hints)),
            input_hints=tuple(sorted(self.input_hints)),
            effective_input_hints=tuple(sorted(self.input_hints)),
            option_hints=tuple(sorted(self.option_hints)),
            effective_option_hints=tuple(sorted(self.option_hints)),
            subprocess_call_count=self.subprocess_call_count,
            effective_subprocess_call_count=self.subprocess_call_count,
        )


_SOURCE_INDEX_CACHE: dict[tuple[Path, frozenset[str]], tuple[str, PytestSourceIndex]] = {}


def _dotted_attribute_name(node: ast.expr) -> str | None:
    """Return a dotted name for a simple call expression."""

    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _dotted_attribute_name(node.value)
        return node.attr if parent is None else f"{parent}.{node.attr}"
    return None


class _PytestSourceVisitor(ast.NodeVisitor):
    """Collect pytest selectors and skip scope in one source traversal."""

    def __init__(self, skip_calls: frozenset[str]) -> None:
        self._skip_calls = skip_calls
        self._scope: list[tuple[str, str]] = []
        self._active_selectors: list[str] = [""]
        self.nodes: set[str] = set()
        self.skip_lines: dict[str, list[int]] = {"": []}
        self.facts: dict[str, _MutableNodeFacts] = {"": _MutableNodeFacts.empty()}

    def _selected_function_name(self, name: str) -> str | None:
        """Return the pytest selector for a directly collectable function."""

        if not self._scope:
            return name
        if len(self._scope) == 1 and self._scope[0][0] == "class":
            return f"{self._scope[0][1]}::{name}"
        return None

    def _visit_selected_scope(self, node: ast.AST, *, kind: str, name: str, selector: str | None) -> None:
        """Visit one scope while attributing calls to every selected owner."""

        self._scope.append((kind, name))
        if selector is not None:
            self.nodes.add(selector)
            self.skip_lines[selector] = []
            self.facts[selector] = _MutableNodeFacts.empty()
            self._active_selectors.append(selector)
        self.generic_visit(node)
        if selector is not None:
            self._active_selectors.pop()
        self._scope.pop()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Index top-level pytest classes and their contained calls."""

        selector = node.name if not self._scope else None
        self._visit_selected_scope(node, kind="class", name=node.name, selector=selector)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Index top-level functions and direct pytest class methods."""

        self._visit_selected_scope(
            node,
            kind="function",
            name=node.name,
            selector=self._selected_function_name(node.name),
        )

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Index async functions using the same pytest selector rules."""

        self._visit_selected_scope(
            node,
            kind="function",
            name=node.name,
            selector=self._selected_function_name(node.name),
        )

    def visit_Call(self, node: ast.Call) -> None:
        """Attribute one skip/xfail call to all enclosing pytest selectors."""

        call_name = _dotted_attribute_name(node.func)
        if call_name in self._skip_calls:
            for selector in self._active_selectors:
                self.skip_lines[selector].append(node.lineno)
        if call_name is not None:
            call_hints = extract_pytest_call_hints(call_name, node)
            for selector in self._active_selectors:
                facts = self.facts[selector]
                facts.call_names.add(call_name)
                facts.function_address_hints.update(call_hints.function_addresses)
                facts.input_hints.update(call_hints.input_symbols)
                if call_name.startswith("subprocess."):
                    facts.subprocess_call_count += 1
                kind = expectation_kind(call_name)
                if call_name.startswith("subprocess.") and any(
                    keyword.arg == "check" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True
                    for keyword in node.keywords
                ):
                    kind = "subprocess-check"
                if kind is not None:
                    facts.expectation_count += 1
                    facts.expectation_kinds.add(kind)
                    facts.evidence_hints.add("explicit-expectation")
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        """Record imported modules as static ownership evidence."""

        for selector in self._active_selectors:
            self.facts[selector].module_hints.update(alias.name for alias in node.names)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Record from-import modules as static ownership evidence."""

        module = f"{'.' * node.level}{node.module or ''}"
        for selector in self._active_selectors:
            self.facts[selector].module_hints.add(module)

    def visit_Raise(self, node: ast.Raise) -> None:
        """Treat an explicit AssertionError raise as a test expectation."""

        exception_name = _dotted_attribute_name(node.exc.func) if isinstance(node.exc, ast.Call) else None
        if exception_name == "AssertionError":
            for selector in self._active_selectors:
                facts = self.facts[selector]
                facts.expectation_count += 1
                facts.expectation_kinds.add("assertion-error")
                facts.evidence_hints.add("explicit-expectation")
        self.generic_visit(node)

    def visit_Assert(self, node: ast.Assert) -> None:
        """Record assertion operators and durable evidence categories."""

        assertion_kinds: set[str] = set()
        assertion_names: set[str] = set()
        for child in ast.walk(node.test):
            if isinstance(child, ast.cmpop | ast.boolop | ast.unaryop):
                assertion_kinds.add(child.__class__.__name__)
            if isinstance(child, ast.expr) and (name := _dotted_attribute_name(child)) is not None:
                assertion_names.add(name)
        lowered_names = " ".join(assertion_names).lower()
        evidence = set()
        for token, label in (
            ("returncode", "exit-code"),
            ("stdout", "output"),
            ("stderr", "diagnostics"),
            ("validation", "tail-validation"),
            ("compile", "recompilation"),
            ("cache", "cache-behavior"),
        ):
            if token in lowered_names:
                evidence.add(label)
        for selector in self._active_selectors:
            facts = self.facts[selector]
            facts.assertion_count += 1
            facts.assertion_kinds.update(assertion_kinds)
            facts.evidence_hints.update(evidence)
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        """Record explicit command options and fixture-like input literals."""

        if not isinstance(node.value, str):
            return
        value = node.value.strip()
        lowered = value.lower()
        for selector in self._active_selectors:
            facts = self.facts[selector]
            if value.startswith(("--", "INERTIA_")):
                facts.option_hints.add(value)
            if lowered.endswith(_INPUT_SUFFIXES):
                facts.input_hints.add(value)


def build_pytest_source_index(
    source: str,
    path: Path,
    skip_calls: frozenset[str],
) -> PytestSourceIndex:
    """Parse source and build all node-specific indexes in one request."""

    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError:
        return PytestSourceIndex(frozenset(), (), PytestFactsProvider(lambda: ()))
    visitor = _PytestSourceVisitor(skip_calls)
    visitor.visit(tree)
    direct_facts = {name: facts.freeze() for name, facts in visitor.facts.items()}
    module_hints = direct_facts[""].module_hints
    direct_facts = {
        name: replace(facts, module_hints=tuple(sorted(set(facts.module_hints) | set(module_hints))))
        for name, facts in direct_facts.items()
    }
    facts_by_node: PytestFactsByNode = tuple(
        (name, resolve_local_helper_facts(name, direct_facts)) for name in visitor.facts
    )
    return PytestSourceIndex(
        nodes=frozenset(visitor.nodes),
        skip_xfail_lines_by_node=tuple((name, tuple(lines)) for name, lines in visitor.skip_lines.items()),
        _facts=PytestFactsProvider(lambda: facts_by_node, facts_by_node),
    )


def load_pytest_source_index(path: Path, skip_calls: frozenset[str]) -> PytestSourceIndex:
    """Return a content-invalidated source index for one test file."""

    source = path.read_text(encoding="utf-8")
    digest = hashlib.sha256(source.encode("utf-8")).hexdigest()
    cache_key = (path.resolve(), skip_calls)
    cached = _SOURCE_INDEX_CACHE.get(cache_key)
    if cached is not None and cached[0] == digest:
        return cached[1]

    def load_facts() -> PytestFactsByNode:
        """Build full facts from the captured content version."""

        return build_pytest_source_index(source, path, skip_calls).all_facts()

    facts = PytestFactsProvider(load_facts)
    persisted = load_cached_pytest_structure(path, digest, skip_calls)
    if persisted is not None:
        index = PytestSourceIndex(
            persisted.nodes,
            persisted.skip_xfail_lines_by_node,
            facts,
        )
    else:
        try:
            tree = ast.parse(source, filename=str(path))
        except SyntaxError:
            index = PytestSourceIndex(frozenset(), (), facts)
        else:
            index = build_pytest_structure_index(tree, skip_calls, facts)
            store_cached_pytest_structure(
                path,
                digest,
                skip_calls,
                CachedPytestStructure(index.nodes, index.skip_xfail_lines_by_node),
            )
    _SOURCE_INDEX_CACHE[cache_key] = (digest, index)
    return index


def clear_pytest_source_index_cache() -> None:
    """Clear request-local source indexes for tests and explicit new runs."""

    _SOURCE_INDEX_CACHE.clear()
