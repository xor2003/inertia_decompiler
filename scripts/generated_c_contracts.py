"""Evaluate fixture expectations against generated C syntax.

Layer: Tooling/gates.
Responsibility: parse generated C and enforce source-backed structural fixture
contracts without changing decompiler output or recovering semantics.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, cast

from pycparser import c_ast, c_parser

if __package__:
    from .generated_c_indexed_argument_contract import (
        IndexedArgumentUseRequirement,
        missing_indexed_argument_uses,
    )
else:
    from generated_c_indexed_argument_contract import (
        IndexedArgumentUseRequirement,
        missing_indexed_argument_uses,
    )

_PARSE_PREFIX: str = (
    "#include <limits.h>\n"
    "typedef _Bool bool;\n"
    "typedef signed char int8_t;\n"
    "typedef unsigned char uint8_t;\n"
    "typedef signed short int16_t;\n"
    "typedef unsigned short uint16_t;\n"
    "typedef signed long int32_t;\n"
    "typedef unsigned long uint32_t;\n"
    "uint16_t SEG_U16(uint16_t segment, uint16_t offset);\n"
    "void *SEG_PTR(uint16_t segment, uint16_t offset);\n"
    "uint16_t PTR_U16(void *pointer);\n"
    "uint32_t PTR_U32(void *pointer);\n"
)
_PRESERVED_RUNTIME_MACRO_PREFIXES = (
    "#define SEG_U16(",
    "#define SEG_PTR(",
    "#define PTR_U16(",
    "#define PTR_U32(",
)


class GeneratedCContractStatus(StrEnum):
    """Typed terminal status for one generated-C fixture contract."""

    NOT_REQUIRED = "not_required"
    PASSED = "passed"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class CallGuardedAssignmentRequirement:
    """Require an assignment to remain inside one call-guarded true branch."""

    guard_call: str
    guard_argument: int
    assignment_name: str
    assignment_value: int

    def to_json(self) -> dict[str, object]:
        """Return a stable JSON representation."""
        return {
            "guard_call": self.guard_call,
            "guard_argument": self.guard_argument,
            "assignment_name": self.assignment_name,
            "assignment_value": self.assignment_value,
        }

    @classmethod
    def from_json(cls, raw: object) -> CallGuardedAssignmentRequirement | None:
        """Parse one persisted structural requirement."""
        if not isinstance(raw, dict):
            return None
        guard_call = raw.get("guard_call")
        guard_argument = raw.get("guard_argument")
        assignment_name = raw.get("assignment_name")
        assignment_value = raw.get("assignment_value")
        if (
            not isinstance(guard_call, str)
            or not isinstance(guard_argument, int)
            or isinstance(guard_argument, bool)
            or not isinstance(assignment_name, str)
            or not isinstance(assignment_value, int)
            or isinstance(assignment_value, bool)
        ):
            return None
        return cls(guard_call, guard_argument, assignment_name, assignment_value)

    def label(self) -> str:
        """Return a concise report label for this requirement."""
        return (
            f"{self.assignment_name}={self.assignment_value} under "
            f"{self.guard_call}(...,{self.guard_argument})"
        )


@dataclass(frozen=True, slots=True)
class BranchBodyEffectsRequirement:
    """Require named calls and one identifier copy to share an if-true body."""

    function_name: str
    required_calls: tuple[str, ...]
    assignment_name: str
    assignment_source_name: str

    def to_json(self) -> dict[str, object]:
        """Return a stable JSON representation."""
        return {
            "function_name": self.function_name,
            "required_calls": list(self.required_calls),
            "assignment_name": self.assignment_name,
            "assignment_source_name": self.assignment_source_name,
        }

    @classmethod
    def from_json(cls, raw: object) -> BranchBodyEffectsRequirement | None:
        """Parse one persisted branch-body requirement."""
        if not isinstance(raw, dict):
            return None
        function_name = raw.get("function_name")
        required_calls = raw.get("required_calls")
        assignment_name = raw.get("assignment_name")
        assignment_source_name = raw.get("assignment_source_name")
        if (
            not isinstance(function_name, str)
            or not isinstance(required_calls, list)
            or not required_calls
            or not all(isinstance(item, str) for item in required_calls)
            or not isinstance(assignment_name, str)
            or not isinstance(assignment_source_name, str)
        ):
            return None
        return cls(
            function_name=function_name,
            required_calls=tuple(required_calls),
            assignment_name=assignment_name,
            assignment_source_name=assignment_source_name,
        )

    def label(self) -> str:
        """Return a concise report label for this requirement."""
        calls = ",".join(self.required_calls)
        return (
            f"{self.function_name}: {self.assignment_name}="
            f"{self.assignment_source_name} with {calls}"
        )


@dataclass(frozen=True, slots=True)
class GeneratedCContractResult:
    """Result of evaluating source-backed expectations against generated C."""

    status: GeneratedCContractStatus
    missing_required_fragments: tuple[str, ...] = ()
    present_forbidden_fragments: tuple[str, ...] = ()
    insufficient_occurrences: tuple[tuple[str, int, int], ...] = ()
    missing_guarded_assignments: tuple[str, ...] = ()
    missing_branch_body_effects: tuple[str, ...] = ()
    missing_indexed_argument_uses: tuple[str, ...] = ()
    parse_error: str | None = None

    @property
    def passed(self) -> bool:
        """Return whether the contract passed or was not required."""
        return self.status is not GeneratedCContractStatus.FAILED

    def to_json(self) -> dict[str, Any]:
        """Return a stable JSON representation for fixture reports."""
        return {
            "status": self.status.value,
            "missing_required_fragments": list(self.missing_required_fragments),
            "present_forbidden_fragments": list(self.present_forbidden_fragments),
            "insufficient_occurrences": [list(item) for item in self.insufficient_occurrences],
            "missing_guarded_assignments": list(self.missing_guarded_assignments),
            "missing_branch_body_effects": list(self.missing_branch_body_effects),
            "missing_indexed_argument_uses": list(self.missing_indexed_argument_uses),
            "parse_error": self.parse_error,
        }


def _integer_constant(node: c_ast.Node) -> int | None:
    """Return one integer literal value from parsed C."""
    if not isinstance(node, c_ast.Constant) or node.type not in {"int", "char"}:
        return None
    try:
        return int(node.value, 0)
    except ValueError:
        return ord(node.value[1]) if len(node.value) == 3 and node.value[0] == "'" else None


def _node_children(node: c_ast.Node) -> tuple[c_ast.Node, ...]:
    """Return typed children across pycparser's untyped base-node boundary."""
    raw_children = cast("tuple[tuple[str, c_ast.Node], ...] | None", node.children())
    if raw_children is None:
        return ()
    return tuple(child for _name, child in raw_children)


def _call_matches(node: c_ast.Node, requirement: CallGuardedAssignmentRequirement) -> bool:
    """Return whether a subtree contains the required call and argument."""
    if isinstance(node, c_ast.FuncCall):
        callee = node.name
        arguments = tuple(node.args.exprs) if node.args is not None else ()
        if (
            isinstance(callee, c_ast.ID)
            and callee.name == requirement.guard_call
            and any(_integer_constant(argument) == requirement.guard_argument for argument in arguments)
        ):
            return True
    return any(_call_matches(child, requirement) for child in _node_children(node))


def _assignment_matches(node: c_ast.Node, requirement: CallGuardedAssignmentRequirement) -> bool:
    """Return whether one syntax node is the required scalar assignment."""
    return (
        isinstance(node, c_ast.Assignment)
        and isinstance(node.lvalue, c_ast.ID)
        and node.lvalue.name == requirement.assignment_name
        and _integer_constant(node.rvalue) == requirement.assignment_value
    )


def _matching_assignment_count(
    node: c_ast.Node,
    requirement: CallGuardedAssignmentRequirement,
) -> int:
    """Count matching assignments recursively under one syntax node."""
    return int(_assignment_matches(node, requirement)) + sum(
        _matching_assignment_count(child, requirement) for child in _node_children(node)
    )


def _owned_assignment_count(
    node: c_ast.Node,
    requirement: CallGuardedAssignmentRequirement,
) -> int:
    """Count matching assignments inside matching true branches."""
    owned = 0
    if isinstance(node, c_ast.If) and _call_matches(node.cond, requirement):
        owned += _matching_assignment_count(node.iftrue, requirement)
    return owned + sum(
        _owned_assignment_count(child, requirement) for child in _node_children(node)
    )


def _function_body(
    parsed: c_ast.FileAST,
    function_name: str,
) -> c_ast.Compound | None:
    """Return the uniquely named generated function body."""
    matches = tuple(
        item.body
        for item in parsed.ext
        if isinstance(item, c_ast.FuncDef) and item.decl.name == function_name
    )
    return matches[0] if len(matches) == 1 else None


def _named_calls(node: c_ast.Node) -> frozenset[str]:
    """Return identifier callees used in one parsed subtree."""
    names = {
        node.name.name
        for node in (node, *_node_children(node))
        if isinstance(node, c_ast.FuncCall) and isinstance(node.name, c_ast.ID)
    }
    return frozenset(names) | frozenset(
        name for child in _node_children(node) for name in _named_calls(child)
    )


def _identifier_copy_ids(
    node: c_ast.Node,
    requirement: BranchBodyEffectsRequirement,
) -> frozenset[int]:
    """Return identities of matching scalar-copy assignments in a subtree."""
    own = (
        frozenset({id(node)})
        if isinstance(node, c_ast.Assignment)
        and node.op == "="
        and isinstance(node.lvalue, c_ast.ID)
        and node.lvalue.name == requirement.assignment_name
        and isinstance(node.rvalue, c_ast.ID)
        and node.rvalue.name == requirement.assignment_source_name
        else frozenset()
    )
    return own | frozenset(
        assignment_id
        for child in _node_children(node)
        for assignment_id in _identifier_copy_ids(child, requirement)
    )


def _branch_body_effects_match(
    parsed: c_ast.FileAST,
    requirement: BranchBodyEffectsRequirement,
) -> bool:
    """Return whether every matching copy belongs to a call-complete if body."""
    body = _function_body(parsed, requirement.function_name)
    if body is None:
        return False
    all_assignments = _identifier_copy_ids(body, requirement)
    required_calls = frozenset(requirement.required_calls)
    owned_assignments: set[int] = set()
    stack: list[c_ast.Node] = [body]
    while stack:
        node = stack.pop()
        if isinstance(node, c_ast.If) and required_calls <= _named_calls(node.iftrue):
            owned_assignments.update(_identifier_copy_ids(node.iftrue, requirement))
        stack.extend(_node_children(node))
    return bool(all_assignments) and all_assignments <= owned_assignments


def _parse_generated_c(source: str, *, compiler: str = "gcc") -> c_ast.FileAST:
    """Preprocess comments and parse generated C through pycparser."""
    parser_source = "\n".join(
        line
        for line in source.splitlines()
        if not line.lstrip().startswith(("#include", *_PRESERVED_RUNTIME_MACRO_PREFIXES))
    )
    completed = subprocess.run(
        [compiler, "-E", "-P", "-x", "c", "-"],
        input=f"{_PARSE_PREFIX}{parser_source}",
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise ValueError(f"generated C preprocessing failed: {completed.stderr.strip()}")
    try:
        return c_parser.CParser().parse(completed.stdout)
    except c_parser.ParseError as ex:
        raise ValueError(f"generated C parser rejected fixture output: {ex}") from ex


@dataclass(frozen=True, slots=True)
class GeneratedCContract:
    """Source-backed output expectations used only by fixture gates."""

    required_fragments: tuple[str, ...] = ()
    forbidden_fragments: tuple[str, ...] = ()
    minimum_occurrences: tuple[tuple[str, int], ...] = ()
    guarded_assignments: tuple[CallGuardedAssignmentRequirement, ...] = ()
    branch_body_effects: tuple[BranchBodyEffectsRequirement, ...] = ()
    indexed_argument_uses: tuple[IndexedArgumentUseRequirement, ...] = ()

    def assess(self, generated_output: str) -> GeneratedCContractResult:
        """Evaluate textual and parsed structural expectations."""
        missing = tuple(fragment for fragment in self.required_fragments if fragment not in generated_output)
        forbidden = tuple(fragment for fragment in self.forbidden_fragments if fragment in generated_output)
        insufficient = tuple(
            (fragment, minimum, generated_output.count(fragment))
            for fragment, minimum in self.minimum_occurrences
            if generated_output.count(fragment) < minimum
        )
        missing_guarded: tuple[str, ...] = ()
        missing_branch_effects: tuple[str, ...] = ()
        missing_indexed_uses: tuple[str, ...] = ()
        parse_error: str | None = None
        if self.guarded_assignments or self.branch_body_effects or self.indexed_argument_uses:
            try:
                parsed = _parse_generated_c(generated_output)
                missing_guarded = tuple(
                    requirement.label()
                    for requirement in self.guarded_assignments
                    if (
                        (total := _matching_assignment_count(parsed, requirement)) == 0
                        or _owned_assignment_count(parsed, requirement) != total
                    )
                )
                missing_branch_effects = tuple(
                    requirement.label()
                    for requirement in self.branch_body_effects
                    if not _branch_body_effects_match(parsed, requirement)
                )
                missing_indexed_uses = missing_indexed_argument_uses(
                    parsed,
                    self.indexed_argument_uses,
                )
            except ValueError as ex:
                parse_error = str(ex)
        status = (
            GeneratedCContractStatus.FAILED
            if (
                missing
                or forbidden
                or insufficient
                or missing_guarded
                or missing_branch_effects
                or missing_indexed_uses
                or parse_error
            )
            else GeneratedCContractStatus.PASSED
        )
        return GeneratedCContractResult(
            status=status,
            missing_required_fragments=missing,
            present_forbidden_fragments=forbidden,
            insufficient_occurrences=insufficient,
            missing_guarded_assignments=missing_guarded,
            missing_branch_body_effects=missing_branch_effects,
            missing_indexed_argument_uses=missing_indexed_uses,
            parse_error=parse_error,
        )

    def to_json(self) -> dict[str, Any]:
        """Return a stable JSON representation for deferred batch execution."""
        return {
            "required_fragments": list(self.required_fragments),
            "forbidden_fragments": list(self.forbidden_fragments),
            "minimum_occurrences": [list(item) for item in self.minimum_occurrences],
            "guarded_assignments": [item.to_json() for item in self.guarded_assignments],
            "branch_body_effects": [item.to_json() for item in self.branch_body_effects],
            "indexed_argument_uses": [item.to_json() for item in self.indexed_argument_uses],
        }

    @classmethod
    def from_json(cls, raw: object) -> GeneratedCContract | None:
        """Parse a contract persisted in an outer fixture result."""
        if not isinstance(raw, dict):
            return None
        required = raw.get("required_fragments")
        forbidden = raw.get("forbidden_fragments")
        minimum = raw.get("minimum_occurrences")
        guarded = raw.get("guarded_assignments", [])
        branch_effects = raw.get("branch_body_effects", [])
        indexed_uses = raw.get("indexed_argument_uses", [])
        if not isinstance(required, list) or not all(isinstance(item, str) for item in required):
            return None
        if not isinstance(forbidden, list) or not all(isinstance(item, str) for item in forbidden):
            return None
        if (
            not isinstance(minimum, list)
            or not isinstance(guarded, list)
            or not isinstance(branch_effects, list)
            or not isinstance(indexed_uses, list)
        ):
            return None
        parsed_minimum: list[tuple[str, int]] = []
        for item in minimum:
            if (
                not isinstance(item, list)
                or len(item) != 2
                or not isinstance(item[0], str)
                or not isinstance(item[1], int)
                or item[1] < 1
            ):
                return None
            parsed_minimum.append((item[0], item[1]))
        parsed_guarded = tuple(CallGuardedAssignmentRequirement.from_json(item) for item in guarded)
        if any(item is None for item in parsed_guarded):
            return None
        parsed_branch_effects = tuple(
            BranchBodyEffectsRequirement.from_json(item) for item in branch_effects
        )
        if any(item is None for item in parsed_branch_effects):
            return None
        parsed_indexed_uses = tuple(
            IndexedArgumentUseRequirement.from_json(item) for item in indexed_uses
        )
        if any(item is None for item in parsed_indexed_uses):
            return None
        return cls(
            required_fragments=tuple(required),
            forbidden_fragments=tuple(forbidden),
            minimum_occurrences=tuple(parsed_minimum),
            guarded_assignments=tuple(item for item in parsed_guarded if item is not None),
            branch_body_effects=tuple(item for item in parsed_branch_effects if item is not None),
            indexed_argument_uses=tuple(item for item in parsed_indexed_uses if item is not None),
        )
