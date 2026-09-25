"""Evaluate indexed near-pointer uses in parsed generated C.

Layer: Tooling/gates.
Responsibility: recognize source-backed indexed argument use in either direct C
array syntax or the equivalent segmented 16-bit near-pointer load form.
"""

from __future__ import annotations

from dataclasses import dataclass

from pycparser import c_ast


def _children(node: c_ast.Node) -> tuple[c_ast.Node, ...]:
    """Return parsed children without relying on generated C text."""
    return tuple(child for _name, child in node.children())


def _strip_casts(node: c_ast.Node) -> c_ast.Node:
    """Return the expression beneath syntax-only C casts."""
    while isinstance(node, c_ast.Cast):
        node = node.expr
    return node


def _integer_constant(node: c_ast.Node) -> int | None:
    """Return one integer literal from parsed C."""
    node = _strip_casts(node)
    if not isinstance(node, c_ast.Constant) or node.type != "int":
        return None
    try:
        return int(node.value, 0)
    except ValueError:
        return None


def _call_name(node: c_ast.Node) -> str | None:
    """Return an identifier call target."""
    return node.name.name if isinstance(node, c_ast.FuncCall) and isinstance(node.name, c_ast.ID) else None


def _contains_id(node: c_ast.Node, name: str) -> bool:
    """Return whether a subtree contains one identifier."""
    node = _strip_casts(node)
    return (isinstance(node, c_ast.ID) and node.name == name) or any(
        _contains_id(child, name) for child in _children(node)
    )


def _contains_pointer_word(node: c_ast.Node, base_name: str) -> bool:
    """Return whether a subtree converts the named near pointer to guest storage."""
    node = _strip_casts(node)
    if _call_name(node) in {"PTR_U16", "PTR_U32"}:
        arguments = tuple(node.args.exprs) if isinstance(node, c_ast.FuncCall) and node.args else ()
        if len(arguments) == 1 and _contains_id(arguments[0], base_name):
            return True
    return any(_contains_pointer_word(child, base_name) for child in _children(node))


def _contains_scaled_index(node: c_ast.Node, index_name: str) -> bool:
    """Return whether a subtree scales the named index by one 16-bit word."""
    node = _strip_casts(node)
    if isinstance(node, c_ast.BinaryOp):
        if node.op == "<<" and _contains_id(node.left, index_name) and _integer_constant(node.right) == 1:
            return True
        if node.op == "*":
            pairs = ((node.left, node.right), (node.right, node.left))
            if any(_contains_id(value, index_name) and _integer_constant(scale) == 2 for value, scale in pairs):
                return True
    return any(_contains_scaled_index(child, index_name) for child in _children(node))


@dataclass(frozen=True, slots=True)
class IndexedArgumentUseRequirement:
    """Require repeated word-indexed uses of one near-pointer argument."""

    base_name: str
    index_name: str
    minimum_count: int
    guard_call: str
    required_guard_arguments: tuple[int, ...]

    def label(self) -> str:
        """Return a stable report label."""
        arguments = ",".join(str(value) for value in self.required_guard_arguments)
        return (
            f"{self.base_name}[{self.index_name}] count>={self.minimum_count} "
            f"under {self.guard_call}(...,{arguments})"
        )

    def to_json(self) -> dict[str, object]:
        """Return a stable JSON representation."""
        return {
            "base_name": self.base_name,
            "index_name": self.index_name,
            "minimum_count": self.minimum_count,
            "guard_call": self.guard_call,
            "required_guard_arguments": list(self.required_guard_arguments),
        }

    @classmethod
    def from_json(cls, raw: object) -> IndexedArgumentUseRequirement | None:
        """Parse one persisted indexed-argument requirement."""
        if not isinstance(raw, dict):
            return None
        base_name = raw.get("base_name")
        index_name = raw.get("index_name")
        minimum_count = raw.get("minimum_count")
        guard_call = raw.get("guard_call")
        required_arguments = raw.get("required_guard_arguments")
        if not _valid_requirement_fields(base_name, index_name, minimum_count, guard_call, required_arguments):
            return None
        return cls(base_name, index_name, minimum_count, guard_call, tuple(required_arguments))


def _valid_requirement_fields(
    base_name: object,
    index_name: object,
    minimum_count: object,
    guard_call: object,
    required_arguments: object,
) -> bool:
    """Return True when parsed requirement fields have valid shapes."""
    return (
        isinstance(base_name, str)
        and isinstance(index_name, str)
        and isinstance(minimum_count, int)
        and not isinstance(minimum_count, bool)
        and minimum_count >= 1
        and isinstance(guard_call, str)
        and isinstance(required_arguments, list)
        and bool(required_arguments)
        and all(isinstance(value, int) and not isinstance(value, bool) for value in required_arguments)
    )


def _indexed_value(node: c_ast.Node, requirement: IndexedArgumentUseRequirement) -> bool:
    """Return whether one node is an accepted indexed near-pointer value."""
    node = _strip_casts(node)
    if isinstance(node, c_ast.ArrayRef):
        return _contains_id(node.name, requirement.base_name) and _contains_id(
            node.subscript, requirement.index_name
        )
    if _call_name(node) != "SEG_U16" or not isinstance(node, c_ast.FuncCall) or node.args is None:
        return False
    arguments = tuple(node.args.exprs)
    return len(arguments) == 2 and _contains_pointer_word(
        arguments[1], requirement.base_name
    ) and _contains_scaled_index(arguments[1], requirement.index_name)


def _indexed_value_count(node: c_ast.Node, requirement: IndexedArgumentUseRequirement) -> int:
    """Count accepted indexed values in one parsed subtree."""
    return int(_indexed_value(node, requirement)) + sum(
        _indexed_value_count(child, requirement) for child in _children(node)
    )


def _guard_arguments(node: c_ast.Node, requirement: IndexedArgumentUseRequirement) -> frozenset[int]:
    """Return required guard literals whose calls consume an indexed value."""
    matched: set[int] = set()
    if _call_name(node) == requirement.guard_call and isinstance(node, c_ast.FuncCall) and node.args:
        arguments = tuple(node.args.exprs)
        indexed = any(_indexed_value_count(argument, requirement) > 0 for argument in arguments)
        if indexed:
            for argument in arguments:
                value = _integer_constant(argument)
                if value in requirement.required_guard_arguments:
                    matched.add(value)
    for child in _children(node):
        matched.update(_guard_arguments(child, requirement))
    return frozenset(matched)


def missing_indexed_argument_uses(
    parsed: c_ast.FileAST,
    requirements: tuple[IndexedArgumentUseRequirement, ...],
) -> tuple[str, ...]:
    """Return labels for unsatisfied parsed indexed-argument requirements."""
    missing: list[str] = []
    for requirement in requirements:
        count = _indexed_value_count(parsed, requirement)
        guards = _guard_arguments(parsed, requirement)
        if count < requirement.minimum_count or not set(requirement.required_guard_arguments) <= guards:
            missing.append(requirement.label())
    return tuple(missing)


__all__ = ["IndexedArgumentUseRequirement", "missing_indexed_argument_uses"]
