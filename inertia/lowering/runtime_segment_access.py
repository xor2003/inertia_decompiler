"""Classify typed runtime segmented accesses.

Layer: Types/Lowering.
Responsibility: prove a runtime helper's segment space and expose its typed
offset expression to lowering and validation consumers.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.

This module does not infer values, object identities, or delete statements. It
resolves only explicit segment registers, typed segmented-load identities, and
bounded C-variable copy chains. Unknown or conflicting evidence remains unknown
so every consumer refuses the transformation.

Dynamic boundary: angr structured-C nodes and codegen objects expose
version-dependent child attributes. Dynamic access is restricted to AST
traversal and project architecture lookup.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable

from inertia.ir.core import MemSpace
from inertia.widening.segmented_load_identity import segmented_load_identity_8616

from .segment_register_state import runtime_segment_name_for_variable_8616

type _VariableKey8616 = tuple[str, object, object, object]
type _AssignmentSources8616 = Mapping[_VariableKey8616, tuple[object, ...]]
_CHILD_ATTRIBUTES_8616 = (
    "statements",
    "lhs",
    "rhs",
    "expr",
    "operand",
    "args",
    "condition",
    "true_node",
    "false_node",
    "body",
    "initializer",
    "iterator",
)


@dataclass(slots=True)
class RuntimeSegmentAccessContext8616:
    """Lazily indexed segment-carrier context for one structured C pass."""

    root: object
    _sources: _AssignmentSources8616 | None = field(default=None, init=False, repr=False)

    @property
    def assignment_sources(self) -> _AssignmentSources8616:
        """Return the assignment-source index, building it at first use."""
        if self._sources is None:
            self._sources = MappingProxyType(_assignment_sources_8616(self.root))
        return self._sources


def _strip_casts_8616(node: object) -> object:
    """Remove structured-C casts from one expression."""
    while isinstance(node, structured_c.CTypeCast):
        node = node.expr
    return node


def _runtime_helper_name_8616(call: structured_c.CFunctionCall) -> str | None:
    """Read one runtime helper name from the angr call boundary."""
    marker = call.tags.get("inertia_x86_16_runtime_segment_helper")
    if isinstance(marker, str) and marker:
        return marker.upper()
    if isinstance(call.callee_target, str) and call.callee_target:
        return call.callee_target.upper()
    callee = call.callee_func
    name = callee.name if callee is not None else None
    return name.upper() if isinstance(name, str) and name else None


def is_runtime_segment_load_helper_8616(node: object) -> bool:
    """Return whether one structured call is a pure typed segmented load."""
    return (
        isinstance(node, structured_c.CFunctionCall)
        and _runtime_helper_name_8616(node) in {"SEG_U8", "SEG_U16", "SEG_U32"}
    )


def _variable_key_8616(node: object) -> _VariableKey8616 | None:
    """Return a stable key for one structured-C segment carrier variable."""
    node = _strip_casts_8616(node)
    if not isinstance(node, structured_c.CVariable):
        return None
    variable = node.variable
    if isinstance(variable, SimRegisterVariable):
        return ("reg", variable.reg, variable.size, variable.name)
    if isinstance(variable, SimMemoryVariable):
        return ("mem", variable.addr, variable.size, variable.name)
    return None


def _iter_ast_nodes_8616(root: object) -> Iterator[object]:
    """Walk supported third-party structured-C children without following cycles."""
    pending = [root]
    seen: set[int] = set()
    while pending:
        node = pending.pop()
        if node is None or id(node) in seen:
            continue
        seen.add(id(node))
        yield node
        for attribute in _CHILD_ATTRIBUTES_8616:
            child = getattr(node, attribute, None)
            if isinstance(child, (list, tuple)):
                pending.extend(reversed(child))
            elif child is not None:
                pending.append(child)


def _assignment_sources_8616(
    root: object,
) -> dict[_VariableKey8616, tuple[object, ...]]:
    """Collect explicit C copy sources for segment-carrier resolution."""
    mutable: defaultdict[_VariableKey8616, list[object]] = defaultdict(list)
    for node in _iter_ast_nodes_8616(root):
        if not isinstance(node, structured_c.CAssignment):
            continue
        key = _variable_key_8616(node.lhs)
        if key is not None:
            mutable[key].append(node.rhs)
    return {key: tuple(values) for key, values in mutable.items()}


def build_runtime_segment_access_context_8616(codegen: object) -> RuntimeSegmentAccessContext8616:
    """Build one reusable lazy segment-carrier context for the current C AST."""
    cfunc = getattr(codegen, "cfunc", None)
    root = getattr(cfunc, "statements", None)
    return RuntimeSegmentAccessContext8616(root=root)


def _direct_segment_space_8616(project: object, expression: object) -> MemSpace | None:
    """Resolve an explicit runtime-state or architectural segment variable."""
    expression = _strip_casts_8616(expression)
    if not isinstance(expression, structured_c.CVariable):
        return None
    variable = expression.variable
    runtime_name = runtime_segment_name_for_variable_8616(variable)
    if runtime_name is not None:
        return MemSpace(runtime_name)
    if not isinstance(variable, SimRegisterVariable):
        return None
    arch = getattr(project, "arch", None)
    registers = getattr(arch, "registers", None)
    if not isinstance(registers, dict):
        return None
    for name, space in (("ds", MemSpace.DS), ("es", MemSpace.ES), ("ss", MemSpace.SS)):
        register = registers.get(name)
        if isinstance(register, tuple) and register and variable.reg == register[0]:
            return space
    return None


def _resolve_segment_space_8616(
    project: object,
    expression: object,
    sources: _AssignmentSources8616,
    seen: frozenset[_VariableKey8616],
) -> MemSpace | None:
    """Resolve one segment carrier through an unambiguous bounded copy chain."""
    direct = _direct_segment_space_8616(project, expression)
    if direct is not None:
        return direct
    key = _variable_key_8616(expression)
    if key is None or key in seen:
        return None
    rhs_values = sources.get(key, ())
    if not rhs_values:
        return None
    resolved = {
        _resolve_segment_space_8616(project, rhs, sources, seen | {key})
        for rhs in rhs_values
    }
    return resolved.pop() if len(resolved) == 1 and None not in resolved else None


def runtime_segment_access_space_8616(
    project: object,
    codegen: object,
    lvalue: object,
    *,
    context: RuntimeSegmentAccessContext8616 | None = None,
) -> MemSpace | None:
    """Return the proven space of a ``SEG_U*`` access, if any."""
    node = _strip_casts_8616(lvalue)
    if not isinstance(node, structured_c.CFunctionCall):
        return None
    helper_name = _runtime_helper_name_8616(node)
    if helper_name not in {"SEG_U8", "SEG_U16", "SEG_U32"}:
        return None
    identity = segmented_load_identity_8616(node)
    if identity is not None:
        return identity.space
    args = tuple(node.args or ())
    if len(args) != 2:
        return None
    direct = _direct_segment_space_8616(project, args[0])
    if direct is not None:
        return direct
    if context is None:
        context = build_runtime_segment_access_context_8616(codegen)
    return _resolve_segment_space_8616(
        project,
        args[0],
        context.assignment_sources,
        frozenset(),
    )


def runtime_segment_access_offset_expr_8616(
    project: object,
    codegen: object,
    access: object,
    *,
    expected_space: MemSpace,
    width: int,
    context: RuntimeSegmentAccessContext8616 | None = None,
) -> object | None:
    """Return a proven runtime access's structured offset expression."""
    node = _strip_casts_8616(access)
    if not isinstance(node, structured_c.CFunctionCall):
        return None
    expected_helper = {1: "SEG_U8", 2: "SEG_U16", 4: "SEG_U32"}.get(width)
    if expected_helper is None or _runtime_helper_name_8616(node) != expected_helper:
        return None
    if runtime_segment_access_space_8616(project, codegen, node, context=context) is not expected_space:
        return None
    args = tuple(node.args or ())
    return args[1] if len(args) == 2 else None
