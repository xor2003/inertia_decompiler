"""Index structured register-return assignments for one unchanged AST root.

Layer: Structuring.
Responsibility: retain a read-only typed projection of bound call assignments
so condition placement does not repeatedly traverse one unchanged C AST.
The caller must discard this projection after any relevant AST mutation.

Owns CFG shape, loops, switches, and structured condition lowering from proven
IR/semantic evidence. Do not perform alias-state ownership, widening,
type/materialization recovery, rewrite cleanup, postprocess, or CLI/reporting
work here.
"""

from __future__ import annotations

from dataclasses import dataclass

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CFunctionCall,
    CVariable,
)
from angr.sim_variable import SimRegisterVariable

from inertia.lowering.c_ast_utils import _iter_c_nodes_deep_8616
from inertia.lowering.structured_tags import copy_structured_tags_8616
from inertia.semantics.callsite_summary import structured_callsite_addr_8616


@dataclass(frozen=True, slots=True)
class IndexedCallReturnRegisterAssignment8616:
    """One bound register assignment retained without changing the C AST."""

    assignment: CAssignment
    call: CFunctionCall
    register_slice: tuple[int, int]
    callsite_addr: int
    assignment_ins_addr: int | None
    rhs_is_call: bool


@dataclass(slots=True)
class CallReturnRegisterIndex8616:
    """Assignment projection valid only while its exact root is unchanged."""

    root: object
    assignments: tuple[IndexedCallReturnRegisterAssignment8616, ...]
    bound_callsite_counts: dict[int, int]
    valid: bool = True

    def matches_root(self, root: object) -> bool:
        """Return whether this projection belongs to the supplied AST root."""
        return self.valid and self.root is root

    def bound_callsite_count(self, callsite_addr: int) -> int:
        """Return the bound-call count captured for one machine callsite."""
        return self.bound_callsite_counts.get(callsite_addr, 0)

    def invalidate(self) -> None:
        """Prevent reuse after a relevant structured-AST mutation."""
        self.valid = False


def _assignment_ins_addr_8616(assignment: CAssignment) -> int | None:
    """Return the exact instruction tag carried by one assignment."""
    tags = copy_structured_tags_8616(assignment.tags)
    if tags is None:
        return None
    ins_addr = tags.get("ins_addr")
    return ins_addr if isinstance(ins_addr, int) else None


def build_call_return_register_index_8616(root: object) -> CallReturnRegisterIndex8616:
    """Build one deterministic read-only assignment projection."""
    assignments: list[IndexedCallReturnRegisterAssignment8616] = []
    bound_callsite_counts: dict[int, int] = {}
    for node in _iter_c_nodes_deep_8616(root):
        if isinstance(node, CFunctionCall):
            callsite_addr = structured_callsite_addr_8616(node)
            if isinstance(callsite_addr, int):
                bound_callsite_counts[callsite_addr] = (
                    bound_callsite_counts.get(callsite_addr, 0) + 1
                )
        if not isinstance(node, CAssignment):
            continue
        lhs = node.lhs
        if not isinstance(lhs, CVariable) or not isinstance(
            lhs.variable,
            SimRegisterVariable,
        ):
            continue
        calls = tuple(
            {
                id(call): call
                for call in _iter_c_nodes_deep_8616(node.rhs)
                if isinstance(call, CFunctionCall)
            }.values()
        )
        if len(calls) != 1:
            continue
        call = calls[0]
        callsite_addr = structured_callsite_addr_8616(call)
        if not isinstance(callsite_addr, int):
            continue
        variable = lhs.variable
        assignments.append(
            IndexedCallReturnRegisterAssignment8616(
                assignment=node,
                call=call,
                register_slice=(int(variable.reg), int(variable.size)),
                callsite_addr=callsite_addr,
                assignment_ins_addr=_assignment_ins_addr_8616(node),
                rhs_is_call=node.rhs is call,
            )
        )
    return CallReturnRegisterIndex8616(
        root,
        tuple(assignments),
        bound_callsite_counts,
    )


__all__ = (
    "CallReturnRegisterIndex8616",
    "IndexedCallReturnRegisterAssignment8616",
    "build_call_return_register_index_8616",
)
