"""Reject unproven changes to the execution scope of stack updates.

Layer: Types/Lowering.
Responsibility: guard logical assignment materialization against collapsing
fragments across a conditional body and a loop iterator. This module does not
choose or recover control flow; Structuring must prove placement before such
fragments can be replaced by a single assignment.
Consumes alias, widening, and typed facts through materialized storage owners.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from angr.analyses.decompiler.structured_codegen.c import CAssignment, CForLoop, CIfElse

from ..c_ast_utils import _iter_c_nodes_deep_8616
from ..pipeline.errors import PipelineHardError


@dataclass(frozen=True, slots=True)
class StackUpdateScopeConflict8616:
    """Instruction fragments whose execution scopes cannot be merged by tags."""

    instruction_addr: int
    iterator_scope: str = "for_iterator"
    guarded_scope: str = "conditional_body"


def require_stack_update_scope_8616(
    root: object,
    instruction_addr: int,
    matches_instruction: Callable[[object], bool],
) -> None:
    """Fail before mutation when an iterator shares an instruction with an arm.

    Matching tags identify origins, not equivalent execution counts. Even when
    one fragment was legally hoisted, promoting it to a whole storage update
    can execute the other fragment's effect on previously excluded paths.
    """
    for loop in _iter_c_nodes_deep_8616(root):
        if not isinstance(loop, CForLoop) or loop.iterator is None:
            continue
        if not matches_instruction(loop.iterator):
            continue
        for node in _iter_c_nodes_deep_8616(loop.body):
            if not isinstance(node, CIfElse):
                continue
            bodies = [body for _condition, body in node.condition_and_nodes]
            if node.else_node is not None:
                bodies.append(node.else_node)
            for body in bodies:
                has_fragment = any(
                    isinstance(statement, CAssignment) and matches_instruction(statement)
                    for statement in _iter_c_nodes_deep_8616(body)
                )
                if has_fragment:
                    raise PipelineHardError(
                        f"stack update at {instruction_addr:#x}: conditional body and "
                        "for iterator share instruction fragments; CFG-proven placement "
                        "is required before whole-storage replacement",
                        layer="Types/Lowering",
                        details=StackUpdateScopeConflict8616(instruction_addr),
                    )
