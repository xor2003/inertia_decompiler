# cython: language_level=3, infer_types=True
"""Classify and materialize deliberate near-return-frame discards.

Layer: Types/Lowering.
Responsibility: turn exact entry POP plus terminal RET instruction evidence
into a typed non-local control-stack escape without exposing the discarded
machine return address as a C scalar result.
Forbidden: symbol, listing, address, or rendered-C pattern matching.

Consumes alias, widening, and typed facts. Do not recover semantics from COD,
source, assembly, or rendered C text.

Dynamic boundary: decoded Capstone operands and third-party angr C-AST/codegen
objects expose version-dependent compatibility attributes.
"""

from __future__ import annotations
import typing
import cython

from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum
from typing import Any, Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from capstone.x86_const import X86_INS_POP, X86_INS_PUSH, X86_INS_RET, X86_OP_REG

from inertia.lowering.structured_tags import copy_structured_tags_8616
import dataclasses
import operator


class _Operand8616(Protocol):
    """Decoded operand fields required by escape classification."""

    type: cython.longlong
    reg: cython.longlong


class _Instruction8616(Protocol):
    """Decoded instruction fields required by escape classification."""

    address: cython.longlong
    id: cython.longlong
    operands: object

    def reg_name(self, reg_id: cython.longlong) -> object:
        """Return the architecture register name for one operand id."""
        ...


class ControlStackEscapeKind8616(Enum):
    """Proven machine-level control-stack escape shape."""

    DISCARD_NEAR_RETURN_FRAME = "discard_near_return_frame"


@dataclasses.dataclass(frozen=True, )
class ControlStackEscapeFact8616:
    """Describe one exact extra near-return-frame unwind."""

    function_addr: cython.longlong
    pop_addr: cython.longlong
    terminal_ret_addr: cython.longlong
    popped_register: object
    discarded_frame_width: cython.longlong
    extra_unwind_depth: cython.longlong
    kind: ControlStackEscapeKind8616


@dataclasses.dataclass(frozen=True, )
class ControlStackEscapeRecord8616:
    """Closed evidence census for one materialized control-stack escape."""

    fact: ControlStackEscapeFact8616
    raw_fact_count: cython.longlong = 1
    normalized_fact_count: cython.longlong = 1
    classified_fact_count: cython.longlong = 1
    materialized_count: cython.longlong = 1
    failure_count: cython.longlong = 0

    @property
    def closes_evidence(self) -> cython.bint:
        """Return whether the one classified escape was materialized."""
        return (
            self.raw_fact_count
            == self.normalized_fact_count
            == self.classified_fact_count
            == self.materialized_count
            == 1
            and self.failure_count == 0
        )


def classify_control_stack_escape_8616(
    instructions: Iterable[object],
    function_addr: cython.longlong,
) -> ControlStackEscapeFact8616 | None:
    """Classify an entry GP POP followed by an uncompensated terminal RET."""
    terminal_ret: object
    instruction: object
    ordered: list[_Instruction8616] = []
    seen: set[tuple[cython.longlong, cython.longlong]] = set()
    for instruction in instructions:
        decoded = cast(_Instruction8616, instruction)
        try:
            key = (decoded.address, decoded.id)
        except AttributeError:
            continue
        if key in seen:
            continue
        seen.add(key)
        ordered.append(decoded)
        if operator.eq(decoded.id, X86_INS_RET):
            break
    if not ordered or operator.ne(ordered[0].id, X86_INS_POP):
        return None
    entry_pop = ordered[0]
    try:
        operand = entry_pop.operands[0]
        register_name = entry_pop.reg_name(operand.reg).lower()
    except (AttributeError, IndexError, TypeError):
        return None
    if operator.ne(operand.type, X86_OP_REG) or register_name not in {"ax", "bx", "cx", "dx", "si", "di"}:
        return None
    terminal_ret = next((instruction for instruction in iter(ordered[1:]) if operator.eq(instruction.id, X86_INS_RET)), None)
    if terminal_ret is None:
        return None
    if any(instruction.id in {X86_INS_PUSH, X86_INS_POP} for instruction in iter(ordered[1:-1])):
        return None
    return ControlStackEscapeFact8616(
        function_addr=function_addr,
        pop_addr=entry_pop.address,
        terminal_ret_addr=terminal_ret.address,
        popped_register=register_name,
        discarded_frame_width=2,
        extra_unwind_depth=1,
        kind=ControlStackEscapeKind8616.DISCARD_NEAR_RETURN_FRAME,
    )


def materialize_control_stack_escape_8616(
    codegen: object,
    fact: ControlStackEscapeFact8616,
) -> cython.bint:
    """Remove only the synthetic C value projected from a discarded return address."""
    root: object
    typed_codegen = cast(Any, codegen)
    root = getattr(getattr(typed_codegen, "cfunc", None), "statements", None)
    if not isinstance(root, structured_c.CStatements):
        return False
    changed = False
    matched_return = False

    def rewrite(statements: object) -> None:
        """Rewrite the exact terminal RET while preserving all prior effects."""
        child: object
        tags: object
        attribute: object
        statement: object
        nonlocal changed, matched_return
        for statement in statements:
            tags = (
                copy_structured_tags_8616(statement.tags)
                if isinstance(statement, structured_c.CReturn)
                else None
            )
            if (
                isinstance(statement, structured_c.CReturn)
                and tags is not None
                and operator.eq(tags.get("ins_addr"), fact.terminal_ret_addr)
            ):
                matched_return = True
                if statement.retval is not None:
                    statement.retval = None
                    changed = True
                statement.tags = {
                    **tags,
                    "inertia_x86_16_control_stack_escape": fact,
                }
            for attribute in ("statements", "body", "else_node"):
                child = getattr(statement, attribute, None)
                if isinstance(child, structured_c.CStatements):
                    rewrite(child.statements)
                elif isinstance(child, list):
                    rewrite(child)

    rewrite(root.statements)
    if not matched_return:
        root.statements.append(
            structured_c.CReturn(
                None,
                codegen=typed_codegen,
                tags={
                    "ins_addr": fact.terminal_ret_addr,
                    "inertia_x86_16_control_stack_escape": fact,
                },
            )
        )
        changed = True
    typed_codegen._inertia_control_stack_escape_record_8616 = ControlStackEscapeRecord8616(fact)
    return changed


__all__ = [
    "ControlStackEscapeFact8616",
    "ControlStackEscapeKind8616",
    "ControlStackEscapeRecord8616",
    "classify_control_stack_escape_8616",
    "materialize_control_stack_escape_8616",
]
