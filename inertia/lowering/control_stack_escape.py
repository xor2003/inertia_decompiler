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

from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum
from typing import Any, Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from capstone.x86_const import X86_INS_POP, X86_INS_PUSH, X86_INS_RET, X86_OP_REG

from inertia.lowering.structured_tags import copy_structured_tags_8616


class _Operand8616(Protocol):
    """Decoded operand fields required by escape classification."""

    type: int
    reg: int


class _Instruction8616(Protocol):
    """Decoded instruction fields required by escape classification."""

    address: int
    id: int
    operands: tuple[_Operand8616, ...]

    def reg_name(self, reg_id: int) -> str:
        """Return the architecture register name for one operand id."""
        ...


class ControlStackEscapeKind8616(Enum):
    """Proven machine-level control-stack escape shape."""

    DISCARD_NEAR_RETURN_FRAME = "discard_near_return_frame"


@dataclass(frozen=True, slots=True)
class ControlStackEscapeFact8616:
    """Describe one exact extra near-return-frame unwind."""

    function_addr: int
    pop_addr: int
    terminal_ret_addr: int
    popped_register: str
    discarded_frame_width: int
    extra_unwind_depth: int
    kind: ControlStackEscapeKind8616


@dataclass(frozen=True, slots=True)
class ControlStackEscapeRecord8616:
    """Closed evidence census for one materialized control-stack escape."""

    fact: ControlStackEscapeFact8616
    raw_fact_count: int = 1
    normalized_fact_count: int = 1
    classified_fact_count: int = 1
    materialized_count: int = 1
    failure_count: int = 0

    @property
    def closes_evidence(self) -> bool:
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
    function_addr: int,
) -> ControlStackEscapeFact8616 | None:
    """Classify an entry GP POP followed by an uncompensated terminal RET."""
    ordered: list[_Instruction8616] = []
    seen: set[tuple[int, int]] = set()
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
        if decoded.id == X86_INS_RET:
            break
    if not ordered or ordered[0].id != X86_INS_POP:
        return None
    entry_pop = ordered[0]
    try:
        operand = entry_pop.operands[0]
        register_name = entry_pop.reg_name(operand.reg).lower()
    except (AttributeError, IndexError, TypeError):
        return None
    if operand.type != X86_OP_REG or register_name not in {"ax", "bx", "cx", "dx", "si", "di"}:
        return None
    terminal_ret = next((instruction for instruction in ordered[1:] if instruction.id == X86_INS_RET), None)
    if terminal_ret is None:
        return None
    if any(instruction.id in {X86_INS_PUSH, X86_INS_POP} for instruction in ordered[1:-1]):
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
) -> bool:
    """Remove only the synthetic C value projected from a discarded return address."""
    typed_codegen = cast(Any, codegen)
    root = getattr(getattr(typed_codegen, "cfunc", None), "statements", None)
    if not isinstance(root, structured_c.CStatements):
        return False
    changed = False
    matched_return = False

    def rewrite(statements: list[Any]) -> None:
        """Rewrite the exact terminal RET while preserving all prior effects."""
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
                and tags.get("ins_addr") == fact.terminal_ret_addr
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
