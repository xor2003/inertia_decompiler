"""Materialize previously proved numeric frame values at their exact C returns.

Layer: Types/Lowering.
Responsibility: capture architectural entry SP once and consume source Alias
and return-path proofs as unsigned word expressions. Does not infer native
SSA inputs, repair signatures, recover semantics from text, or remove calls.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen import c

from inertia.pipeline.errors import PipelineHardError
from inertia.semantics.numeric_stack_pointer_returns import (
    NumericStackPointerReturn8616,
    NumericStackPointerReturnInventory8616,
    numeric_stack_pointer_return_inventory_8616,
    numeric_stack_pointer_return_inventory_is_current_8616,
)

from .c_ast_utils import _iter_c_nodes_deep_8616
from .codegen_return_origin import return_value_origin_8616
from .entry_stack_pointer_capture import (
    EntryStackPointerCaptureFailure8616,
    StackPointerCaptureFunction8616,
    entry_stack_pointer_projection_8616,
    is_entry_stack_pointer_projection_8616,
    prepare_entry_stack_pointer_capture_8616,
)


class NumericStackPointerLoweringStatus8616(StrEnum):
    """Whether current source proofs were consumed, unchanged, or refused."""

    MATERIALIZED = "materialized"
    STABLE = "stable"
    REFUSED = "refused"


class NumericStackPointerLoweringFailure8616(StrEnum):
    """Named source or storage defects that prevent truthful materialization."""

    SOURCE_CHANGED = "source_changed"
    FUNCTION_SCOPE_MISMATCH = "function_scope_mismatch"
    INVALID_CAPTURE = "invalid_capture"
    NO_ENTRY_SEQUENCE = "no_entry_sequence"


@dataclass(frozen=True, slots=True)
class NumericStackPointerLoweringStats8616:
    """Closed ledger for actual C-return projections, separate from proof publication."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int
    changed_count: int = 0


@dataclass(frozen=True, slots=True)
class NumericStackPointerLoweringResult8616:
    """Materialization outcome with no persistent source-authority cache."""

    status: NumericStackPointerLoweringStatus8616
    stats: NumericStackPointerLoweringStats8616
    failure: NumericStackPointerLoweringFailure8616 | None = None
    function_addr: int | None = None
    source_function_addr: int | None = None

    @property
    def changed(self) -> bool:
        """Return whether a capture or return expression actually changed."""
        return self.stats.changed_count > 0

    def to_dict(self) -> dict[str, object]:
        """Serialize the owned outcome without retaining native C objects."""
        return {"status": self.status.value, "stats": asdict(self.stats),
                "function_addr": self.function_addr, "source_function_addr": self.source_function_addr,
                "failure": None if self.failure is None else self.failure.value}


class _Codegen8616(Protocol):
    """Owned fields attached to the dynamic native codegen boundary."""

    cfunc: StackPointerCaptureFunction8616 | None
    _inertia_numeric_stack_pointer_return_lowering_8616: NumericStackPointerLoweringResult8616 | None


@dataclass(frozen=True, slots=True)
class _ReturnPlans8616:
    """Ephemeral C bindings and the ledger they must close in this operation."""

    raw: int
    normalized: int
    entries: tuple[tuple[c.CReturn, NumericStackPointerReturn8616], ...]
    function_addr: int
    source_function_addr: int

    def outcome(
        self, failure: NumericStackPointerLoweringFailure8616 | None = None,
        *, changed: int = 0,
    ) -> NumericStackPointerLoweringResult8616:
        """Close current C obligations without disguising classified failures."""
        status = NumericStackPointerLoweringStatus8616.REFUSED
        if failure is None and self.entries:
            status = (NumericStackPointerLoweringStatus8616.MATERIALIZED if changed
                      else NumericStackPointerLoweringStatus8616.STABLE)
        return NumericStackPointerLoweringResult8616(
            status, NumericStackPointerLoweringStats8616(
                self.raw, self.normalized, len(self.entries),
                len(self.entries) if failure is None else 0, int(failure is not None), changed,
            ), failure, self.function_addr, self.source_function_addr,
        )


def _collect_return_plans(
    inventory: NumericStackPointerReturnInventory8616, returns: tuple[c.CReturn, ...], function_addr: int,
) -> _ReturnPlans8616:
    """Bind exact transported RET identities without interpreting native values."""
    proofs = {(item.block_addr, item.return_addr): item.proof for item in inventory.observations
              if item.proof is not None}
    plans: list[tuple[c.CReturn, NumericStackPointerReturn8616]] = []
    normalized = 0
    for statement in returns:
        origin = return_value_origin_8616(statement)
        if (origin is None or origin.width_bits != 16
                or origin.return_block_addr is None or origin.return_instruction_addr is None):
            continue
        if any(isinstance(node, c.CFunctionCall) for node in _iter_c_nodes_deep_8616(statement.retval)):
            continue
        normalized += 1
        proof = proofs.get((origin.return_block_addr, origin.return_instruction_addr))
        if proof is not None:
            plans.append((statement, proof))
    return _ReturnPlans8616(len(returns), normalized, tuple(plans), function_addr, inventory.source_ir.function_addr)


def _project_returns(
    codegen: object, plans: _ReturnPlans8616, value: c.CVariable,
) -> int:
    """Materialize only source-owned scalar values, preserving surrounding calls."""
    changed = 0
    for statement, proof in plans.entries:
        if not is_entry_stack_pointer_projection_8616(statement.retval, value, proof.assignment.entry_sp_offset):
            statement.retval = entry_stack_pointer_projection_8616(value, proof.assignment.entry_sp_offset, codegen)
            changed += 1
    return changed


def lower_numeric_stack_pointer_returns_8616(
    codegen: object,
) -> NumericStackPointerLoweringResult8616 | None:
    """Consume current published proofs; preserve unknown returns and every call."""
    inventory = numeric_stack_pointer_return_inventory_8616(codegen)
    function = cast(_Codegen8616, codegen).cfunc
    if inventory is None or function is None:
        return None
    nodes = tuple(_iter_c_nodes_deep_8616(function.statements))
    returns = tuple(node for node in nodes if isinstance(node, c.CReturn))
    plans = _collect_return_plans(inventory, returns, function.addr)
    if function.addr != inventory.source_ir.function_addr:
        return plans.outcome(NumericStackPointerLoweringFailure8616.FUNCTION_SCOPE_MISMATCH)
    if not numeric_stack_pointer_return_inventory_is_current_8616(inventory):
        return plans.outcome(NumericStackPointerLoweringFailure8616.SOURCE_CHANGED)
    proofs = tuple(proof for _, proof in plans.entries)
    captured = prepare_entry_stack_pointer_capture_8616(codegen, inventory.source_ir, proofs)
    if captured is None:
        return plans.outcome()
    failures = {
        EntryStackPointerCaptureFailure8616.SOURCE_CHANGED: NumericStackPointerLoweringFailure8616.SOURCE_CHANGED,
        EntryStackPointerCaptureFailure8616.FUNCTION_SCOPE_MISMATCH: NumericStackPointerLoweringFailure8616.FUNCTION_SCOPE_MISMATCH,
        EntryStackPointerCaptureFailure8616.INVALID_CAPTURE: NumericStackPointerLoweringFailure8616.INVALID_CAPTURE,
        EntryStackPointerCaptureFailure8616.NO_ENTRY_SEQUENCE: NumericStackPointerLoweringFailure8616.NO_ENTRY_SEQUENCE,
    }
    if captured.failure is not None:
        return plans.outcome(failures[captured.failure])
    if captured.value is None:
        return plans.outcome(NumericStackPointerLoweringFailure8616.INVALID_CAPTURE)
    value, changed = captured.value, captured.changed_count
    changed += _project_returns(codegen, plans, value)
    if changed:
        function.refresh()
    return plans.outcome(changed=changed)


def apply_numeric_stack_pointer_return_lowering_8616(
    codegen: object,
) -> NumericStackPointerLoweringResult8616 | None:
    """Publish current C obligations as diagnostics, never cached proof authority."""
    result = lower_numeric_stack_pointer_returns_8616(codegen)
    cast(_Codegen8616, codegen)._inertia_numeric_stack_pointer_return_lowering_8616 = result
    if result is not None and result.stats.failure_count:
        raise PipelineHardError(
            f"numeric return materialization failed: {result.failure}",
            layer="types:numeric_stack_pointer_returns",
            function_addr=result.function_addr,
            details=result.to_dict(),
        )
    return result
