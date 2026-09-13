"""Run ordered postprocess bootstrap commands through one guarded callback.

Layer: Rewrite/Postprocess cleanup.
Responsibility: schedule already-owned bootstrap consumers in deterministic
order and stop immediately after guarded validation fails.
Consumes already-proven IR, alias, widening, typed, and structuring facts.
Do not recover new semantics, storage identity, types, call signatures, control
flow, or facts from rendered text, COD, source, or CLI/reporting evidence here.
Every operation is injected from its authoritative Types/Lowering or
Structuring boundary. Dynamic boundary: codegen is a third-party angr object.
"""

from __future__ import annotations

import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol, cast

__all__ = [
    "PostprocessBootstrapOperations8616",
    "run_postprocess_bootstrap_steps_8616",
]

type BootstrapOperation8616 = Callable[[], bool]
type GuardedBootstrapApply8616 = Callable[[str, BootstrapOperation8616], bool]


class _BootstrapCodegenBoundary8616(Protocol):
    """Third-party codegen status consumed by bootstrap orchestration."""

    cfunc: object
    _inertia_postprocess_validation_failed: bool


@dataclass(frozen=True, slots=True)
class PostprocessBootstrapOperations8616:
    """Every semantic operation scheduled by the bootstrap transaction."""

    normalize_fact_backed_stack_accesses: BootstrapOperation8616
    materialize_direct_stack_mov: BootstrapOperation8616
    materialize_direct_stack_incdec: BootstrapOperation8616
    apply_typed_conditions: BootstrapOperation8616
    materialize_global_byte_index_sum_loop: BootstrapOperation8616
    materialize_selector_return_branches: BootstrapOperation8616
    rewrite_decoded_jcc_conditions: BootstrapOperation8616
    selector_return_contract_active: Callable[[], bool]

    def ordered(self) -> tuple[tuple[str, BootstrapOperation8616], ...]:
        """Return the unconditional bootstrap prefix in exact execution order."""
        return (
            (
                "_normalize_fact_backed_stack_accesses_8616",
                self.normalize_fact_backed_stack_accesses,
            ),
            (
                "_materialize_direct_stack_mov_instructions_8616",
                self.materialize_direct_stack_mov,
            ),
            (
                "_materialize_direct_stack_incdec_instructions_8616",
                self.materialize_direct_stack_incdec,
            ),
            ("_apply_typed_conditions_to_codegen_8616", self.apply_typed_conditions),
            (
                "_materialize_global_byte_index_sum_loop_8616",
                self.materialize_global_byte_index_sum_loop,
            ),
            (
                "_materialize_cfg_selector_return_branches_early_8616",
                self.materialize_selector_return_branches,
            ),
        )


def _function_addr_8616(codegen: object) -> int | None:
    """Return the active address at the explicit third-party CFunction boundary."""
    try:
        cfunc = cast(_BootstrapCodegenBoundary8616, codegen).cfunc
    except AttributeError:
        return None
    # Dynamic boundary: angr CFunction variants expose address at runtime.
    addr = getattr(cfunc, "addr", None)
    return addr if isinstance(addr, int) else None


def run_postprocess_bootstrap_steps_8616(
    codegen: object,
    skip_names: set[str],
    apply_step: GuardedBootstrapApply8616,
    operations: PostprocessBootstrapOperations8616,
    *,
    debug_enabled: bool = False,
    timing_enabled: bool = False,
) -> bool:
    """Run every enabled bootstrap command through guarded validation."""
    surface = cast(_BootstrapCodegenBoundary8616, codegen)
    if debug_enabled:
        print(
            "[postprocess-bootstrap] "
            f"function={_function_addr_8616(codegen)!r} "
            f"skip={','.join(sorted(skip_names)) if skip_names else '-'}",
            file=sys.stderr,
            flush=True,
        )

    def execute(pass_name: str, operation: BootstrapOperation8616) -> bool:
        """Run one enabled command and close its timing/validation lane."""
        if pass_name in skip_names:
            return True
        if debug_enabled and pass_name in {
            "_materialize_direct_stack_mov_instructions_8616",
            "_materialize_direct_stack_incdec_instructions_8616",
        }:
            print(
                f"[postprocess-bootstrap] enter {pass_name}",
                file=sys.stderr,
                flush=True,
            )
        started = time.perf_counter()
        keep_running = apply_step(pass_name, operation)
        if timing_enabled:
            print(
                f"[{time.strftime('%H:%M:%S')}] postprocess bootstrap: "
                f"{pass_name} ({time.perf_counter() - started:.3f}s)",
                file=sys.stderr,
                flush=True,
            )
        return bool(keep_running and not surface._inertia_postprocess_validation_failed)

    for pass_name, operation in operations.ordered():
        if not execute(pass_name, operation):
            return False

    jcc_name = "_rewrite_decoded_jcc_conditions_8616"
    return bool(
        jcc_name in skip_names
        or operations.selector_return_contract_active()
        or execute(jcc_name, operations.rewrite_decoded_jcc_conditions)
    )
