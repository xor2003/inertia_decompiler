"""Tests for typed Rewrite bootstrap orchestration."""

from __future__ import annotations

from types import SimpleNamespace

from angr_platforms.X86_16.postprocess.bootstrap_orchestration import (
    PostprocessBootstrapOperations8616,
    run_postprocess_bootstrap_steps_8616,
)


def _operations(
    executed: list[str],
    *,
    selector_active: bool = False,
) -> PostprocessBootstrapOperations8616:
    """Return observable operations without implementing semantic behavior."""

    def operation(name: str):
        """Build one callback that records its authoritative owner invocation."""
        return lambda: executed.append(name) or False

    return PostprocessBootstrapOperations8616(
        normalize_fact_backed_stack_accesses=operation("normalize"),
        materialize_direct_stack_mov=operation("mov"),
        materialize_direct_stack_incdec=operation("incdec"),
        apply_typed_conditions=operation("conditions"),
        materialize_global_byte_index_sum_loop=operation("byte-loop"),
        materialize_selector_return_branches=operation("selector"),
        rewrite_decoded_jcc_conditions=operation("jcc"),
        selector_return_contract_active=lambda: selector_active,
    )


def test_bootstrap_preserves_order_and_skip_policy() -> None:
    """Enabled commands execute once in order while skipped commands stay absent."""
    applied: list[str] = []
    executed: list[str] = []
    codegen = SimpleNamespace(_inertia_postprocess_validation_failed=False)

    def apply_step(name: str, operation) -> bool:
        """Execute one guarded callback and record its pass identity."""
        applied.append(name)
        operation()
        return True

    assert run_postprocess_bootstrap_steps_8616(
        codegen,
        {"_apply_typed_conditions_to_codegen_8616"},
        apply_step,
        _operations(executed),
    )
    assert executed == [
        "normalize",
        "mov",
        "incdec",
        "byte-loop",
        "selector",
        "jcc",
    ]
    assert "_apply_typed_conditions_to_codegen_8616" not in applied


def test_bootstrap_selector_contract_suppresses_jcc_rewrite() -> None:
    """A proven selector-return contract keeps the legacy JCC bridge disabled."""
    executed: list[str] = []
    codegen = SimpleNamespace(_inertia_postprocess_validation_failed=False)

    assert run_postprocess_bootstrap_steps_8616(
        codegen,
        set(),
        lambda _name, operation: bool(operation()) or True,
        _operations(executed, selector_active=True),
    )
    assert "selector" in executed
    assert "jcc" not in executed


def test_bootstrap_stops_immediately_after_validation_failure() -> None:
    """No later semantic owner runs after the guarded transaction fails."""
    executed: list[str] = []
    codegen = SimpleNamespace(_inertia_postprocess_validation_failed=False)

    def apply_step(name: str, operation) -> bool:
        """Fail validation after the direct MOV command."""
        operation()
        if name == "_materialize_direct_stack_mov_instructions_8616":
            codegen._inertia_postprocess_validation_failed = True
        return True

    assert not run_postprocess_bootstrap_steps_8616(
        codegen,
        set(),
        apply_step,
        _operations(executed),
    )
    assert executed == ["normalize", "mov"]
