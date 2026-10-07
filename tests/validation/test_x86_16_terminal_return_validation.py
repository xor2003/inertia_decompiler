from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CReturn, CStatements, CVariable
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimStackVariable
import inertia.structuring.decompiler_structuring_stage as structuring_stage
from inertia.frontend.x86_16.arch_86_16 import Arch86_16

from inertia.structuring.terminal_register_values import (
    TerminalReturnValueMaterializationResult8616,
    materialize_linear_terminal_return_value_8616,
)
from inertia.validation.tail_validation import (
    canonicalize_tail_validation_summary_field_values_8616,
)
from inertia.validation.tail_validation_fingerprint import _expr_fingerprint
from inertia.validation.validation_terminal_returns import (
    TerminalReturnValidationRefusal8616,
    terminal_return_value_validation_delta_8616,
)


class _DummyCodegen:
    def __init__(self) -> None:
        self._idx = 0
        self.cstyle_null_cmp = False
        self.project = SimpleNamespace(arch=Arch86_16())

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx

    def next_node_idx(self) -> int:
        return self.next_idx("")

    def next_ident(self, name: str) -> str:
        return name


def _materialized_mul_return() -> tuple[_DummyCodegen, TerminalReturnValueMaterializationResult8616]:
    codegen = _DummyCodegen()
    argument_a = CVariable(
        SimStackVariable(4, 2, base="bp", name="a", region=0x1000),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    argument_b = CVariable(
        SimStackVariable(6, 2, base="bp", name="b", region=0x1000),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    return_node = CReturn(argument_a, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=0x4010,
        arg_list=(argument_a, argument_b),
        statements=CStatements([return_node], codegen=codegen),
        functy=SimpleNamespace(returnty=SimTypeShort(False).with_arch(codegen.project.arch)),
    )
    function = SimpleNamespace(prototype=None)
    proven_value = CBinaryOp("Mul", argument_a, argument_b, codegen=codegen)

    def recover_proven_value(*_args: object) -> CBinaryOp:
        codegen._inertia_missing_terminal_ax_return_terminal_value_block_count_8616 = 1
        return proven_value

    result = materialize_linear_terminal_return_value_8616(
        codegen.project,
        codegen,
        function,
        recover_proven_value=recover_proven_value,
        expressions_equivalent=lambda current, proven: current is proven,
    )
    return codegen, result


def _validation_delta(
    codegen: _DummyCodegen,
    result: TerminalReturnValueMaterializationResult8616,
    *,
    include_stack_change: bool = False,
) -> dict[str, object]:
    assert result.replaced_return_value is not None
    assert result.materialized_return_value is not None
    codegen.project._inertia_tail_validation_active_codegen = codegen
    try:
        raw_added = _expr_fingerprint(result.materialized_return_value, codegen.project)
        raw_removed = _expr_fingerprint(result.replaced_return_value, codegen.project)
    finally:
        del codegen.project._inertia_tail_validation_active_codegen
    assert "stack_arg:" in raw_added
    assert "stack_arg:" in raw_removed
    added = canonicalize_tail_validation_summary_field_values_8616("returns", {raw_added})
    removed = canonicalize_tail_validation_summary_field_values_8616("returns", {raw_removed})
    delta: dict[str, object] = {
        "returns": {
            "added": tuple(added),
            "removed": tuple(removed),
        }
    }
    if include_stack_change:
        delta["stack_writes"] = {"added": ("stack_slot:SS:BP-0x2:size2",), "removed": ()}
    return {"changed": True, "status": "changed", "delta": delta}


def test_terminal_return_validation_accepts_only_exact_return_delta() -> None:
    codegen, result = _materialized_mul_return()

    accepted = terminal_return_value_validation_delta_8616(
        codegen.project,
        codegen,
        result,
        _validation_delta(codegen, result),
    )
    refused = terminal_return_value_validation_delta_8616(
        codegen.project,
        codegen,
        result,
        _validation_delta(codegen, result, include_stack_change=True),
    )

    assert accepted.accepted is True
    assert accepted.stats.classified_fact_count == accepted.stats.materialized_count == 1
    assert refused.accepted is False
    assert refused.refusal is TerminalReturnValidationRefusal8616.UNRELATED_DELTA


def test_structuring_validation_consumes_exact_terminal_return_delta(monkeypatch) -> None:
    codegen, result = _materialized_mul_return()
    codegen._inertia_terminal_return_value_materialization_result_8616 = result
    project = SimpleNamespace(kb=SimpleNamespace(functions=None))
    validation = _validation_delta(codegen, result)
    monkeypatch.setattr(
        structuring_stage,
        "build_x86_16_tail_validation_verdict",
        lambda pass_name, _validation: f"{pass_name}:stable",
    )

    accepted = structuring_stage._try_accept_structuring_validation_delta_from_evidence_8616(
        project,
        codegen,
        validation,
        spec_name="terminal_return",
    )

    assert accepted is True
    assert validation["changed"] is False
    assert validation["status"] == "stable"
    assert "delta" not in validation
    assert codegen._inertia_structuring_terminal_return_validation_accepts_8616 == 1
