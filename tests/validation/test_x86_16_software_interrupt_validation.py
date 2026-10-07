from __future__ import annotations

from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeChar, SimTypeShort
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.frontend.x86_16.interrupt_contract import interrupt_core_addr_8616
from inertia.ir.core import IRBinaryValue, IRValue, MemSpace

from inertia.semantics.software_interrupt_inputs import (
    SoftwareInterruptInputArtifact8616,
    SoftwareInterruptInputFact8616,
    SoftwareInterruptInputStats8616,
    SoftwareInterruptRefusalKind8616,
)
from inertia.validation.validation_interrupt_calls import (
    SoftwareInterruptValidationIssueKind8616,
    validate_software_interrupt_inputs_8616,
)


class _Codegen:
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


def _fact() -> SoftwareInterruptInputFact8616:
    return SoftwareInterruptInputFact8616(
        callsite_addr=0x104,
        target_addr=interrupt_core_addr_8616(0x33),
        vector=0x33,
        selector_value=4,
        argument_registers=("ax", "cx", "dx"),
        argument_values=tuple(
            IRValue(MemSpace.CONST, const=value, size=2) for value in (4, 5, 6)
        ),
        result_register="ax",
    )


def _codegen_with_fact() -> _Codegen:
    codegen = _Codegen()
    codegen._inertia_software_interrupt_input_artifact_8616 = (
        SoftwareInterruptInputArtifact8616(
            facts=(_fact(),),
            stats=SoftwareInterruptInputStats8616(1, 1, 1, 1, 0),
        )
    )
    return codegen


def _constant(value: int, codegen: _Codegen) -> structured_c.CConstant:
    return structured_c.CConstant(value, SimTypeShort(False), codegen=codegen)


def _returned_call_root(
    codegen: _Codegen,
    values: tuple[int, ...],
) -> tuple[structured_c.CStatements, structured_c.CFunctionCall]:
    call = structured_c.CFunctionCall(
        "interrupt_int33",
        None,
        [_constant(value, codegen) for value in values],
        tags={"ins_addr": 0x104},
        codegen=codegen,
    )
    root = structured_c.CStatements(
        statements=[structured_c.CReturn(call, codegen=codegen)],
        codegen=codegen,
    )
    return root, call


@pytest.mark.parametrize(
    ("values", "expected_kind"),
    (
        ((4, 5), SoftwareInterruptValidationIssueKind8616.ARGUMENT_COUNT_MISMATCH),
        ((4, 5, 7), SoftwareInterruptValidationIssueKind8616.ARGUMENT_VALUE_MISMATCH),
    ),
)
def test_interrupt_validation_rejects_argument_loss_or_drift(
    values: tuple[int, ...],
    expected_kind: SoftwareInterruptValidationIssueKind8616,
) -> None:
    codegen = _codegen_with_fact()
    root, _call = _returned_call_root(codegen, values)

    report = validate_software_interrupt_inputs_8616(codegen, root)

    assert not report.passed
    assert tuple(issue.kind for issue in report.issues) == (expected_kind,)


def test_interrupt_validation_rejects_missing_call() -> None:
    codegen = _codegen_with_fact()
    root = structured_c.CStatements(statements=[], codegen=codegen)

    report = validate_software_interrupt_inputs_8616(codegen, root)

    assert tuple(issue.kind for issue in report.issues) == (
        SoftwareInterruptValidationIssueKind8616.MISSING_CALL,
    )


def test_interrupt_validation_rejects_unavailable_argument_surface() -> None:
    codegen = _codegen_with_fact()
    root, call = _returned_call_root(codegen, (4, 5, 6))
    call.args = object()

    report = validate_software_interrupt_inputs_8616(codegen, root)

    assert tuple(issue.kind for issue in report.issues) == (
        SoftwareInterruptValidationIssueKind8616.ARGUMENT_SURFACE_UNAVAILABLE,
    )


def test_interrupt_validation_rejects_semantics_refusal() -> None:
    codegen = _Codegen()
    codegen._inertia_software_interrupt_input_artifact_8616 = (
        SoftwareInterruptInputArtifact8616(
            refusals=(
                (
                    0x104,
                    SoftwareInterruptRefusalKind8616.REQUIRED_REGISTER_UNRESOLVED,
                    "dx",
                ),
            ),
            stats=SoftwareInterruptInputStats8616(1, 1, 1, 0, 1),
        )
    )
    root = structured_c.CStatements(statements=[], codegen=codegen)

    report = validate_software_interrupt_inputs_8616(codegen, root)

    assert tuple(issue.kind for issue in report.issues) == (
        SoftwareInterruptValidationIssueKind8616.INPUT_RECOVERY_REFUSED,
    )


def test_interrupt_validation_accepts_exact_returned_call() -> None:
    codegen = _codegen_with_fact()
    root, _call = _returned_call_root(codegen, (4, 5, 6))

    report = validate_software_interrupt_inputs_8616(codegen, root)

    assert report.passed
    assert report.materialized_count == 1


def test_interrupt_validation_accepts_proven_byte_shift_count() -> None:
    codegen = _Codegen()
    shifted = IRBinaryValue(
        "Shl",
        IRValue(MemSpace.CONST, const=5, size=2),
        IRValue(MemSpace.CONST, const=1, size=1),
        size=2,
    )
    fact = SoftwareInterruptInputFact8616(
        callsite_addr=0x104,
        target_addr=interrupt_core_addr_8616(0x33),
        vector=0x33,
        selector_value=4,
        argument_registers=("ax", "cx", "dx"),
        argument_values=(
            IRValue(MemSpace.CONST, const=4, size=2),
            shifted,
            IRValue(MemSpace.CONST, const=6, size=2),
        ),
        result_register="ax",
    )
    codegen._inertia_software_interrupt_input_artifact_8616 = (
        SoftwareInterruptInputArtifact8616(
            facts=(fact,),
            stats=SoftwareInterruptInputStats8616(1, 1, 1, 1, 0),
        )
    )
    shifted_ast = structured_c.CBinaryOp(
        "Shl",
        _constant(5, codegen),
        structured_c.CConstant(1, SimTypeChar(False), codegen=codegen),
        codegen=codegen,
    )
    call = structured_c.CFunctionCall(
        "interrupt_int33",
        None,
        [_constant(4, codegen), shifted_ast, _constant(6, codegen)],
        tags={"ins_addr": 0x104},
        codegen=codegen,
    )
    root = structured_c.CStatements(
        statements=[structured_c.CReturn(call, codegen=codegen)],
        codegen=codegen,
    )

    report = validate_software_interrupt_inputs_8616(codegen, root)

    assert report.passed
    assert report.materialized_count == 1
