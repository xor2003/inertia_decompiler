"""Typed def-use regressions for unresolved angr virtual carriers."""

from __future__ import annotations

from types import SimpleNamespace

from angr.ailment.expression import VirtualVariable, VirtualVariableCategory
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CDirtyExpression,
    CStatements,
    CUnaryOp,
    CVariable,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimStackVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16

from inertia.validation.status_flag_preservation import (
    PackedStatusFlagPreservationEvidence8616,
)
from inertia.validation.tail_validation import (
    refresh_x86_16_final_semantic_validation_8616,
)
from inertia.validation.validation_dataflow import validate_structured_def_use_8616


class _Codegen:
    """Minimal third-party codegen surface for structured-C fixtures."""

    def __init__(self) -> None:
        self._idx = 0
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cstyle_null_cmp = False

    def next_idx(self, _name: str) -> int:
        """Return a stable synthetic C AST index."""
        self._idx += 1
        return self._idx
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def _dirty(codegen: _Codegen, varid: int) -> CDirtyExpression:
    """Build one unresolved virtual carrier with structured SSA identity."""
    return CDirtyExpression(SimpleNamespace(varid=varid), codegen=codegen)


def _register_dirty(codegen: _Codegen, varid: int, reg_offset: int) -> CDirtyExpression:
    """Build one register-backed AIL virtual carrier."""
    virtual = VirtualVariable(
        0,
        varid,
        16,
        VirtualVariableCategory.REGISTER,
        oident=reg_offset,
    )
    return CDirtyExpression(virtual, codegen=codegen)


def _local(codegen: _Codegen) -> CVariable:
    """Build one BP-relative destination local."""
    return CVariable(
        SimStackVariable(-2, 2, base="bp", name="local_2"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )


def test_def_use_refuses_uninitialized_virtual_carrier_read() -> None:
    codegen = _Codegen()
    root = CStatements(
        [CAssignment(_local(codegen), _dirty(codegen, 7), codegen=codegen)],
        codegen=codegen,
    )

    report = validate_structured_def_use_8616(root, include_virtual_carriers=True)

    assert report.passed is False
    assert report.failure_count == 1
    assert "virtual-carrier:varid-7:size2" in report.issues[0].token()


def test_intermediate_def_use_leaves_regenerated_virtual_carriers_unclassified() -> None:
    codegen = _Codegen()
    root = CStatements(
        [CAssignment(_local(codegen), _dirty(codegen, 7), codegen=codegen)],
        codegen=codegen,
    )

    report = validate_structured_def_use_8616(root)

    assert report.passed is True
    assert report.raw_fact_count == 0


def test_final_semantic_refresh_opts_into_virtual_carrier_validation() -> None:
    codegen = _Codegen()
    root = CStatements(
        [CAssignment(_local(codegen), _dirty(codegen, 7), codegen=codegen)],
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(arg_list=[], statements=root)

    intermediate = refresh_x86_16_final_semantic_validation_8616(
        codegen.project,
        codegen,
        persist_failures=False,
    )
    final = refresh_x86_16_final_semantic_validation_8616(
        codegen.project,
        codegen,
        persist_failures=False,
        include_virtual_carriers=True,
    )

    assert intermediate.def_use.failure_count == 0
    assert final.def_use.failure_count == 1


def test_def_use_accepts_virtual_carrier_after_exact_definition() -> None:
    codegen = _Codegen()
    virtual_definition = _dirty(codegen, 7)
    virtual_read = _dirty(codegen, 7)
    root = CStatements(
        [
            CAssignment(
                virtual_definition,
                CConstant(3, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            CAssignment(_local(codegen), virtual_read, codegen=codegen),
        ],
        codegen=codegen,
    )

    report = validate_structured_def_use_8616(root, include_virtual_carriers=True)

    assert report.passed is True
    assert report.classified_fact_count == 1
    assert report.materialized_count == 1


def test_def_use_accepts_register_backed_virtual_at_exact_packed_flag_site() -> None:
    codegen = _Codegen()
    assignment = CAssignment(
        _dirty(codegen, 8),
        _register_dirty(codegen, 7, 36),
        codegen=codegen,
    )
    assignment.tags["ins_addr"] = 0x1010
    root = CStatements([assignment], codegen=codegen)

    report = validate_structured_def_use_8616(
        root,
        include_virtual_carriers=True,
        packed_status_flag_preservation=PackedStatusFlagPreservationEvidence8616(
            36,
            frozenset({0x1010}),
        ),
    )

    assert report.passed is True
    assert report.materialized_count == 1


def test_def_use_refuses_register_backed_virtual_outside_packed_flag_site() -> None:
    codegen = _Codegen()
    assignment = CAssignment(
        _dirty(codegen, 8),
        _register_dirty(codegen, 7, 36),
        codegen=codegen,
    )
    assignment.tags["ins_addr"] = 0x1010
    root = CStatements([assignment], codegen=codegen)

    report = validate_structured_def_use_8616(
        root,
        include_virtual_carriers=True,
        packed_status_flag_preservation=PackedStatusFlagPreservationEvidence8616(
            36,
            frozenset({0x1020}),
        ),
    )

    assert report.passed is False
    assert report.failure_count == 1
    assert "register-carrier:reg+0x24:size2" in report.issues[0].token()


def test_def_use_refuses_unresolved_dereference_store_carriers() -> None:
    codegen = _Codegen()
    address = CBinaryOp(
        "Add",
        _dirty(codegen, 10),
        _dirty(codegen, 11),
        codegen=codegen,
    )
    root = CStatements(
        [
            CAssignment(
                CUnaryOp("Dereference", address, codegen=codegen),
                _dirty(codegen, 12),
                codegen=codegen,
            )
        ],
        codegen=codegen,
    )

    report = validate_structured_def_use_8616(root, include_virtual_carriers=True)

    assert report.passed is False
    assert report.failure_count == 3
    assert {issue.storage.ssa_id for issue in report.issues} == {
        "varid-10",
        "varid-11",
        "varid-12",
    }
