from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CBinaryOp,
    CConstant,
    CIfElse,
    CStatements,
    CVariable,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimStackVariable
from inertia.lowering.stack_lowering_impl import _canonicalize_stack_cvar_expr
from archinfo import ArchX86

from inertia.validation.validation_materialized_condition_storage import (
    MaterializedConditionStorageIntegrityStatus8616,
    MaterializedConditionStorageSurface8616,
    capture_materialized_condition_storage_surface_8616,
    compare_materialized_condition_storage_surfaces_8616,
    record_materialized_condition_storage_failure_8616,
)


class _Codegen:
    def __init__(self) -> None:
        self._next_index = 0
        self.cstyle_null_cmp = False
        self.cfunc: object | None = None
        self.project = SimpleNamespace(arch=ArchX86())

    def next_idx(self, _kind: str) -> int:
        index = self._next_index
        self._next_index += 1
        return index

    def next_node_idx(self) -> int:
        return self.next_idx("")

    def next_ident(self, name: str) -> str:
        return name


def _condition_codegen(*, offset: int, name: str, materialized: bool = True) -> _Codegen:
    codegen = _Codegen()
    variable_type = SimTypeShort(False)
    variable = CVariable(
        SimStackVariable(offset, 2, base="bp", name=name),
        variable_type=variable_type,
        codegen=codegen,
    )
    condition = CBinaryOp(
        "CmpNE",
        variable,
        CConstant(0, variable_type, codegen=codegen),
        codegen=codegen,
        tags={
            "ins_addr": 0x1234,
            "vex_block_addr": 0x1230,
            "inertia_structuring_condition_cfg_materialized_8616": materialized,
        },
    )
    root = CStatements(
        [
            CIfElse(
                [(condition, CStatements([], codegen=codegen))],
                else_node=None,
                cstyle_ifs=True,
                codegen=codegen,
            )
        ],
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(statements=root)
    return codegen


def test_materialized_condition_storage_ignores_names_but_detects_argument_redirect() -> None:
    before = capture_materialized_condition_storage_surface_8616(
        _condition_codegen(offset=2, name="which")
    )
    renamed = capture_materialized_condition_storage_surface_8616(
        _condition_codegen(offset=2, name="renamed")
    )
    redirected = capture_materialized_condition_storage_surface_8616(
        _condition_codegen(offset=4, name="value")
    )

    assert before == renamed
    assert before != redirected
    assert compare_materialized_condition_storage_surfaces_8616(
        before,
        renamed,
    ).status is MaterializedConditionStorageIntegrityStatus8616.STABLE
    drift = compare_materialized_condition_storage_surfaces_8616(before, redirected)
    assert drift.status is MaterializedConditionStorageIntegrityStatus8616.DRIFTED
    assert drift.drifted is True
    codegen = SimpleNamespace()
    assert record_materialized_condition_storage_failure_8616(codegen, drift) is True
    assert codegen._inertia_postprocess_validation_failed is True
    assert codegen._inertia_postprocess_validation_failure_pass == "materialized_condition_storage_integrity"
    assert "offset=2" in codegen._inertia_postprocess_validation_failure_error
    assert "offset=4" in codegen._inertia_postprocess_validation_failure_error


def test_materialized_condition_storage_reports_unobserved_without_structuring_marker() -> None:
    unobserved = capture_materialized_condition_storage_surface_8616(
        _condition_codegen(offset=2, name="which", materialized=False)
    )
    observed = capture_materialized_condition_storage_surface_8616(
        _condition_codegen(offset=4, name="value")
    )

    assert unobserved == MaterializedConditionStorageSurface8616(entries=())
    result = compare_materialized_condition_storage_surfaces_8616(unobserved, observed)
    assert result.status is MaterializedConditionStorageIntegrityStatus8616.UNOBSERVED
    assert result.drifted is False
    codegen = SimpleNamespace()
    assert record_materialized_condition_storage_failure_8616(codegen, result) is False
    assert vars(codegen) == {}


def test_stack_cvar_canonicalization_preserves_owned_condition_tags() -> None:
    codegen = _Codegen()
    variable_type = SimTypeShort(False)
    alias = CVariable(
        SimStackVariable(4, 2, base="bp", name="s_4"),
        variable_type=variable_type,
        codegen=codegen,
    )
    canonical = CVariable(
        SimStackVariable(4, 2, base="bp", name="arg_4"),
        variable_type=variable_type,
        codegen=codegen,
    )
    tags = {
        "ins_addr": 0x10126,
        "vex_block_addr": 0x10120,
        "inertia_structuring_condition_cfg_materialized_8616": True,
    }
    condition = CBinaryOp(
        "CmpLT",
        alias,
        CConstant(2, variable_type, codegen=codegen),
        codegen=codegen,
        tags=tags,
    )

    rewritten = _canonicalize_stack_cvar_expr(
        condition,
        codegen,
        unwrap_c_casts=lambda expression: expression,
        resolve_stack_cvar_at_offset=lambda *_args, **_kwargs: canonical,
    )

    assert isinstance(rewritten, CBinaryOp)
    assert rewritten.lhs is canonical
    assert dict(rewritten.tags.items()) == tags
    assert rewritten.tags is not condition.tags
