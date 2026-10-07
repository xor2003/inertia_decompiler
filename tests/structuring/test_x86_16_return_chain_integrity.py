"""Tests for the Structuring-owned materialized return-chain AST guard."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import CConstant, CReturn, CStatements, CVariable
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimStackVariable
import inertia.postprocess.decompiler_postprocess_stage as decompiler_postprocess_stage
import inertia.structuring.decompiler_structuring_stage as decompiler_structuring_stage
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.pipeline.errors import PipelineHardError

from inertia.structuring.return_chain_integrity import (
    MaterializedReturnChainIntegrityVerdict8616,
    assess_materialized_return_chain_integrity_8616,
    require_materialized_return_chain_integrity_8616,
)


class _DummyCodegen:
    """Minimum identity allocator required by current angr C AST nodes."""

    def __init__(self) -> None:
        self._idx = 0
        self.cstyle_null_cmp = False
        self.project = SimpleNamespace(arch=Arch86_16())

    def next_idx(self, _name: str) -> int:
        """Return one unique C node identity."""
        self._idx += 1
        return self._idx

    def next_ident(self, name: str) -> str:
        """Return a stable display identity for one C node class."""
        return name

    def next_node_idx(self) -> int:
        """Return one unique generic node identity."""
        return self.next_idx("")


def _return_statement(value: int, codegen: _DummyCodegen) -> CReturn:
    """Build one constant return for the third-party structured C boundary."""
    return CReturn(CConstant(value, SimTypeShort(False), codegen=codegen), codegen=codegen)


def _codegen_with_returns(*values: int) -> SimpleNamespace:
    """Build initialized return-chain metadata and a matching C AST test double."""
    codegen = _DummyCodegen()
    statements = CStatements(
        statements=[_return_statement(value, codegen) for value in values],
        codegen=codegen,
    )
    return SimpleNamespace(
        cfunc=SimpleNamespace(statements=statements),
        _inertia_return_chain_flattened_8616=False,
        _inertia_return_chain_suffix_materialized_8616=True,
        _inertia_return_chain_materialized_values_8616=(1, 2, 3),
        _inertia_return_chain_final_value_8616=255,
    )


def _codegen_with_mask_return(*, preserved: bool) -> SimpleNamespace:
    """Build one Structuring-owned mask return and its durable fingerprint."""
    codegen = _DummyCodegen()
    mask = CVariable(
        SimStackVariable(-4, 2, base="bp", name="mask", region=0x1000),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    retval = mask if preserved else CConstant(0, SimTypeShort(False), codegen=codegen)
    return SimpleNamespace(
        cfunc=SimpleNamespace(statements=CStatements([CReturn(retval, codegen=codegen)], codegen=codegen)),
        _inertia_return_chain_flattened_8616=False,
        _inertia_return_chain_suffix_materialized_8616=False,
        _inertia_mask_accumulator_materialized_8616=True,
        _inertia_mask_accumulator_return_fingerprint_8616="stack_slot:SS:BP-0x4:size2",
    )


def test_return_chain_integrity_is_not_applicable_without_metadata() -> None:
    """Third-party codegen objects without return-chain state remain unaffected."""
    result = assess_materialized_return_chain_integrity_8616(SimpleNamespace())

    assert result.verdict is MaterializedReturnChainIntegrityVerdict8616.NOT_APPLICABLE
    assert result.accepted is True


def test_return_chain_integrity_accepts_values_independent_of_render_spelling() -> None:
    """The guard consumes integer AST constants, so decimal versus hex is irrelevant."""
    result = assess_materialized_return_chain_integrity_8616(_codegen_with_returns(1, 2, 3, 255))

    assert result.verdict is MaterializedReturnChainIntegrityVerdict8616.PASSED
    assert result.expected_values == (1, 2, 3, 255)
    assert result.missing_values == ()


def test_return_chain_integrity_accepts_mask_accumulator_return() -> None:
    result = assess_materialized_return_chain_integrity_8616(
        _codegen_with_mask_return(preserved=True)
    )

    assert result.verdict is MaterializedReturnChainIntegrityVerdict8616.PASSED
    assert result.active is True


def test_return_chain_integrity_rejects_lost_mask_accumulator_return() -> None:
    result = assess_materialized_return_chain_integrity_8616(
        _codegen_with_mask_return(preserved=False)
    )

    assert result.verdict is MaterializedReturnChainIntegrityVerdict8616.MISSING_RETURN_EXPRESSION
    assert result.accepted is False
    assert result.observed_return_fingerprints == ("const:0",)


def test_return_chain_integrity_accepts_coalesced_equal_return_edges() -> None:
    """Equal CFG return values may share one structured return statement."""
    codegen = _codegen_with_returns(0, 1)
    codegen._inertia_return_chain_materialized_values_8616 = (0, 0, 0, 0)
    codegen._inertia_return_chain_final_value_8616 = 1

    result = assess_materialized_return_chain_integrity_8616(codegen)

    assert result.verdict is MaterializedReturnChainIntegrityVerdict8616.PASSED
    assert result.expected_values == (0, 0, 0, 0, 1)
    assert result.observed_values == (0, 1)


def test_active_return_chain_blocks_weaker_selector_replacement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A later selector pass must not discard an accepted return-chain proof."""
    codegen = _codegen_with_returns(1, 2, 3, 255)
    original_root = codegen.cfunc.statements

    def unexpected_selector_replacement(_project: object, _codegen: object) -> bool:
        raise AssertionError("selector replacement must not run over an active return chain")

    monkeypatch.setattr(
        decompiler_postprocess_stage,
        "_materialize_cfg_selector_return_branches_8616",
        unexpected_selector_replacement,
    )

    changed = decompiler_structuring_stage._materialize_structuring_selector_return_branches_8616(
        SimpleNamespace(),
        codegen,
    )

    assert changed is False
    assert codegen.cfunc.statements is original_root


def test_return_chain_integrity_reports_every_missing_expected_value() -> None:
    """Loss of conditional or final constant returns produces a typed refusal."""
    result = assess_materialized_return_chain_integrity_8616(_codegen_with_returns(1, 3))

    assert result.verdict is MaterializedReturnChainIntegrityVerdict8616.MISSING_RETURN_VALUES
    assert result.accepted is False
    assert result.missing_values == (2, 255)


def test_return_chain_integrity_requirement_fails_at_structuring_layer() -> None:
    """The shared pipeline guard reports typed AST loss without reading C text."""
    codegen = _codegen_with_returns(1, 3)

    with pytest.raises(PipelineHardError, match="authoritative C AST lost") as caught:
        require_materialized_return_chain_integrity_8616(codegen, context="test")

    assert caught.value.layer == "structuring"
    assert caught.value.details["missing_values"] == (2, 255)
