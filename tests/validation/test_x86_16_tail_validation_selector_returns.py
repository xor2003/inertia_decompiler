"""Regression tests for selector-return edge validation."""

from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CBinaryOp,
    CConstant,
    CIfElse,
    CReturn,
    CStatements,
)
from angr.sim_type import SimTypeShort
from inertia.frontend.x86_16.arch_86_16 import Arch86_16

from inertia.validation.tail_validation import (
    collect_x86_16_tail_validation_summary,
    compare_x86_16_tail_validation_summaries,
)
from inertia.validation.tail_validation_selector_returns import (
    collect_selector_return_fingerprints_8616,
    parse_selector_return_fingerprint_8616,
)


class _Codegen8616:
    """Minimal angr codegen boundary for selector-return validation tests."""

    def __init__(self) -> None:
        self._idx = 0
        self.cstyle_null_cmp = False
        self.cfunc: object | None = None
        self.project = SimpleNamespace(arch=Arch86_16())

    def next_idx(self, _name: str) -> int:
        """Return a stable synthetic AST index."""
        self._idx += 1
        return self._idx
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def _constant_8616(value: int, codegen: _Codegen8616) -> CConstant:
    """Build one word constant for a synthetic selector."""
    return CConstant(value, SimTypeShort(False), codegen=codegen)


def _selector_root_8616(
    condition_op: str,
    true_value: int,
    false_value: int,
    codegen: _Codegen8616,
) -> CStatements:
    """Build ``if (condition) return true; return false;``."""
    condition = CBinaryOp(
        condition_op,
        _constant_8616(1, codegen),
        _constant_8616(2, codegen),
        codegen=codegen,
    )
    branch = CIfElse(
        [
            (
                condition,
                CStatements([CReturn(_constant_8616(true_value, codegen), codegen=codegen)], codegen=codegen),
            )
        ],
        codegen=codegen,
    )
    return CStatements(
        [branch, CReturn(_constant_8616(false_value, codegen), codegen=codegen)],
        addr=0x4010,
        codegen=codegen,
    )


def _collect_direct_8616(root: CStatements):
    """Collect selector fingerprints using deterministic synthetic callbacks."""

    def condition_fingerprint(condition: object) -> str:
        assert isinstance(condition, CBinaryOp)
        return f"{condition.op}(const:1,const:2)"

    def return_fingerprint(value: object) -> str:
        assert isinstance(value, CConstant)
        return f"const:{value.value}"

    return collect_selector_return_fingerprints_8616(
        root,
        condition_fingerprint=condition_fingerprint,
        return_fingerprint=return_fingerprint,
    )


def test_selector_return_fingerprint_refuses_inverse_condition_with_unchanged_arms() -> None:
    before_codegen = _Codegen8616()
    after_codegen = _Codegen8616()
    before = _collect_direct_8616(_selector_root_8616("CmpLT", 1, 2, before_codegen))
    after = _collect_direct_8616(_selector_root_8616("CmpGE", 1, 2, after_codegen))

    assert before.fingerprints != after.fingerprints
    assert before.stats.classified_fact_count == before.stats.materialized_count == 1


def test_selector_return_fingerprint_accepts_inverse_condition_with_swapped_arms() -> None:
    before_codegen = _Codegen8616()
    after_codegen = _Codegen8616()
    before = _collect_direct_8616(_selector_root_8616("CmpLT", 1, 2, before_codegen))
    after = _collect_direct_8616(_selector_root_8616("CmpGE", 2, 1, after_codegen))

    assert before.fingerprints == after.fingerprints


def test_tail_validation_summary_observes_selector_return_edge_polarity() -> None:
    project = SimpleNamespace(arch=Arch86_16())
    before_codegen = _Codegen8616()
    after_codegen = _Codegen8616()
    before_root = _selector_root_8616("CmpLT", 1, 2, before_codegen)
    after_root = _selector_root_8616("CmpGE", 1, 2, after_codegen)
    before_codegen.cfunc = SimpleNamespace(addr=0x4010, body=before_root)
    after_codegen.cfunc = SimpleNamespace(addr=0x4010, body=after_root)

    before = collect_x86_16_tail_validation_summary(project, before_codegen, mode="live_out")
    after = collect_x86_16_tail_validation_summary(project, after_codegen, mode="live_out")
    diff = compare_x86_16_tail_validation_summaries(before, after)

    assert diff["changed"] is True
    assert any(token.startswith("selector-return:") for token in before.control_flow_effects)


def test_tail_validation_compacts_selector_return_as_typed_observation(monkeypatch) -> None:
    """Oversized selectors retain condition candidates and exact return arms."""
    monkeypatch.setenv("INERTIA_TAIL_VALIDATION_FINGERPRINT_LIMIT", "16")
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _Codegen8616()
    root = _selector_root_8616("CmpLT", 7, 7, codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, body=root)

    summary = collect_x86_16_tail_validation_summary(project, codegen, mode="live_out")
    selector_tokens = tuple(
        token for token in summary.control_flow_effects if token.startswith("selector-return:")
    )

    assert len(selector_tokens) == 1
    observation = parse_selector_return_fingerprint_8616(selector_tokens[0])
    assert observation is not None
    assert observation.arms_identical
    assert len(observation.condition_candidates) == 2
    assert all(
        candidate.startswith("conditions:sha256:")
        for candidate in observation.condition_candidates
    )
