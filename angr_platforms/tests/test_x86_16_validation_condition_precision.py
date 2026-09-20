from __future__ import annotations

from types import SimpleNamespace

import pytest
from angr_platforms.X86_16 import decompiler_structuring_stage as structuring_stage
from angr_platforms.X86_16 import tail_validation as tail_validation_module
from angr_platforms.X86_16.structuring.condition_evidence_closure import (
    ConditionEvidenceClosure8616,
)
from angr_platforms.X86_16.validation_condition_closure_delta import (
    ConditionClosureDeltaStatus8616,
    validate_condition_closure_delta_8616,
)
from angr_platforms.X86_16.validation_condition_precision import (
    ConditionPrecisionEvidence8616,
    condition_precision_validation_delta_8616,
)

WIDE_LT = "CmpLT(stack_slot:SS:BP+0x4:size4,stack_slot:SS:BP+0x8:size4)"
WIDE_GT = "CmpGT(stack_slot:SS:BP+0x4:size4,stack_slot:SS:BP+0x8:size4)"
HIGH_LE = "CmpLE(stack_slot:SS:BP+0x6:size2,stack_slot:SS:BP+0xa:size2)"
HIGH_GE = "CmpGE(stack_slot:SS:BP+0x6:size2,stack_slot:SS:BP+0xa:size2)"


def _validation(*, extra_return: bool = False) -> dict[str, object]:
    delta: dict[str, object] = {
        "conditions": {
            "added": (WIDE_GT, WIDE_LT),
            "removed": (HIGH_GE, HIGH_LE),
        },
        "control_flow_effects": {
            "added": (f"if:{WIDE_GT}", f"if:{WIDE_LT}"),
            "removed": (f"if:{HIGH_GE}", f"if:{HIGH_LE}"),
        },
    }
    if extra_return:
        delta["returns"] = {"added": ("const:1",), "removed": ()}
    return {"changed": True, "status": "changed", "delta": delta}


def _codegen() -> SimpleNamespace:
    return SimpleNamespace(
        _inertia_condition_precision_evidence_8616=(
            ConditionPrecisionEvidence8616(HIGH_LE, WIDE_LT),
            ConditionPrecisionEvidence8616(HIGH_GE, WIDE_GT),
        )
    )


def test_condition_precision_validation_accepts_exact_evidence_pairs() -> None:
    result = condition_precision_validation_delta_8616(_codegen(), _validation())

    assert result.accepted is True
    assert result.stats.classified_fact_count == 2
    assert result.stats.materialized_count == 2
    assert result.stats.failure_count == 0


def test_condition_precision_validation_refuses_unmatched_condition() -> None:
    validation = _validation()
    delta = validation["delta"]
    assert isinstance(delta, dict)
    conditions = delta["conditions"]
    assert isinstance(conditions, dict)
    conditions["added"] = (WIDE_GT, "CmpEQ(const:1,const:2)")

    result = condition_precision_validation_delta_8616(_codegen(), validation)

    assert result.accepted is False
    assert result.stats.failure_count == 1


def test_condition_precision_validation_refuses_extra_semantic_field() -> None:
    result = condition_precision_validation_delta_8616(
        _codegen(),
        _validation(extra_return=True),
    )

    assert result.accepted is False
    assert result.stats.failure_count == 1


def _loop_validation() -> dict[str, object]:
    return {
        "changed": True,
        "delta": {
            "conditions": {"added": (WIDE_LT,), "removed": (HIGH_LE,)},
            "control_flow_effects": {
                "added": (
                    f"loop:{WIDE_LT}",
                    f"loop-body-calls:{WIDE_LT}:addr:0x1234,addr:0x5678",
                    f"loop-body-writes:{WIDE_LT}:stack_slot:SS:BP-0x2:size2",
                ),
                "removed": (
                    f"loop:{HIGH_LE}",
                    f"loop-body-calls:{HIGH_LE}:addr:0x1234,addr:0x5678",
                    f"loop-body-writes:{HIGH_LE}:stack_slot:SS:BP-0x2:size2",
                ),
            },
        },
    }


def test_condition_precision_accepts_exact_loop_guard_and_unchanged_body() -> None:
    result = condition_precision_validation_delta_8616(_codegen(), _loop_validation())
    assert result.accepted
    assert result.stats.materialized_count == 1


@pytest.mark.parametrize("corruption", ["call", "order", "write", "kind", "missing", "extra"])
def test_condition_precision_refuses_changed_loop_effects(corruption: str) -> None:
    validation = _loop_validation()
    controls = validation["delta"]["control_flow_effects"]
    added = list(controls["added"])
    if corruption == "call":
        added[1] = f"loop-body-calls:{WIDE_LT}:addr:0x9999,addr:0x5678"
    elif corruption == "order":
        added[1] = f"loop-body-calls:{WIDE_LT}:addr:0x5678,addr:0x1234"
    elif corruption == "write":
        added[2] = f"loop-body-writes:{WIDE_LT}:stack_slot:SS:BP-0x4:size2"
    elif corruption == "kind":
        added[0] = f"if:{WIDE_LT}"
    elif corruption == "missing":
        added.pop()
    else:
        added.append(f"loop-body-calls:{WIDE_LT}:addr:0x9999")
    controls["added"] = tuple(added)
    assert not condition_precision_validation_delta_8616(_codegen(), validation).accepted


def test_condition_precision_refuses_guard_kind_change() -> None:
    validation = _validation()
    validation["delta"]["control_flow_effects"]["added"] = (
        f"while:{WIDE_GT}", f"if:{WIDE_LT}",
    )
    assert not condition_precision_validation_delta_8616(_codegen(), validation).accepted


def test_structuring_precision_refuses_incomplete_condition_closure() -> None:
    """Exact changed-pair evidence cannot excuse an omitted typed branch."""
    required = frozenset({(0x101B0, 0x101A9), (0x101C0, 0x101B2)})
    codegen = _codegen()
    codegen.cfunc = SimpleNamespace(addr=0x4010)
    codegen._inertia_structuring_condition_evidence_closure_8616 = (
        ConditionEvidenceClosure8616(
            required_keys=required,
            materialized_keys=frozenset({(0x101B0, 0x101A9)}),
            unresolved_branch_owners=frozenset(),
        )
    )
    validation = _validation()
    validation["semantic_failures"] = None

    accepted = structuring_stage._try_accept_structuring_validation_delta_from_evidence_8616(
        SimpleNamespace(kb=SimpleNamespace(functions=None)),
        codegen,
        validation,
        spec_name="final",
    )

    assert accepted is False
    assert validation["changed"] is True
    assert "delta" in validation


def test_condition_precision_validation_accepts_compacted_exact_pair() -> None:
    before = "CmpNE(" + "lhs" * 180 + ",const:0)"
    after = "CmpEQ(" + "rhs" * 180 + ",const:0)"
    compact_before = tail_validation_module._compact_tail_validation_observable_8616(
        "conditions",
        before,
    )
    compact_after = tail_validation_module._compact_tail_validation_observable_8616(
        "conditions",
        after,
    )
    control_before = tail_validation_module._compact_tail_validation_observable_8616(
        "control_flow_effects",
        f"if:{before}",
    )
    control_after = tail_validation_module._compact_tail_validation_observable_8616(
        "control_flow_effects",
        f"if:{after}",
    )
    codegen = SimpleNamespace(
        _inertia_condition_precision_evidence_8616=(
            ConditionPrecisionEvidence8616(before, after),
        )
    )
    validation = {
        "changed": True,
        "delta": {
            "conditions": {
                "added": (compact_after,),
                "removed": (compact_before,),
            },
            "control_flow_effects": {
                "added": (control_after,),
                "removed": (control_before,),
            },
        },
    }

    result = condition_precision_validation_delta_8616(codegen, validation)

    assert control_before == f"if:{compact_before}"
    assert control_after == f"if:{compact_after}"
    assert result.accepted is True
    assert result.stats.failure_count == 0


def _closed_condition_surface() -> ConditionEvidenceClosure8616:
    keys = frozenset({(0x101B0, 0x101A9), (0x10174, 0x1016F)})
    return ConditionEvidenceClosure8616(
        required_keys=keys,
        materialized_keys=keys,
        unresolved_branch_owners=frozenset(),
    )


def _closed_condition_validation() -> dict[str, object]:
    before = "conditions:sha256:before:len:855"
    after = "conditions:sha256:after:len:612"
    return {
        "changed": True,
        "semantic_failures": None,
        "delta": {
            "conditions": {"added": (after,), "removed": (before,)},
            "control_flow_effects": {
                "added": (f"if:{after}",),
                "removed": (f"if:{before}",),
            },
            "helper_calls": {"added": (), "removed": ()},
            "global_writes": {"added": (), "removed": ()},
        },
    }


def test_condition_closure_accepts_condition_only_raw_flag_rewrite() -> None:
    result = validate_condition_closure_delta_8616(
        _closed_condition_surface(),
        _closed_condition_validation(),
    )

    assert result.status is ConditionClosureDeltaStatus8616.ACCEPTED
    assert result.stats.raw_fact_count == 2
    assert result.stats.materialized_count == 2
    assert result.stats.failure_count == 0


def test_condition_closure_refuses_incomplete_typed_owners() -> None:
    closure = _closed_condition_surface()
    incomplete = ConditionEvidenceClosure8616(
        required_keys=closure.required_keys,
        materialized_keys=frozenset({(0x101B0, 0x101A9)}),
        unresolved_branch_owners=frozenset(),
    )

    result = validate_condition_closure_delta_8616(
        incomplete,
        _closed_condition_validation(),
    )

    assert result.status is ConditionClosureDeltaStatus8616.REFUSED_INCOMPLETE_CLOSURE
    assert result.stats.failure_count == 1


def test_condition_closure_refuses_semantic_effect_or_failure() -> None:
    changed_write = _closed_condition_validation()
    delta = changed_write["delta"]
    assert isinstance(delta, dict)
    delta["global_writes"] = {"added": ("global:0x132",), "removed": ()}
    write_result = validate_condition_closure_delta_8616(
        _closed_condition_surface(),
        changed_write,
    )

    failed_semantics = _closed_condition_validation()
    failed_semantics["semantic_failures"] = {"control_flow": ("predicate_mismatch",)}
    semantic_result = validate_condition_closure_delta_8616(
        _closed_condition_surface(),
        failed_semantics,
    )

    assert write_result.status is ConditionClosureDeltaStatus8616.REFUSED_EFFECT_SURFACE
    assert semantic_result.status is ConditionClosureDeltaStatus8616.REFUSED_SEMANTIC_FAILURE


def test_condition_closure_refuses_nonmatching_control_guard() -> None:
    validation = _closed_condition_validation()
    delta = validation["delta"]
    assert isinstance(delta, dict)
    controls = delta["control_flow_effects"]
    assert isinstance(controls, dict)
    controls["added"] = ("if-body-calls:addr:0x1234",)

    result = validate_condition_closure_delta_8616(
        _closed_condition_surface(),
        validation,
    )

    assert result.status is ConditionClosureDeltaStatus8616.REFUSED_GUARD_MISMATCH
    assert result.stats.failure_count == 1
