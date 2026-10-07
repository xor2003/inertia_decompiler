from types import SimpleNamespace

from inertia.validation.tail_validation import (
    extract_x86_16_tail_validation_snapshot,
    format_x86_16_tail_validation_diff,
    persist_x86_16_tail_validation_snapshot,
)
from inertia.validation.validation_semantic_failures import (
    TailSemanticFailureScope8616,
    collect_tail_semantic_failures_8616,
    format_tail_semantic_failures_8616,
    normalize_tail_semantic_failures_8616,
)


def _summary(**overrides: tuple[str, ...]) -> SimpleNamespace:
    fields = {
        "def_use_issues": (),
        "missing_required_calls": (),
        "callsite_multiplicity_issues": (),
        "call_interface_issues": (),
        "call_argument_class_issues": (),
        "function_parameter_issues": (),
        "function_return_class_issues": (),
        "control_flow_issues": (),
        "storage_identity_issues": (),
    }
    fields.update(overrides)
    return SimpleNamespace(**fields)


def test_all_after_scope_keeps_preexisting_semantic_failures() -> None:
    issue = "uninitialized-read:register-carrier:flags"
    before = _summary(def_use_issues=(issue,))
    after = _summary(def_use_issues=(issue,))

    assert collect_tail_semantic_failures_8616(after, before=before) == {
        "def_use": (issue,),
    }


def test_introduced_scope_ignores_unchanged_failures_and_keeps_new_ones() -> None:
    existing = "uninitialized-read:register-carrier:flags"
    introduced = "missing-required-call:0x1234"
    before = _summary(def_use_issues=(existing,))
    after = _summary(
        def_use_issues=(existing,),
        missing_required_calls=(introduced,),
    )

    assert collect_tail_semantic_failures_8616(
        after,
        before=before,
        scope=TailSemanticFailureScope8616.INTRODUCED,
    ) == {"required_calls": (introduced,)}


def test_introduced_scope_treats_duplicate_issue_as_a_new_failure() -> None:
    issue = "call-interface:0x5678"

    assert collect_tail_semantic_failures_8616(
        _summary(call_interface_issues=(issue, issue)),
        before=_summary(call_interface_issues=(issue,)),
        scope=TailSemanticFailureScope8616.INTRODUCED,
    ) == {"call_interfaces": (issue,)}


def test_callsite_multiplicity_keeps_its_own_semantic_failure_family() -> None:
    issue = "callsite-multiplicity:duplicate-final-callsite:callsite=0x1010"

    assert collect_tail_semantic_failures_8616(
        _summary(callsite_multiplicity_issues=(issue,)),
    ) == {"callsite_multiplicity": (issue,)}


def test_semantic_failure_codec_keeps_typed_families_and_issues() -> None:
    failures = normalize_tail_semantic_failures_8616(
        {
            "call_interfaces": ["call-interface:0x1234"],
            "invalid": "not-a-sequence-of-issues",
            42: ["not-a-family"],
        }
    )

    assert failures == {"call_interfaces": ("call-interface:0x1234",)}
    assert format_tail_semantic_failures_8616(failures) == (
        "call_interfaces: call-interface:0x1234",
    )


def test_semantic_failures_survive_tail_validation_snapshot_round_trip() -> None:
    function_info: dict[str, object] = {}
    codegen = SimpleNamespace()
    validation = {
        "changed": True,
        "status": "failed",
        "mode": "live_out",
        "semantic_failures": {"function_return_class": ("unresolved-return-class:ax",)},
    }

    persisted = persist_x86_16_tail_validation_snapshot(
        function_info=function_info,
        codegen=codegen,
        stage="structuring",
        validation=validation,
    )
    extracted = extract_x86_16_tail_validation_snapshot(function_info)

    assert persisted["semantic_failures"] == validation["semantic_failures"]
    assert extracted["structuring"]["semantic_failures"] == validation["semantic_failures"]
    assert format_x86_16_tail_validation_diff(dict(extracted["structuring"])) == (
        "function_return_class: unresolved-return-class:ax"
    )
