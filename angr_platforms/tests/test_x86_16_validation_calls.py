from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CConstant,
    CFunctionCall,
    CStatements,
    CVariable,
)
from angr.sim_type import (
    SimTypeBottom,
    SimTypeChar,
    SimTypeFunction,
    SimTypeLong,
    SimTypePointer,
    SimTypeShort,
)
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16 import validation_calls as validation_calls_module
from angr_platforms.X86_16.callsite_summary import (
    CallerReturnUseEvidence8616,
    CallerReturnUseVerdict8616,
    CallsiteArgumentClass8616,
    CallsiteSummary8616,
    record_caller_return_use_evidence_8616,
)
from angr_platforms.X86_16.lowering.segmented_memory_lowering import (
    NearPointerArgumentFact8616,
)
from angr_platforms.X86_16.lowering.stack_prototype_materialization import (
    FunctionParameterWidthFact8616,
)
from angr_platforms.X86_16.pipeline.structured_ast_query_index import StructuredAstQueryIndex8616
from angr_platforms.X86_16.tail_validation import (
    X86_16TailValidationSummary,
    build_x86_16_tail_validation_cached_result,
    refresh_x86_16_final_semantic_validation_8616,
    x86_16_tail_validation_snapshot_passed,
)
from angr_platforms.X86_16.validation_calls import (
    validate_call_argument_classes_8616,
    validate_call_interfaces_8616,
    validate_function_parameters_8616,
    validate_function_return_class_8616,
    validate_required_callsites_8616,
)
from archinfo import ArchX86


class _Codegen:
    def __init__(self) -> None:
        self._next_index = 0
        self._inertia_callsite_summaries = {}
        self.project = SimpleNamespace(arch=ArchX86())

    def next_idx(self, _kind: str) -> int:
        index = self._next_index
        self._next_index += 1
        return index
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def _summary(
    *,
    stack_probe_helper: bool = False,
    arg_count: int | None = 2,
    target_addr: int = 0x2000,
    logical_arg_widths: tuple[int, ...] = (2, 2),
    logical_arg_classes: tuple[CallsiteArgumentClass8616, ...] = (
        CallsiteArgumentClass8616.VALUE,
        CallsiteArgumentClass8616.VALUE,
    ),
) -> CallsiteSummary8616:
    return CallsiteSummary8616(
        callsite_addr=0x1010,
        target_addr=target_addr,
        return_addr=0x1013,
        kind="direct_near",
        arg_count=arg_count,
        arg_widths=(2, 2),
        stack_cleanup=4,
        return_register="ax",
        return_used=True,
        stack_probe_helper=stack_probe_helper,
        logical_arg_widths=logical_arg_widths,
        logical_arg_classes=logical_arg_classes,
    )


def _empty_summary(*, missing_required_calls: tuple[str, ...] = ()) -> X86_16TailValidationSummary:
    return X86_16TailValidationSummary(
        (),
        (),
        (),
        (),
        (),
        (),
        (),
        (),
        missing_required_calls=missing_required_calls,
    )


def _record_return_evidence(
    codegen: _Codegen,
    verdict: CallerReturnUseVerdict8616,
    *,
    classified: int = 1,
    failures: int = 0,
) -> None:
    """Record one typed binary caller-use contract for return-class tests."""
    evidence = CallerReturnUseEvidence8616(
        target_addr=0x1000,
        verdict=verdict,
        raw_fact_count=1,
        normalized_fact_count=1,
        classified_fact_count=classified,
        materialized_count=classified,
        failure_count=failures,
        used_callsite_count=classified if verdict is CallerReturnUseVerdict8616.USED else 0,
        unused_callsite_count=classified if verdict is CallerReturnUseVerdict8616.UNUSED else 0,
        callsite_addrs=(0x1200,),
    )
    record_caller_return_use_evidence_8616(codegen.project, 0x1000, evidence)


def _set_return_surface(
    codegen: _Codegen,
    return_type: object,
    *,
    statements: CStatements | None = None,
) -> None:
    """Install the third-party final C declaration surface used by validation."""
    function_type = (
        SimTypeFunction([], return_type).with_arch(codegen.project.arch)
        if return_type is not None
        else None
    )
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        functy=function_type,
        arg_list=[],
        statements=statements,
    )


def _set_parameter_surface(
    codegen: _Codegen,
    parameter_types: tuple[object, ...],
    *,
    offsets: tuple[int, ...],
    storage_widths: tuple[int, ...] | None = None,
    statements: CStatements | None = None,
) -> None:
    """Install final C parameter types and their exact BP storage identities."""
    assert len(parameter_types) == len(offsets)
    if storage_widths is None:
        storage_widths = (2,) * len(offsets)
    assert len(storage_widths) == len(offsets)
    variables = tuple(
        SimStackVariable(
            offset,
            storage_width,
            base="bp",
            name=f"arg_{offset:x}",
            region=0x1000,
        )
        for offset, storage_width in zip(offsets, storage_widths, strict=True)
    )
    arg_list = [
        CVariable(variable, variable_type=parameter_type, codegen=codegen)
        for variable, parameter_type in zip(variables, parameter_types, strict=False)
    ]
    function_type = SimTypeFunction(
        list(parameter_types),
        SimTypeShort(False),
    ).with_arch(codegen.project.arch)
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        functy=function_type,
        arg_list=arg_list,
        statements=statements,
    )


def test_function_parameter_validation_accepts_exact_width() -> None:
    codegen = _Codegen()
    codegen._inertia_function_parameter_width_facts_8616 = (
        FunctionParameterWidthFact8616(stack_offset=4, width_bytes=2),
    )
    _set_parameter_surface(codegen, (SimTypeShort(False),), offsets=(4,))

    report = validate_function_parameters_8616(codegen.project, codegen)

    assert report.passed
    assert report.raw_fact_count == 1
    assert report.normalized_fact_count == 1
    assert report.classified_fact_count == 1
    assert report.materialized_count == 1
    assert report.failure_count == 0


@pytest.mark.parametrize(
    ("raw_offset", "expected"),
    [(6, 6), (None, None), ("unresolved", None), (True, None)],
)
def test_parameter_bp_offset_refuses_invalid_import_boundary(
    monkeypatch: pytest.MonkeyPatch,
    raw_offset: object,
    expected: int | None,
) -> None:
    """Only concrete integer coordinates may cross the skipped-import boundary."""
    variable = SimStackVariable(4, 2, base="bp", name="arg_4", region=0x1000)
    monkeypatch.setattr(
        validation_calls_module,
        "machine_bp_offset_for_stack_variable_8616",
        lambda _codegen, _variable: raw_offset,
    )

    assert validation_calls_module._parameter_bp_offset_8616(object(), variable, None) == expected


def test_function_parameter_validation_projects_complete_entry_sp_interface() -> None:
    codegen = _Codegen()
    codegen._inertia_function_parameter_width_facts_8616 = (
        FunctionParameterWidthFact8616(stack_offset=4, width_bytes=2),
        FunctionParameterWidthFact8616(stack_offset=6, width_bytes=2),
    )
    _set_parameter_surface(
        codegen,
        (SimTypeShort(False), SimTypeShort(False)),
        offsets=(2, 4),
    )

    report = validate_function_parameters_8616(codegen.project, codegen)

    assert report.passed
    assert report.classified_fact_count == 2
    assert report.materialized_count == 2


def test_function_parameter_validation_refuses_width_mismatch() -> None:
    codegen = _Codegen()
    codegen._inertia_function_parameter_width_facts_8616 = (
        FunctionParameterWidthFact8616(stack_offset=4, width_bytes=2),
    )
    _set_parameter_surface(
        codegen,
        (SimTypeLong(False),),
        offsets=(4,),
        storage_widths=(4,),
    )

    report = validate_function_parameters_8616(codegen.project, codegen)

    assert report.passed is False
    assert report.issue_tokens() == (
        "function-parameter:width-mismatch:function=0x1000:bp=+0x4:"
        "expected-width=2:actual-width=4",
    )


def test_function_parameter_validation_separates_char_type_from_word_storage() -> None:
    codegen = _Codegen()
    codegen._inertia_function_parameter_width_facts_8616 = (
        FunctionParameterWidthFact8616(stack_offset=4, width_bytes=2),
    )
    _set_parameter_surface(
        codegen,
        (SimTypeChar(False),),
        offsets=(4,),
        storage_widths=(2,),
    )

    report = validate_function_parameters_8616(codegen.project, codegen)

    assert report.passed
    assert report.classified_fact_count == 1
    assert report.materialized_count == 1


def test_function_parameter_validation_refuses_type_wider_than_storage() -> None:
    codegen = _Codegen()
    codegen._inertia_function_parameter_width_facts_8616 = (
        FunctionParameterWidthFact8616(stack_offset=4, width_bytes=2),
    )
    _set_parameter_surface(
        codegen,
        (SimTypeLong(False),),
        offsets=(4,),
        storage_widths=(2,),
    )

    report = validate_function_parameters_8616(codegen.project, codegen)

    assert report.passed is False
    assert report.issue_tokens() == (
        "function-parameter:width-mismatch:function=0x1000:bp=+0x4:"
        "expected-width=2:actual-width=4",
    )


def test_function_parameter_validation_accepts_binary_proven_pointer() -> None:
    codegen = _Codegen()
    codegen._inertia_near_pointer_argument_facts_8616 = (
        NearPointerArgumentFact8616(
            stack_offset=4,
            carrier_load_ins_addr=0x1010,
            dereference_ins_addr=0x1014,
            access_width_bytes=2,
        ),
    )
    pointer_type = SimTypePointer(SimTypeShort(False)).with_arch(codegen.project.arch)
    _set_parameter_surface(codegen, (pointer_type,), offsets=(4,))

    report = validate_function_parameters_8616(codegen.project, codegen)

    assert report.passed
    assert report.classified_fact_count == 1
    assert report.materialized_count == 1


def test_function_parameter_width_uses_abi_bytes_for_loaded_16_bit_project() -> None:
    codegen = _Codegen()
    codegen._inertia_function_parameter_width_facts_8616 = (
        FunctionParameterWidthFact8616(stack_offset=4, width_bytes=2),
    )
    pointer_type = SimTypePointer(SimTypeShort(False)).with_arch(codegen.project.arch)
    _set_parameter_surface(codegen, (pointer_type,), offsets=(4,))
    codegen.project.arch = SimpleNamespace(bits=32, bytes=2)

    report = validate_function_parameters_8616(codegen.project, codegen)

    assert report.passed
    assert report.classified_fact_count == 1
    assert report.materialized_count == 1


def test_function_parameter_validation_refuses_scalar_for_proven_pointer() -> None:
    codegen = _Codegen()
    codegen._inertia_near_pointer_argument_facts_8616 = (
        NearPointerArgumentFact8616(
            stack_offset=4,
            carrier_load_ins_addr=0x1010,
            dereference_ins_addr=0x1014,
            access_width_bytes=2,
        ),
    )
    _set_parameter_surface(codegen, (SimTypeShort(False),), offsets=(4,))

    report = validate_function_parameters_8616(codegen.project, codegen)

    assert report.passed is False
    assert report.issue_tokens() == (
        "function-parameter:class-mismatch:function=0x1000:bp=+0x4:"
        "expected-class=pointer:actual-class=value",
    )


def test_function_parameter_validation_does_not_infer_value_without_class_evidence() -> None:
    codegen = _Codegen()
    _set_parameter_surface(codegen, (SimTypeShort(False),), offsets=(4,))

    report = validate_function_parameters_8616(codegen.project, codegen)

    assert report.passed
    assert report.raw_fact_count == 0
    assert report.classified_fact_count == 0


def test_function_parameter_validation_refuses_missing_final_parameter_surface() -> None:
    codegen = _Codegen()
    codegen._inertia_function_parameter_width_facts_8616 = (
        FunctionParameterWidthFact8616(stack_offset=6, width_bytes=2),
    )
    _set_parameter_surface(codegen, (SimTypeShort(False),), offsets=(4,))

    report = validate_function_parameters_8616(codegen.project, codegen)

    assert report.passed is False
    assert report.issue_tokens() == (
        "function-parameter:type-surface-unavailable:function=0x1000:bp=+0x6:"
        "expected-width=2:actual-width=unknown",
    )


def test_function_parameter_validation_refuses_conflicting_width_evidence() -> None:
    codegen = _Codegen()
    codegen._inertia_function_parameter_width_facts_8616 = (
        FunctionParameterWidthFact8616(stack_offset=4, width_bytes=2),
        FunctionParameterWidthFact8616(stack_offset=4, width_bytes=4),
    )
    _set_parameter_surface(codegen, (SimTypeShort(False),), offsets=(4,))

    report = validate_function_parameters_8616(codegen.project, codegen)

    assert report.passed is False
    assert report.raw_fact_count == 2
    assert report.normalized_fact_count == 2
    assert report.classified_fact_count == 0
    assert report.issue_tokens() == (
        "function-parameter:width-evidence-conflict:function=0x1000:bp=+0x4",
    )


def test_function_return_class_validation_accepts_unobserved_void_surface() -> None:
    codegen = _Codegen()
    _record_return_evidence(codegen, CallerReturnUseVerdict8616.UNUSED)
    _set_return_surface(
        codegen,
        SimTypeBottom(label="void").with_arch(codegen.project.arch),
    )

    report = validate_function_return_class_8616(codegen.project, codegen)

    assert report.passed
    assert report.raw_fact_count == 1
    assert report.normalized_fact_count == 1
    assert report.classified_fact_count == 0
    assert report.materialized_count == 0
    assert report.failure_count == 0


def test_function_return_class_validation_accepts_proven_value() -> None:
    codegen = _Codegen()
    _record_return_evidence(codegen, CallerReturnUseVerdict8616.USED)
    _set_return_surface(codegen, SimTypeShort(False))

    report = validate_function_return_class_8616(codegen.project, codegen)

    assert report.passed
    assert report.classified_fact_count == 1
    assert report.materialized_count == 1
    assert report.failure_count == 0


def test_function_return_class_validation_refuses_void_for_proven_value() -> None:
    codegen = _Codegen()
    _record_return_evidence(codegen, CallerReturnUseVerdict8616.USED)
    _set_return_surface(
        codegen,
        SimTypeBottom(label="void").with_arch(codegen.project.arch),
    )

    report = validate_function_return_class_8616(codegen.project, codegen)

    assert report.passed is False
    assert report.issue_tokens() == (
        "function-return-class:class-mismatch:function=0x1000:"
        "expected=value:actual=void",
    )


def test_function_return_class_validation_accepts_unobserved_value_surface() -> None:
    codegen = _Codegen()
    _record_return_evidence(codegen, CallerReturnUseVerdict8616.UNUSED)
    _set_return_surface(codegen, SimTypeShort(False))

    report = validate_function_return_class_8616(codegen.project, codegen)

    assert report.passed
    assert report.raw_fact_count == 1
    assert report.normalized_fact_count == 1
    assert report.classified_fact_count == 0
    assert report.materialized_count == 0


def test_function_return_class_validation_refuses_missing_final_type_surface() -> None:
    codegen = _Codegen()
    _record_return_evidence(codegen, CallerReturnUseVerdict8616.USED)
    _set_return_surface(codegen, None)

    report = validate_function_return_class_8616(codegen.project, codegen)

    assert report.passed is False
    assert report.issue_tokens() == (
        "function-return-class:type-surface-unavailable:function=0x1000:"
        "expected=value:actual=unknown",
    )


def test_function_return_class_validation_does_not_guess_unknown_evidence() -> None:
    codegen = _Codegen()
    _record_return_evidence(
        codegen,
        CallerReturnUseVerdict8616.UNKNOWN,
        classified=0,
        failures=1,
    )
    _set_return_surface(codegen, SimTypeShort(False))

    report = validate_function_return_class_8616(codegen.project, codegen)

    assert report.passed
    assert report.raw_fact_count == 1
    assert report.normalized_fact_count == 1
    assert report.classified_fact_count == 0
    assert report.materialized_count == 0
    assert report.failure_count == 0


def test_required_callsite_validation_matches_exact_node_identity() -> None:
    codegen = _Codegen()
    call = CFunctionCall("apply_twice", None, [], tags={"ins_addr": 0x1010}, codegen=codegen)
    root = CStatements([call], codegen=codegen)
    codegen._inertia_callsite_summaries = {id(call): _summary()}

    report = validate_required_callsites_8616(codegen, root)

    assert report.passed
    assert report.raw_fact_count == 1
    assert report.materialized_count == 1
    assert report.failure_count == 0


def test_required_callsite_validation_matches_non_mapping_exact_tags() -> None:
    """Exact Rust-backed tags distinguish reversed same-target calls."""

    class _TagMap:
        def __init__(self, values: dict[str, int]) -> None:
            self._values = dict(values)

        def items(self):
            return self._values.items()

    codegen = _Codegen()
    first = CFunctionCall("apply_twice", None, [], tags={}, codegen=codegen)
    second = CFunctionCall("apply_twice", None, [], tags={}, codegen=codegen)
    first.tags = _TagMap({"ins_addr": 0x1010})
    second.tags = _TagMap({"ins_addr": 0x1020})
    first_summary = _summary(arg_count=0)
    second_summary = CallsiteSummary8616(
        callsite_addr=0x1020,
        target_addr=first_summary.target_addr,
        return_addr=0x1023,
        kind=first_summary.kind,
        arg_count=0,
        arg_widths=(),
        stack_cleanup=first_summary.stack_cleanup,
        return_register=first_summary.return_register,
        return_used=first_summary.return_used,
    )
    codegen._inertia_callsite_summaries = {1: first_summary, 2: second_summary}
    root = CStatements([second, first], codegen=codegen)

    report = validate_required_callsites_8616(codegen, root)

    assert report.passed
    assert report.materialized_count == 2


def test_required_callsite_validation_consumes_shared_query_index(monkeypatch) -> None:
    codegen = _Codegen()
    call = CFunctionCall("apply_twice", None, [], tags={"ins_addr": 0x1010}, codegen=codegen)
    root = CStatements([call], codegen=codegen)
    codegen._inertia_callsite_summaries = {id(call): _summary()}
    query_index = StructuredAstQueryIndex8616.build(root)

    def fail_rewalk(_root: object):
        raise AssertionError("shared validation query index must prevent a root rewalk")
        yield

    monkeypatch.setattr(validation_calls_module, "_iter_c_nodes_deep_8616", fail_rewalk)

    report = validate_required_callsites_8616(codegen, root, query_index=query_index)

    assert report.passed


def test_call_validators_consume_one_shared_match_surface(monkeypatch) -> None:
    codegen = _Codegen()
    call = CFunctionCall("apply_twice", None, [], tags={"ins_addr": 0x1010}, codegen=codegen)
    root = CStatements([call], codegen=codegen)
    codegen._inertia_callsite_summaries = {
        id(call): _summary(arg_count=0, logical_arg_widths=(), logical_arg_classes=())
    }
    query_index = StructuredAstQueryIndex8616.build(root)
    surface = validation_calls_module.build_required_call_validation_surface_8616(
        codegen,
        root,
        query_index=query_index,
    )

    def fail_rebuild(*_args: object, **_kwargs: object):
        raise AssertionError("shared required-call surface must prevent rematching")

    monkeypatch.setattr(
        validation_calls_module,
        "build_required_call_validation_surface_8616",
        fail_rebuild,
    )

    assert validate_required_callsites_8616(codegen, root, surface=surface).passed
    assert validate_call_interfaces_8616(codegen, root, surface=surface).passed
    assert validate_call_argument_classes_8616(codegen, root, surface=surface).passed


def test_required_callsite_validation_matches_rebased_slice_target_identity() -> None:
    codegen = _Codegen()
    original_project = SimpleNamespace(
        loader=SimpleNamespace(main_object=SimpleNamespace(linked_base=0x10000, max_addr=0x2000))
    )
    codegen.project._inertia_original_project = original_project
    codegen.project._inertia_original_linear_delta = 0xF1A7
    call = CFunctionCall(
        "cmp_i16",
        SimpleNamespace(addr=0x0E69),
        [],
        tags={},
        codegen=codegen,
    )
    root = CStatements([call], codegen=codegen)
    codegen._inertia_callsite_summaries = {1: _summary(target_addr=0x10010)}

    report = validate_required_callsites_8616(codegen, root)

    assert report.passed
    assert report.materialized_count == 1


def test_required_callsite_validation_uses_metadata_name_without_ast_target() -> None:
    codegen = _Codegen()
    codegen.project._inertia_lst_metadata = SimpleNamespace(code_labels={0x2000: "apply_twice"})
    args = (
        CConstant(1, SimTypeShort(False), codegen=codegen),
        CConstant(2, SimTypeShort(False), codegen=codegen),
    )
    call = CFunctionCall("apply_twice", None, args, tags={}, codegen=codegen)
    root = CStatements([call], codegen=codegen)
    codegen._inertia_callsite_summaries = {1: _summary()}

    report = validate_required_callsites_8616(codegen, root)

    assert report.passed
    assert report.materialized_count == 1


def test_required_callsite_validation_refuses_unrelated_rebased_slice_target() -> None:
    codegen = _Codegen()
    original_project = SimpleNamespace(
        loader=SimpleNamespace(main_object=SimpleNamespace(linked_base=0x10000, max_addr=0x2000))
    )
    codegen.project._inertia_original_project = original_project
    codegen.project._inertia_original_linear_delta = 0xF1A7
    call = CFunctionCall(
        "other",
        SimpleNamespace(addr=0x0E70),
        [],
        tags={},
        codegen=codegen,
    )
    root = CStatements([call], codegen=codegen)
    codegen._inertia_callsite_summaries = {1: _summary(target_addr=0x10010)}

    report = validate_required_callsites_8616(codegen, root)

    assert not report.passed
    assert report.materialized_count == 0
    assert report.failure_count == 1


def test_required_callsite_validation_collapses_identical_clone_metadata() -> None:
    codegen = _Codegen()
    call = CFunctionCall("apply_twice", None, [], tags={"ins_addr": 0x1010}, codegen=codegen)
    root = CStatements([call], codegen=codegen)
    summary = _summary()
    codegen._inertia_callsite_summaries = {1: summary, id(call): summary}

    report = validate_required_callsites_8616(codegen, root)

    assert report.passed
    assert report.raw_fact_count == 2
    assert report.normalized_fact_count == 1
    assert report.classified_fact_count == 1
    assert report.materialized_count == 1
    assert report.failure_count == 0


def test_required_callsite_validation_keeps_conflicting_clone_metadata() -> None:
    codegen = _Codegen()
    call = CFunctionCall("apply_twice", None, [], tags={"ins_addr": 0x1010}, codegen=codegen)
    root = CStatements([call], codegen=codegen)
    codegen._inertia_callsite_summaries = {
        id(call): _summary(arg_count=2),
        1: _summary(arg_count=1),
    }

    report = validate_required_callsites_8616(codegen, root)

    assert not report.passed
    assert report.raw_fact_count == 2
    assert report.normalized_fact_count == 2
    assert report.classified_fact_count == 2
    assert report.materialized_count == 1
    assert report.failure_count == 1


def test_required_callsite_validation_reports_call_loss() -> None:
    codegen = _Codegen()
    codegen._inertia_callsite_summaries = {1: _summary()}

    report = validate_required_callsites_8616(codegen, CStatements([], codegen=codegen))

    assert not report.passed
    assert report.classified_fact_count == 1
    assert report.materialized_count == 0
    assert report.failure_count == 1
    assert report.missing_calls == (
        "missing-required-call:callsite=0x1010:target=0x2000:argc=2",
    )


def test_required_callsite_validation_uses_unrepresented_owned_inventory() -> None:
    """A deleted call remains required through the authoritative binary inventory."""
    codegen = _Codegen()
    summary = _summary()
    codegen._inertia_callsite_summaries = {}
    codegen._inertia_callsite_summary_inventory_8616 = {
        summary.callsite_addr: summary,
    }

    report = validate_required_callsites_8616(codegen, CStatements([], codegen=codegen))

    assert not report.passed
    assert report.raw_fact_count == 1
    assert report.normalized_fact_count == 1
    assert report.classified_fact_count == 1
    assert report.materialized_count == 0
    assert report.failure_count == 1
    assert report.missing_calls == (
        "missing-required-call:callsite=0x1010:target=0x2000:argc=2",
    )


def test_required_callsite_validation_excludes_stack_probe_helpers() -> None:
    codegen = _Codegen()
    codegen._inertia_callsite_summaries = {1: _summary(stack_probe_helper=True)}

    report = validate_required_callsites_8616(codegen, CStatements([], codegen=codegen))

    assert report.passed
    assert report.raw_fact_count == 1
    assert report.normalized_fact_count == 0


def test_call_interface_validation_accepts_binary_proven_arity() -> None:
    codegen = _Codegen()
    args = [
        CConstant(1, SimTypeShort(False), codegen=codegen),
        CConstant(2, SimTypeShort(False), codegen=codegen),
    ]
    call = CFunctionCall("apply_twice", None, args, tags={"ins_addr": 0x1010}, codegen=codegen)
    codegen._inertia_callsite_summaries = {id(call): _summary()}

    report = validate_call_interfaces_8616(codegen, CStatements([call], codegen=codegen))

    assert report.passed
    assert report.raw_fact_count == 1
    assert report.normalized_fact_count == 1
    assert report.classified_fact_count == 1
    assert report.materialized_count == 1
    assert report.failure_count == 0


def test_call_interface_validation_refuses_guessed_empty_prototype_arity() -> None:
    codegen = _Codegen()
    short_type = SimTypeShort(False).with_arch(codegen.project.arch)
    callee = SimpleNamespace(
        addr=0x2000,
        name="external_stub",
        prototype=SimTypeFunction([], short_type).with_arch(codegen.project.arch),
        is_prototype_guessed=True,
    )
    call = CFunctionCall(
        "external_stub",
        callee,
        [CConstant(1, short_type, codegen=codegen)],
        tags={"ins_addr": 0x1010},
        codegen=codegen,
    )
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x1010,
            target_addr=0x2000,
            return_addr=0x1013,
            kind="direct_far",
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=2,
            return_register="ax",
            return_used=None,
        )
    }

    report = validate_call_interfaces_8616(codegen, CStatements([call], codegen=codegen))

    assert report.passed
    assert report.classified_fact_count == 0


def test_call_interface_validation_uses_project_target_name_for_helper_arity() -> None:
    codegen = _Codegen()
    codegen.project.kb = SimpleNamespace(labels={0x2000: "__aNldiv"})
    long_type = SimTypeLong(False).with_arch(codegen.project.arch)
    call = CFunctionCall(
        "sub_2000",
        None,
        [CConstant(1, long_type, codegen=codegen), CConstant(2, long_type, codegen=codegen)],
        tags={"ins_addr": 0x1010},
        codegen=codegen,
    )
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x1010,
            target_addr=0x2000,
            return_addr=0x1013,
            kind="direct_near",
            arg_count=4,
            arg_widths=(2, 2, 2, 2),
            stack_cleanup=8,
            return_register="ax",
            return_used=True,
            logical_arg_widths=(),
        )
    }

    report = validate_call_interfaces_8616(codegen, CStatements([call], codegen=codegen))

    assert report.passed
    assert report.classified_fact_count == 1
    assert report.materialized_count == 1


def test_call_interface_validation_prefers_rendered_helper_name_to_stale_target() -> None:
    codegen = _Codegen()
    short_type = SimTypeShort(False).with_arch(codegen.project.arch)
    long_type = SimTypeLong(False).with_arch(codegen.project.arch)
    callee = SimpleNamespace(
        addr=0x2000,
        name="aNldiv",
        prototype=SimTypeFunction([short_type] * 4, long_type).with_arch(codegen.project.arch),
    )
    call = CFunctionCall(
        "sub_2000",
        callee,
        [CConstant(1, long_type, codegen=codegen), CConstant(2, long_type, codegen=codegen)],
        tags={"ins_addr": 0x1010},
        codegen=codegen,
    )
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x1010,
            target_addr=0x2000,
            return_addr=0x1013,
            kind="direct_near",
            arg_count=4,
            arg_widths=(2, 2, 2, 2),
            stack_cleanup=8,
            return_register="ax",
            return_used=True,
            logical_arg_widths=(2, 2, 2, 2),
        )
    }

    report = validate_call_interfaces_8616(codegen, CStatements([call], codegen=codegen))

    assert report.passed
    assert report.classified_fact_count == 1
    assert report.materialized_count == 1


def test_call_interface_validation_accepts_accounted_dword_prototype_grouping() -> None:
    codegen = _Codegen()
    long_type = SimTypeLong(False).with_arch(codegen.project.arch)
    callee = SimpleNamespace(
        addr=0x2000,
        prototype=SimTypeFunction([long_type, long_type], long_type).with_arch(codegen.project.arch),
        is_prototype_guessed=False,
    )
    args = [
        CConstant(1, long_type, codegen=codegen),
        CConstant(2, long_type, codegen=codegen),
    ]
    call = CFunctionCall("wide_divide", callee, args, tags={"ins_addr": 0x1010}, codegen=codegen)
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x1010,
            target_addr=0x2000,
            return_addr=0x1013,
            kind="direct_near",
            arg_count=4,
            arg_widths=(2, 2, 2, 2),
            stack_cleanup=8,
            return_register="ax",
            return_used=True,
            logical_arg_widths=(2, 2, 2, 2),
        )
    }

    report = validate_call_interfaces_8616(codegen, CStatements([call], codegen=codegen))

    assert report.passed
    assert report.classified_fact_count == 1
    assert report.materialized_count == 1
    assert report.failure_count == 0


def test_call_interface_validation_accepts_proven_nested_dword_argument() -> None:
    codegen = _Codegen()
    short_type = SimTypeShort(False).with_arch(codegen.project.arch)
    long_type = SimTypeLong(False).with_arch(codegen.project.arch)
    call = CFunctionCall(
        "format_value",
        None,
        [
            CConstant(1, short_type, codegen=codegen),
            CConstant(2, short_type, codegen=codegen),
            CConstant(3, long_type, codegen=codegen),
        ],
        tags={"ins_addr": 0x1010},
        codegen=codegen,
    )
    codegen._inertia_callsite_summaries = {
        id(call): _summary(logical_arg_widths=(2, 2, 4), logical_arg_classes=())
    }

    report = validate_call_interfaces_8616(codegen, CStatements([call], codegen=codegen))

    assert report.passed
    assert report.classified_fact_count == 1
    assert report.materialized_count == 1
    assert report.failure_count == 0


def test_call_interface_validation_accepts_accounted_variadic_nested_dword() -> None:
    codegen = _Codegen()
    short_type = SimTypeShort(False).with_arch(codegen.project.arch)
    long_type = SimTypeLong(False).with_arch(codegen.project.arch)
    inner_callee = SimpleNamespace(
        addr=0x3000,
        name="aNldiv",
        prototype_libname=None,
        prototype=SimTypeFunction([long_type, long_type], long_type).with_arch(
            codegen.project.arch
        ),
    )
    nested = CFunctionCall(
        "aNldiv",
        inner_callee,
        [CConstant(30, long_type, codegen=codegen), CConstant(1, long_type, codegen=codegen)],
        tags={"ins_addr": 0x1008},
        codegen=codegen,
    )
    outer_callee = SimpleNamespace(
        addr=0x2000,
        name="sprintf",
        prototype=SimTypeFunction(
            [short_type, short_type],
            short_type,
            variadic=True,
        ).with_arch(codegen.project.arch),
        is_prototype_guessed=False,
    )
    call = CFunctionCall(
        "sprintf",
        outer_callee,
        [
            CConstant(1, short_type, codegen=codegen),
            CConstant(2, short_type, codegen=codegen),
            nested,
        ],
        tags={"ins_addr": 0x1010},
        codegen=codegen,
    )
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x1010,
            target_addr=0x2000,
            return_addr=0x1013,
            kind="direct_near",
            arg_count=4,
            arg_widths=(2, 2, 2, 2),
            stack_cleanup=8,
            return_register="ax",
            return_used=True,
            logical_arg_widths=(2, 2, 2, 2),
        )
    }

    report = validate_call_interfaces_8616(codegen, CStatements([call], codegen=codegen))

    assert report.passed
    assert report.classified_fact_count == 1
    assert report.materialized_count == 1


def test_call_interface_validation_accepts_exact_return_pair_without_prototype() -> None:
    codegen = _Codegen()
    short_type = SimTypeShort(False).with_arch(codegen.project.arch)
    nested = CFunctionCall(
        "wide_result",
        None,
        [],
        tags={"ins_addr": 0x1008},
        codegen=codegen,
    )
    call = CFunctionCall(
        "consume",
        None,
        [
            CConstant(1, short_type, codegen=codegen),
            CConstant(2, short_type, codegen=codegen),
            nested,
        ],
        tags={"ins_addr": 0x1010},
        codegen=codegen,
    )
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x1010,
            target_addr=0x2000,
            return_addr=0x1013,
            kind="direct_near",
            arg_count=4,
            arg_widths=(2, 2, 2, 2),
            stack_cleanup=8,
            return_register="ax",
            return_used=True,
            push_arg_sources=(
                ("ret_reg", 0x1008, "dx"),
                ("ret_reg", 0x1008, "ax"),
                ("imm", 2),
                ("imm", 1),
            ),
            logical_arg_widths=(2, 2, 2, 2),
        )
    }

    report = validate_call_interfaces_8616(codegen, CStatements([call], codegen=codegen))

    assert report.passed
    assert report.classified_fact_count == 1
    assert report.materialized_count == 1


def test_call_interface_validation_prefers_proven_logical_shape_to_stale_prototype() -> None:
    codegen = _Codegen()
    short_type = SimTypeShort(False).with_arch(codegen.project.arch)
    long_type = SimTypeLong(False).with_arch(codegen.project.arch)
    callee = SimpleNamespace(
        addr=0x2000,
        prototype=SimTypeFunction([short_type] * 5, short_type).with_arch(codegen.project.arch),
    )
    call = CFunctionCall(
        "load",
        callee,
        [
            CConstant(1, short_type, codegen=codegen),
            CConstant(0, short_type, codegen=codegen),
            CConstant(1, short_type, codegen=codegen),
            CConstant(2, long_type, codegen=codegen),
        ],
        tags={"ins_addr": 0x1010},
        codegen=codegen,
    )
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x1010,
            target_addr=0x2000,
            return_addr=0x1013,
            kind="direct_near",
            arg_count=5,
            arg_widths=(2, 2, 2, 2, 2),
            stack_cleanup=10,
            return_register="ax",
            return_used=True,
            logical_arg_widths=(2, 2, 2, 4),
        )
    }

    report = validate_call_interfaces_8616(codegen, CStatements([call], codegen=codegen))

    assert report.passed
    assert report.classified_fact_count == 1
    assert report.materialized_count == 1
    assert report.failure_count == 0


def test_call_interface_validation_refuses_lost_arguments() -> None:
    codegen = _Codegen()
    call = CFunctionCall("apply_twice", None, [], tags={"ins_addr": 0x1010}, codegen=codegen)
    codegen._inertia_callsite_summaries = {id(call): _summary()}

    report = validate_call_interfaces_8616(codegen, CStatements([call], codegen=codegen))

    assert not report.passed
    assert report.raw_fact_count == 1
    assert report.normalized_fact_count == 1
    assert report.classified_fact_count == 1
    assert report.materialized_count == 0
    assert report.failure_count == 1
    assert report.issue_tokens() == (
        "call-interface:argument-count-mismatch:callsite=0x1010:"
        "target=0x2000:expected-argc=2:actual-argc=0:physical-widths=2,2:"
        "logical-widths=2,2:actual-widths=none:prototype-widths=unknown:"
        "prototype-variadic=unknown",
    )


def test_call_interface_validation_uses_proven_logical_far_pointer_arity() -> None:
    codegen = _Codegen()
    argument = CConstant(1, SimTypeShort(False), codegen=codegen)
    call = CFunctionCall("read_far", None, [argument], tags={"ins_addr": 0x1010}, codegen=codegen)
    codegen._inertia_callsite_summaries = {
        id(call): _summary(
            logical_arg_widths=(4,),
            logical_arg_classes=(CallsiteArgumentClass8616.POINTER,),
        )
    }

    report = validate_call_interfaces_8616(codegen, CStatements([call], codegen=codegen))

    assert report.passed
    assert report.classified_fact_count == 1
    assert report.materialized_count == 1


def test_call_interface_validation_does_not_guess_unknown_arity() -> None:
    codegen = _Codegen()
    call = CFunctionCall("unknown", None, [], tags={"ins_addr": 0x1010}, codegen=codegen)
    codegen._inertia_callsite_summaries = {
        id(call): _summary(
            arg_count=None,
            logical_arg_widths=(),
            logical_arg_classes=(),
        )
    }

    report = validate_call_interfaces_8616(codegen, CStatements([call], codegen=codegen))

    assert report.passed
    assert report.normalized_fact_count == 1
    assert report.classified_fact_count == 0
    assert report.materialized_count == 0


def test_call_argument_class_validation_accepts_pointer_and_value() -> None:
    codegen = _Codegen()
    short_type = SimTypeShort(False)
    pointer_type = SimTypePointer(short_type).with_arch(codegen.project.arch)
    pointer = CVariable(
        SimStackVariable(6, 2, base="bp", name="pointer"),
        variable_type=pointer_type,
        codegen=codegen,
    )
    value = CConstant(7, short_type, codegen=codegen)
    call = CFunctionCall(
        "consume",
        None,
        [pointer, value],
        tags={"ins_addr": 0x1010},
        codegen=codegen,
    )
    codegen._inertia_callsite_summaries = {
        id(call): _summary(
            logical_arg_classes=(
                CallsiteArgumentClass8616.POINTER,
                CallsiteArgumentClass8616.VALUE,
            )
        )
    }

    report = validate_call_argument_classes_8616(
        codegen,
        CStatements([call], codegen=codegen),
    )

    assert report.passed
    assert report.raw_fact_count == 2
    assert report.normalized_fact_count == 2
    assert report.classified_fact_count == 2
    assert report.materialized_count == 2
    assert report.failure_count == 0


def test_call_argument_class_validation_refuses_value_for_pointer() -> None:
    codegen = _Codegen()
    value = CConstant(7, SimTypeShort(False), codegen=codegen)
    call = CFunctionCall(
        "consume",
        None,
        [value],
        tags={"ins_addr": 0x1010},
        codegen=codegen,
    )
    codegen._inertia_callsite_summaries = {
        id(call): _summary(
            arg_count=1,
            logical_arg_widths=(2,),
            logical_arg_classes=(CallsiteArgumentClass8616.POINTER,),
        )
    }

    report = validate_call_argument_classes_8616(
        codegen,
        CStatements([call], codegen=codegen),
    )

    assert not report.passed
    assert report.classified_fact_count == 1
    assert report.materialized_count == 0
    assert report.failure_count == 1
    assert report.issue_tokens() == (
        "call-argument-class:class-mismatch:callsite=0x1010:"
        "target=0x2000:arg=0:expected=pointer:actual=value",
    )


def test_call_argument_class_validation_does_not_guess_from_widths() -> None:
    codegen = _Codegen()
    short_type = SimTypeShort(False)
    pointer_type = SimTypePointer(short_type).with_arch(codegen.project.arch)
    pointer = CVariable(
        SimStackVariable(6, 2, base="bp", name="pointer"),
        variable_type=pointer_type,
        codegen=codegen,
    )
    call = CFunctionCall(
        "consume",
        None,
        [pointer],
        tags={"ins_addr": 0x1010},
        codegen=codegen,
    )
    codegen._inertia_callsite_summaries = {
        id(call): _summary(
            arg_count=1,
            logical_arg_widths=(2,),
            logical_arg_classes=(),
        )
    }

    report = validate_call_argument_classes_8616(
        codegen,
        CStatements([call], codegen=codegen),
    )

    assert report.passed
    assert report.raw_fact_count == 0
    assert report.normalized_fact_count == 0
    assert report.classified_fact_count == 0
    assert report.materialized_count == 0
    assert report.failure_count == 0


def test_final_semantic_refresh_promotes_call_argument_class_failure() -> None:
    codegen = _Codegen()
    value = CConstant(7, SimTypeShort(False), codegen=codegen)
    call = CFunctionCall(
        "consume",
        None,
        [value],
        tags={"ins_addr": 0x1010},
        codegen=codegen,
    )
    root = CStatements([call], codegen=codegen)
    codegen.cfunc = SimpleNamespace(arg_list=[], statements=root)
    codegen._inertia_callsite_summaries = {
        id(call): _summary(
            arg_count=1,
            logical_arg_widths=(2,),
            logical_arg_classes=(CallsiteArgumentClass8616.POINTER,),
        )
    }
    codegen._inertia_tail_validation_snapshot = {
        "structuring": {"status": "stable", "changed": False},
        "postprocess": {"status": "stable", "changed": False},
    }

    report = refresh_x86_16_final_semantic_validation_8616(
        codegen.project,
        codegen,
    )

    issue = (
        "call-argument-class:class-mismatch:callsite=0x1010:"
        "target=0x2000:arg=0:expected=pointer:actual=value"
    )
    assert report.passed is False
    assert report.call_argument_classes.issue_tokens() == (issue,)
    postprocess = codegen._inertia_tail_validation_snapshot["postprocess"]
    assert postprocess["semantic_failures"] == {
        "call_argument_classes": (issue,)
    }
    assert postprocess["final_semantic_guard"]["call_argument_classes"] == {
        "raw_fact_count": 1,
        "normalized_fact_count": 1,
        "classified_fact_count": 1,
        "materialized_count": 0,
        "failure_count": 1,
    }


def test_final_semantic_refresh_promotes_call_interface_failure() -> None:
    codegen = _Codegen()
    call = CFunctionCall("apply_twice", None, [], tags={"ins_addr": 0x1010}, codegen=codegen)
    root = CStatements([call], codegen=codegen)
    codegen.cfunc = SimpleNamespace(arg_list=[], statements=root)
    codegen._inertia_callsite_summaries = {id(call): _summary()}
    codegen._inertia_tail_validation_snapshot = {
        "structuring": {"status": "stable", "changed": False},
        "postprocess": {"status": "stable", "changed": False},
    }

    report = refresh_x86_16_final_semantic_validation_8616(codegen.project, codegen)

    issue = (
        "call-interface:argument-count-mismatch:callsite=0x1010:"
        "target=0x2000:expected-argc=2:actual-argc=0:physical-widths=2,2:"
        "logical-widths=2,2:actual-widths=none:prototype-widths=unknown:"
        "prototype-variadic=unknown"
    )
    assert report.passed is False
    assert report.call_interfaces.issue_tokens() == (issue,)
    assert x86_16_tail_validation_snapshot_passed(
        codegen._inertia_tail_validation_snapshot
    ) is False
    postprocess = codegen._inertia_tail_validation_snapshot["postprocess"]
    assert postprocess["semantic_failures"] == {"call_interfaces": (issue,)}
    assert issue in postprocess["summary_text"]
    assert postprocess["final_semantic_guard"]["call_interfaces"] == {
        "raw_fact_count": 1,
        "normalized_fact_count": 1,
        "classified_fact_count": 1,
        "materialized_count": 0,
        "failure_count": 1,
    }


def test_final_semantic_refresh_promotes_function_return_class_failure() -> None:
    codegen = _Codegen()
    root = CStatements([], codegen=codegen)
    _record_return_evidence(codegen, CallerReturnUseVerdict8616.USED)
    _set_return_surface(
        codegen,
        SimTypeBottom(label="void").with_arch(codegen.project.arch),
        statements=root,
    )
    codegen._inertia_tail_validation_snapshot = {
        "structuring": {"status": "stable", "changed": False},
        "postprocess": {"status": "stable", "changed": False},
    }

    report = refresh_x86_16_final_semantic_validation_8616(codegen.project, codegen)

    issue = (
        "function-return-class:class-mismatch:function=0x1000:"
        "expected=value:actual=void"
    )
    assert report.passed is False
    assert report.function_return_class.issue_tokens() == (issue,)
    postprocess = codegen._inertia_tail_validation_snapshot["postprocess"]
    assert postprocess["semantic_failures"] == {
        "function_return_class": (issue,)
    }
    assert postprocess["final_semantic_guard"]["function_return_class"] == {
        "raw_fact_count": 1,
        "normalized_fact_count": 1,
        "classified_fact_count": 1,
        "materialized_count": 0,
        "failure_count": 1,
    }


def test_final_semantic_refresh_promotes_function_parameter_failure() -> None:
    codegen = _Codegen()
    root = CStatements([], codegen=codegen)
    codegen._inertia_function_parameter_width_facts_8616 = (
        FunctionParameterWidthFact8616(stack_offset=4, width_bytes=2),
    )
    _set_parameter_surface(
        codegen,
        (SimTypeLong(False),),
        offsets=(4,),
        storage_widths=(4,),
        statements=root,
    )
    codegen._inertia_tail_validation_snapshot = {
        "structuring": {"status": "stable", "changed": False},
        "postprocess": {"status": "stable", "changed": False},
    }

    report = refresh_x86_16_final_semantic_validation_8616(codegen.project, codegen)

    issue = (
        "function-parameter:width-mismatch:function=0x1000:bp=+0x4:"
        "expected-width=2:actual-width=4"
    )
    assert report.passed is False
    assert report.function_parameters.issue_tokens() == (issue,)
    postprocess = codegen._inertia_tail_validation_snapshot["postprocess"]
    assert postprocess["semantic_failures"] == {"function_parameters": (issue,)}
    assert postprocess["final_semantic_guard"]["function_parameters"] == {
        "raw_fact_count": 1,
        "normalized_fact_count": 1,
        "classified_fact_count": 1,
        "materialized_count": 0,
        "failure_count": 1,
    }


def test_tail_validation_refuses_required_call_loss_even_when_baseline_also_lost() -> None:
    issue = "missing-required-call:callsite=0x1010:target=0x2000:argc=2"

    result = build_x86_16_tail_validation_cached_result(
        owner={},
        stage="postprocess",
        mode="live_out",
        before_fingerprint="same-lost-call",
        after_fingerprint="same-lost-call",
        before_summary=_empty_summary(missing_required_calls=(issue,)),
        after_summary=_empty_summary(missing_required_calls=(issue,)),
    )

    assert result["changed"] is True
    assert result["status"] == "failed"
    assert result["semantic_failures"] == {"required_calls": (issue,)}
