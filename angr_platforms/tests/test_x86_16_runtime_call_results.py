"""Runtime register result reads must not execute their producer a second time."""

from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CConstant,
    CExpressionStatement,
    CFunctionCall,
    CIfElse,
    CStatements,
    CVariable,
)
from angr.sim_type import SimTypeChar, SimTypeFunction, SimTypeShort
from angr.sim_variable import SimStackVariable, SimTemporaryVariable
from angr_platforms.X86_16.c_ast_utils import _iter_c_nodes_deep_8616
from angr_platforms.X86_16.callsite_summary import CallsiteSummary8616
from angr_platforms.X86_16.decompiler_postprocess_calls import (
    _materialize_callsite_stack_arguments_8616,
)
from angr_platforms.X86_16.lowering.call_argument_semantic_gap import has_literal_push_stack_carrier_8616
from angr_platforms.X86_16.lowering.gp_register_state import (
    RuntimeGPExpressionView8616,
    runtime_gp_expression_view_8616,
    runtime_gp_state_assignment_8616,
)
from angr_platforms.X86_16.lowering.runtime_call_results import (
    RuntimeCallResultVerdict8616,
    materialize_runtime_call_result_read_8616,
)
from test_x86_16_decompiler_postprocess_calls import _empty_codegen, _project

_PRODUCER_CALLSITE = 0x1001
_PROVEN_LITERAL_ARGUMENT = 37


def _runtime_producer():
    project = _project()
    codegen = _empty_codegen(project)
    producer = CFunctionCall(
        "sub_2000",
        SimpleNamespace(addr=0x2000, name="sub_2000", block_addrs_set={0x2000}, prototype_libname=None,
                        prototype=SimTypeFunction([], SimTypeShort(False)).with_arch(project.arch)),
        [CConstant(0, SimTypeShort(False), codegen=codegen)],
        codegen=codegen,
        tags={"ins_addr": 0x1001},
    )
    assignment = runtime_gp_state_assignment_8616(
        "ax", producer, codegen=codegen, function_addr=0x4010
    )
    assert assignment is not None
    return project, codegen, producer, assignment


@pytest.mark.parametrize("captured", [False, True])
def test_call_argument_reuses_masked_runtime_result_without_duplicate_execution(captured):
    project, codegen, producer, assignment = _runtime_producer()
    prefix = list(_captured_publication(codegen, producer)) if captured else [assignment]
    consumer = CFunctionCall(
        "sub_3000",
        SimpleNamespace(addr=0x3000, name="sub_3000", block_addrs_set={0x3000}),
        [], codegen=codegen, tags={"ins_addr": 0x1008},
    )
    codegen.cfunc.statements = CStatements(
        [*prefix, CExpressionStatement(consumer, codegen=codegen)],
        addr=0x4010, codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_return_exprs_8616 = {0x1001: producer}
    codegen._inertia_callsite_summaries = {
        id(producer): CallsiteSummary8616(
            callsite_addr=0x1001, target_addr=0x2000, return_addr=0x1004,
            kind="direct_near", arg_count=1, arg_widths=(2,), stack_cleanup=2,
            return_register="ax", return_used=True, return_shape="ax",
        ),
        id(consumer): CallsiteSummary8616(
            callsite_addr=0x1008, target_addr=0x3000, return_addr=0x100B,
            kind="direct_near", arg_count=1, arg_widths=(2,), stack_cleanup=2,
            return_register="ax", return_used=False,
            push_arg_sources=(("ret_reg", 0x1001, "ax"),),
        ),
    }

    assert _materialize_callsite_stack_arguments_8616(project, codegen)

    calls = [node for node in _iter_c_nodes_deep_8616(codegen.cfunc.statements)
             if isinstance(node, CFunctionCall)]
    assert sum(call.tags.get("ins_addr") == _PRODUCER_CALLSITE for call in calls) == 1
    assert len(consumer.args) == 1
    assert not any(isinstance(node, CFunctionCall)
                   for node in _iter_c_nodes_deep_8616(consumer.args[0]))
    assert codegen.cfunc.statements.statements[:len(prefix)] == prefix
    assert runtime_gp_expression_view_8616(consumer.args[0]) == RuntimeGPExpressionView8616("ax", "eax", 0, 2)


@pytest.mark.parametrize("masked", [False, True])
@pytest.mark.parametrize("has_source", [False, True])
def test_proven_arguments_reach_masked_calls_without_replacing_statements(masked, has_source):
    project, codegen, producer, assignment = _runtime_producer()
    statement = assignment if masked else CExpressionStatement(producer, codegen=codegen)
    original_rhs = assignment.rhs
    root = CStatements([statement], addr=0x4010, codegen=codegen)
    codegen.cfunc.statements = root
    codegen.cfunc.body = root
    codegen._inertia_callsite_summaries = {
        id(producer): CallsiteSummary8616(
            callsite_addr=0x1001, target_addr=0x2000, return_addr=0x1004,
            kind="direct_near", arg_count=1, arg_widths=(2,), stack_cleanup=2,
            return_register="ax", return_used=True, return_shape="ax",
            push_arg_sources=(("imm", 37),) if has_source else (),
        ),
    }

    for _ in range(2):
        _materialize_callsite_stack_arguments_8616(project, codegen)
        assert producer.args[0].value == (37 if has_source else 0)
        assert root.statements == [statement]
        assert assignment.rhs is original_rhs
        assert sum(node is producer for node in _iter_c_nodes_deep_8616(root)) == 1


@pytest.mark.parametrize("masked", [False, True])
@pytest.mark.parametrize("has_source", [False, True])
def test_literal_push_evidence_is_not_overruled_by_a_named_stack_carrier(masked, has_source):
    project, codegen, producer, assignment = _runtime_producer()
    producer.args = [CVariable(
        SimStackVariable(-28, 2, base="bp", name="local_1a", ident="is_carrier"),
        variable_type=SimTypeShort(False).with_arch(project.arch), codegen=codegen,
    )]
    original_argument = producer.args[0]
    statement = assignment if masked else CExpressionStatement(producer, codegen=codegen)
    root = CStatements([statement], addr=0x4010, codegen=codegen)
    codegen.cfunc.statements = root
    codegen.cfunc.body = root
    codegen._inertia_callsite_summaries = {
        id(producer): CallsiteSummary8616(
            callsite_addr=0x1001, target_addr=0x2000, return_addr=0x1004,
            kind="direct_near", arg_count=1, arg_widths=(2,), stack_cleanup=2,
            return_register="ax", return_used=True, return_shape="ax",
            push_arg_sources=(("imm", _PROVEN_LITERAL_ARGUMENT),) if has_source else (),
        ),
    }

    _materialize_callsite_stack_arguments_8616(project, codegen)

    if has_source:
        assert isinstance(producer.args[0], CConstant)
        assert producer.args[0].value == _PROVEN_LITERAL_ARGUMENT
    else:
        assert producer.args[0] is original_argument
    assert root.statements == [statement]


@pytest.mark.parametrize("source", [None, (), ("imm",), ("imm", True), ("imm", 37, 2), ("bp", -28, 2)])
def test_literal_source_classifier_refuses_other_or_malformed_sources(source):
    project, codegen, producer, _assignment = _runtime_producer()
    producer.args = [CVariable(
        SimStackVariable(-28, 2, base="bp", name="local_1a", ident="is_carrier"),
        variable_type=SimTypeShort(False).with_arch(project.arch), codegen=codegen,
    )]

    assert not has_literal_push_stack_carrier_8616(producer, (source,))
    assert not has_literal_push_stack_carrier_8616(producer, ())


def _captured_publication(codegen, producer):
    temporary = CVariable(
        SimTemporaryVariable(7, 2), variable_type=producer.type, codegen=codegen,
    )
    capture = CAssignment(temporary, producer, codegen=codegen)
    publication = runtime_gp_state_assignment_8616(
        "ax", temporary, codegen=codegen, function_addr=0x4010,
    )
    assert publication is not None
    return capture, publication


@pytest.mark.parametrize("barrier", ["none", "ax", "call", "branch", "stale"])
def test_runtime_result_read_across_transparent_sibling_sequences(barrier):
    _project_obj, codegen, producer, _assignment = _runtime_producer()
    capture, publication = _captured_publication(codegen, producer)
    store = CAssignment(CVariable(SimStackVariable(-2, 2, base="bp"),
                                 variable_type=producer.type, codegen=codegen),
                        CConstant(3, producer.type, codegen=codegen), codegen=codegen)
    prefix = [store]
    middle = []
    if barrier == "ax":
        middle = [runtime_gp_state_assignment_8616("ax", store.rhs, codegen=codegen, function_addr=0x4010)]
    elif barrier == "call":
        middle = [CExpressionStatement(CFunctionCall("other", None, [], codegen=codegen), codegen=codegen)]
    elif barrier == "branch":
        middle = [CIfElse([(store.rhs, CStatements([], codegen=codegen))], codegen=codegen)]
    root = CStatements([CStatements([capture, publication], codegen=codegen), *middle,
                        CStatements(prefix, codegen=codegen)], codegen=codegen)
    if barrier == "stale":
        prefix = [CAssignment(store.lhs, store.rhs, codegen=codegen)]
    result = materialize_runtime_call_result_read_8616(
        root, prefix, 0x1001, "ax", codegen=codegen, function_addr=0x4010,
    )
    expected = RuntimeCallResultVerdict8616.PROVEN if barrier == "none" else RuntimeCallResultVerdict8616.UNKNOWN_REFUSE
    assert result.verdict is expected
    assert capture.rhs is producer


@pytest.mark.parametrize("captured", [False, True])
@pytest.mark.parametrize("barrier", ["ax", "al", "call", "branch", "none", "bx"])
def test_runtime_result_read_requires_uninterrupted_producer(barrier, captured):
    _project_obj, codegen, producer, assignment = _runtime_producer()
    prefix = list(_captured_publication(codegen, producer)) if captured else [assignment]
    if barrier in {"ax", "al", "bx"}:
        prefix.append(runtime_gp_state_assignment_8616(
            barrier, CConstant(3, SimTypeShort(False), codegen=codegen),
            codegen=codegen, function_addr=0x4010,
        ))
    elif barrier == "call":
        prefix.append(CExpressionStatement(
            CFunctionCall("sub_4000", None, [], codegen=codegen), codegen=codegen,
        ))
    elif barrier == "branch":
        prefix.append(CIfElse([
            (CConstant(1, SimTypeShort(False), codegen=codegen), CStatements([], codegen=codegen))
        ], codegen=codegen))
    root = CStatements(prefix, codegen=codegen)

    result = materialize_runtime_call_result_read_8616(
        root, prefix, 0x1001, "ax", codegen=codegen, function_addr=0x4010,
    )

    proven = barrier in {"none", "bx"}
    assert result.verdict is (RuntimeCallResultVerdict8616.PROVEN if proven
                              else RuntimeCallResultVerdict8616.UNKNOWN_REFUSE)
    assert (result.classified_fact_count, result.materialized_count) == ((1, 1) if proven else (0, 0))
    assert result.failure_count == (0 if proven else 1)
    assert (result.refusal_reason is None) is proven
    assert sum(node is producer for node in _iter_c_nodes_deep_8616(root)) == 1


@pytest.mark.parametrize("transparent", [False, True])
def test_runtime_result_read_accepts_adjacent_temporary_publication(transparent):
    _project_obj, codegen, producer, _assignment = _runtime_producer()
    capture, publication = _captured_publication(codegen, producer)
    prefix = [capture, publication]
    if transparent:
        prefix = [CStatements(prefix, codegen=codegen)]
    root = CStatements(prefix, codegen=codegen)

    result = materialize_runtime_call_result_read_8616(
        root, prefix, 0x1001, "ax", codegen=codegen, function_addr=0x4010,
    )

    assert result.verdict is RuntimeCallResultVerdict8616.PROVEN
    assert runtime_gp_expression_view_8616(result.expression) == RuntimeGPExpressionView8616("ax", "eax", 0, 2)
    assert capture.rhs is producer
    assert publication.rhs.rhs.lhs is capture.lhs
    assert sum(node is producer for node in _iter_c_nodes_deep_8616(root)) == 1


@pytest.mark.parametrize("corruption", ["missing", "other-value", "clobber", "wrong-register", "bad-mask", "narrow", "narrow-type", "stack"])
def test_runtime_result_read_refuses_unproven_temporary_publication(corruption):
    _project_obj, codegen, producer, _assignment = _runtime_producer()
    capture, publication = _captured_publication(codegen, producer)
    prefix = [capture, publication]
    register = "ax"
    if corruption == "missing":
        prefix.pop()
    elif corruption == "other-value":
        publication.rhs.rhs.lhs = CConstant(7, producer.type, codegen=codegen)
    elif corruption == "clobber":
        prefix.insert(1, CAssignment(capture.lhs, CConstant(0, producer.type, codegen=codegen), codegen=codegen))
    elif corruption == "wrong-register":
        register = "dx"
    elif corruption == "bad-mask":
        publication.rhs.rhs.rhs.value = 0xff
    elif corruption == "narrow":
        capture.lhs.variable = SimTemporaryVariable(7, 1)
    elif corruption == "narrow-type":
        capture.lhs.variable_type = SimTypeChar().with_arch(_project_obj.arch)
    else:
        capture.lhs.variable = SimStackVariable(-2, 2, base="bp")
    root = CStatements(prefix, codegen=codegen)

    result = materialize_runtime_call_result_read_8616(
        root, prefix, 0x1001, register, codegen=codegen, function_addr=0x4010,
    )

    assert result.verdict is RuntimeCallResultVerdict8616.UNKNOWN_REFUSE
    expected_reason = {
        "missing": "missing_publication", "other-value": "publication_mismatch",
        "clobber": "publication_mismatch", "wrong-register": "publication_mismatch",
        "bad-mask": "publication_mismatch", "narrow": "capture_width",
        "narrow-type": "capture_type", "stack": "capture_storage",
    }[corruption]
    assert result.refusal_reason.value == expected_reason
    assert result.materialized_count == 0
    assert result.failure_count == 1


@pytest.mark.parametrize("scope", ["absent", "outside-prefix", "new-prefix", "duplicate", "wrong-register", "bad-mask"])
def test_runtime_result_read_refuses_ambiguous_or_unsupported_ownership(scope):
    _project_obj, codegen, producer, assignment = _runtime_producer()
    prefix = [assignment]
    root = CStatements([assignment], codegen=codegen)
    register = "ax"
    if scope == "absent":
        root.statements = []
        prefix = []
    elif scope == "outside-prefix":
        prefix = []
    elif scope == "new-prefix":
        root.statements = []
    elif scope == "duplicate":
        root.statements.append(CExpressionStatement(producer, codegen=codegen))
        prefix.append(CExpressionStatement(producer, codegen=codegen))
    elif scope == "wrong-register":
        register = "dx"
    else:
        assignment.rhs.rhs.rhs.value = 0xFF

    result = materialize_runtime_call_result_read_8616(
        root, prefix, 0x1001, register, codegen=codegen, function_addr=0x4010,
    )

    expected = (RuntimeCallResultVerdict8616.ABSENT if scope == "absent" else
                RuntimeCallResultVerdict8616.PROVEN if scope == "new-prefix" else
                RuntimeCallResultVerdict8616.UNKNOWN_REFUSE)
    assert result.verdict is expected


@pytest.mark.parametrize("debug", [False, True])
def test_runtime_result_refusal_diagnostic_is_opt_in(debug, monkeypatch, caplog):
    _project_obj, codegen, _producer, assignment = _runtime_producer()
    if debug:
        monkeypatch.setenv("INERTIA_DEBUG_CALL_MATERIALIZATION", "1")
    else:
        monkeypatch.delenv("INERTIA_DEBUG_CALL_MATERIALIZATION", raising=False)
    root = CStatements([assignment], codegen=codegen)

    result = materialize_runtime_call_result_read_8616(
        root, [], 0x1001, "ax", codegen=codegen, function_addr=0x4010,
    )

    assert result.refusal_reason.value == "ownership"
    records = [record for record in caplog.records if record.name.endswith(".runtime_call_results")]
    assert len(records) == int(debug)
    if debug:
        message = records[0].getMessage()
        for evidence in ("function=0x4010", "callsite=0x1001", "register=ax", "reason=ownership",
                         "root_calls=1", "prefix_matches=0", "prefix_length=0"):
            assert evidence in message
