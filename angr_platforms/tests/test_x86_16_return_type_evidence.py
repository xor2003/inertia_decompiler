from __future__ import annotations

from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CConstant,
    CFunctionCall,
    CReturn,
    CStatements,
    CVariable,
)
from angr.sim_type import SimTypeBottom, SimTypeFunction, SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.callsite_summary import (
    CallerReturnUseEvidence8616,
    CallerReturnUseVerdict8616,
    record_caller_return_use_evidence_8616,
)
from angr_platforms.X86_16.lowering.return_type_evidence import (
    FunctionReturnClass8616,
    caller_return_use_evidence_proves_used_8616,
    function_result_is_proven_unobserved_8616,
    proven_function_return_class_8616,
)
from angr_platforms.X86_16.lowering.unobserved_returns import (
    UnobservedReturnLoweringStats8616,
    neutralize_unobserved_unresolved_returns_8616,
    return_value_needs_neutralization_8616,
)


@pytest.mark.parametrize("bare", [False, True])
def test_void_contract_never_synthesizes_a_scalar_return(bare):
    arch = Arch86_16()
    project = SimpleNamespace(arch=arch)
    return_type = SimTypeBottom(label="void").with_arch(arch)
    prototype = SimTypeFunction([], return_type).with_arch(arch)
    codegen = SimpleNamespace(project=project, next_idx=lambda _name: 1,
                              next_ident=lambda name: name, next_node_idx=lambda: 1)
    carrier = None if bare else CVariable(
        SimRegisterVariable(0, 2, ident="unassigned", region=0x1000),
        variable_type=SimTypeShort(False).with_arch(arch), codegen=codegen,
    )
    statement = CReturn(carrier, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x1000, arg_list=[], prototype=prototype, functy=prototype,
                                    statements=CStatements([statement], codegen=codegen))
    record_caller_return_use_evidence_8616(
        project, 0x1000, _evidence(CallerReturnUseVerdict8616.UNUSED, raw=1, classified=1, failures=0),
    )
    assert not return_value_needs_neutralization_8616(carrier, return_type)
    assert not neutralize_unobserved_unresolved_returns_8616(project, codegen)
    assert statement.retval is carrier
    assert codegen._inertia_unobserved_return_lowering_stats_8616.materialized_count == 0


def _evidence(
    verdict: CallerReturnUseVerdict8616,
    *,
    raw: int,
    classified: int,
    failures: int,
    target_addr: int = 0x1000,
) -> CallerReturnUseEvidence8616:
    return CallerReturnUseEvidence8616(
        target_addr=target_addr,
        verdict=verdict,
        raw_fact_count=raw,
        normalized_fact_count=raw,
        classified_fact_count=classified,
        materialized_count=classified,
        failure_count=failures,
        used_callsite_count=classified if verdict is CallerReturnUseVerdict8616.USED else 0,
        unused_callsite_count=classified if verdict is CallerReturnUseVerdict8616.UNUSED else 0,
        callsite_addrs=tuple(range(raw)),
    )


def _function(arch: Arch86_16) -> SimpleNamespace:
    prototype = SimTypeFunction([SimTypeShort(False)], SimTypeShort(False)).with_arch(arch)
    return SimpleNamespace(
        addr=0x1000,
        prototype=prototype,
        is_prototype_guessed=True,
        info={},
    )


def test_proves_used_return_from_at_least_one_classified_caller() -> None:
    evidence = _evidence(CallerReturnUseVerdict8616.USED, raw=3, classified=2, failures=1)

    assert caller_return_use_evidence_proves_used_8616(evidence) is True


def test_only_observed_callers_prove_a_return_class() -> None:
    project = SimpleNamespace()
    record_caller_return_use_evidence_8616(
        project,
        0x1000,
        _evidence(CallerReturnUseVerdict8616.USED, raw=3, classified=2, failures=1),
    )
    record_caller_return_use_evidence_8616(
        project,
        0x2000,
        CallerReturnUseEvidence8616(
            target_addr=0x2000,
            verdict=CallerReturnUseVerdict8616.UNUSED,
            raw_fact_count=2,
            normalized_fact_count=2,
            classified_fact_count=2,
            materialized_count=2,
            failure_count=0,
            used_callsite_count=0,
            unused_callsite_count=2,
            callsite_addrs=(0x1200, 0x1300),
        ),
    )

    assert proven_function_return_class_8616(project, 0x1000) is FunctionReturnClass8616.VALUE
    assert function_result_is_proven_unobserved_8616(project, 0x1000) is False
    assert proven_function_return_class_8616(project, 0x2000) is None
    assert function_result_is_proven_unobserved_8616(project, 0x2000) is True


def test_return_class_refuses_incomplete_or_absent_evidence() -> None:
    project = SimpleNamespace()
    record_caller_return_use_evidence_8616(
        project,
        0x1000,
        _evidence(CallerReturnUseVerdict8616.UNKNOWN, raw=3, classified=2, failures=1),
    )

    assert proven_function_return_class_8616(project, 0x1000) is None
    assert function_result_is_proven_unobserved_8616(project, 0x1000) is False
    assert proven_function_return_class_8616(project, 0x2000) is None


def test_refuses_used_verdict_without_a_materialized_used_callsite() -> None:
    evidence = CallerReturnUseEvidence8616(
        target_addr=0x1000,
        verdict=CallerReturnUseVerdict8616.USED,
        raw_fact_count=1,
        normalized_fact_count=1,
        classified_fact_count=1,
        materialized_count=0,
        failure_count=1,
        used_callsite_count=1,
        unused_callsite_count=0,
        callsite_addrs=(0x1200,),
    )

    assert caller_return_use_evidence_proves_used_8616(evidence) is False


def test_closed_unused_caller_evidence_does_not_prove_void() -> None:
    arch = Arch86_16()
    project = SimpleNamespace(arch=arch)
    function = _function(arch)
    evidence = _evidence(CallerReturnUseVerdict8616.UNUSED, raw=3, classified=3, failures=0)
    record_caller_return_use_evidence_8616(project, 0x1000, evidence)

    assert proven_function_return_class_8616(project, function.addr) is None
    assert function_result_is_proven_unobserved_8616(project, function.addr) is True
    assert isinstance(function.prototype.returnty, SimTypeShort)
    assert function.is_prototype_guessed is True


def test_closed_unused_evidence_lowers_unresolved_return_without_inferring_void() -> None:
    arch = Arch86_16()
    project = SimpleNamespace(arch=arch)
    return_type = SimTypeShort(False).with_arch(arch)
    prototype = SimTypeFunction([], return_type).with_arch(arch)
    codegen = SimpleNamespace(project=project, next_idx=lambda _name: 1, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    variable = SimRegisterVariable(0, 2, ident="ir_2", name="v5", region=0x1000)
    carrier = CVariable(
        variable,
        unified_variable=variable,
        variable_type=return_type,
        codegen=codegen,
    )
    return_node = CReturn(carrier, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        statements=CStatements([return_node], codegen=codegen),
        prototype=prototype,
        functy=prototype,
    )
    record_caller_return_use_evidence_8616(
        project,
        0x1000,
        _evidence(CallerReturnUseVerdict8616.UNUSED, raw=1, classified=1, failures=0),
    )

    assert neutralize_unobserved_unresolved_returns_8616(project, codegen) is True
    assert isinstance(return_node.retval, CConstant)
    assert return_node.retval.value == 0
    assert isinstance(codegen.cfunc.prototype.returnty, SimTypeShort)
    assert codegen._inertia_unobserved_return_lowering_stats_8616 == UnobservedReturnLoweringStats8616(
        raw_fact_count=1,
        normalized_fact_count=1,
        classified_fact_count=1,
        materialized_count=1,
        failure_count=0,
    )


def test_unobserved_return_lowering_keeps_assigned_scalar_carrier() -> None:
    arch = Arch86_16()
    project = SimpleNamespace(arch=arch)
    return_type = SimTypeShort(False).with_arch(arch)
    prototype = SimTypeFunction([], return_type).with_arch(arch)
    codegen = SimpleNamespace(project=project, next_idx=lambda _name: 1, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    variable = SimRegisterVariable(0, 2, ident="ir_3", name="v10", region=0x1000)
    assigned = CVariable(variable, unified_variable=variable, variable_type=return_type, codegen=codegen)
    returned = CVariable(variable, unified_variable=variable, variable_type=return_type, codegen=codegen)
    return_node = CReturn(returned, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        statements=CStatements(
            [CAssignment(assigned, CConstant(7, return_type, codegen=codegen), codegen=codegen), return_node],
            codegen=codegen,
        ),
        prototype=prototype,
        functy=prototype,
    )
    record_caller_return_use_evidence_8616(
        project,
        0x1000,
        _evidence(CallerReturnUseVerdict8616.UNUSED, raw=1, classified=1, failures=0),
    )

    assert neutralize_unobserved_unresolved_returns_8616(project, codegen) is False
    assert return_node.retval is returned


def test_unobserved_return_lowering_keeps_assigned_stack_local_carrier() -> None:
    arch = Arch86_16()
    project = SimpleNamespace(arch=arch)
    return_type = SimTypeShort(False).with_arch(arch)
    prototype = SimTypeFunction([], return_type).with_arch(arch)
    codegen = SimpleNamespace(project=project, next_idx=lambda _name: 1, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    variable = SimStackVariable(-2, 2, base="bp", name="mask", region=0x1000)
    assigned = CVariable(variable, variable_type=return_type, codegen=codegen)
    returned = CVariable(variable, variable_type=return_type, codegen=codegen)
    return_node = CReturn(returned, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        arg_list=[],
        statements=CStatements(
            [CAssignment(assigned, CConstant(7, return_type, codegen=codegen), codegen=codegen), return_node],
            codegen=codegen,
        ),
        prototype=prototype,
        functy=prototype,
    )
    record_caller_return_use_evidence_8616(
        project,
        0x1000,
        _evidence(CallerReturnUseVerdict8616.UNUSED, raw=1, classified=1, failures=0),
    )

    assert neutralize_unobserved_unresolved_returns_8616(project, codegen) is False
    assert return_node.retval is returned


def test_unobserved_return_lowering_keeps_function_argument() -> None:
    arch = Arch86_16()
    project = SimpleNamespace(arch=arch)
    return_type = SimTypeShort(False).with_arch(arch)
    prototype = SimTypeFunction([return_type], return_type).with_arch(arch)
    codegen = SimpleNamespace(project=project, next_idx=lambda _name: 1, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    variable = SimStackVariable(4, 2, base="bp", name="DLC", region=0x1000)
    argument = CVariable(variable, variable_type=return_type, codegen=codegen)
    returned = CVariable(variable, variable_type=return_type, codegen=codegen)
    return_node = CReturn(returned, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        arg_list=[argument],
        statements=CStatements([return_node], codegen=codegen),
        prototype=prototype,
        functy=prototype,
    )
    record_caller_return_use_evidence_8616(
        project,
        0x1000,
        _evidence(CallerReturnUseVerdict8616.UNUSED, raw=1, classified=1, failures=0),
    )

    assert neutralize_unobserved_unresolved_returns_8616(project, codegen) is False
    assert return_node.retval is returned


def test_unobserved_return_lowering_preserves_side_effecting_call_result() -> None:
    arch = Arch86_16()
    project = SimpleNamespace(arch=arch)
    return_type = SimTypeShort(False).with_arch(arch)
    prototype = SimTypeFunction([], return_type).with_arch(arch)
    codegen = SimpleNamespace(project=project, next_idx=lambda _name: 1, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    call = CFunctionCall("probe", None, [], codegen=codegen)
    return_node = CReturn(call, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        statements=CStatements([return_node], codegen=codegen),
        prototype=prototype,
        functy=prototype,
    )
    record_caller_return_use_evidence_8616(
        project,
        0x1000,
        _evidence(CallerReturnUseVerdict8616.UNUSED, raw=1, classified=1, failures=0),
    )

    assert neutralize_unobserved_unresolved_returns_8616(project, codegen) is False
    assert return_node.retval is call
    assert codegen._inertia_unobserved_return_lowering_stats_8616.classified_fact_count == 0


def test_rebased_closed_unused_evidence_does_not_prove_void() -> None:
    arch = Arch86_16()
    original_addr = 0x104DC
    project = SimpleNamespace(
        arch=arch,
        _inertia_original_linear_delta=original_addr - 0x1000,
    )
    function = _function(arch)
    evidence = _evidence(
        CallerReturnUseVerdict8616.UNUSED,
        raw=1,
        classified=1,
        failures=0,
        target_addr=original_addr,
    )
    record_caller_return_use_evidence_8616(project, original_addr, evidence)

    assert proven_function_return_class_8616(project, function.addr) is None
    assert function_result_is_proven_unobserved_8616(project, function.addr) is True
    assert isinstance(function.prototype.returnty, SimTypeShort)


def test_refuses_conflicting_return_evidence_across_exact_slice_aliases() -> None:
    arch = Arch86_16()
    original_addr = 0x104DC
    project = SimpleNamespace(
        arch=arch,
        _inertia_original_linear_delta=original_addr - 0x1000,
    )
    function = _function(arch)
    record_caller_return_use_evidence_8616(
        project,
        function.addr,
        _evidence(CallerReturnUseVerdict8616.UNUSED, raw=1, classified=1, failures=0),
    )
    record_caller_return_use_evidence_8616(
        project,
        original_addr,
        _evidence(
            CallerReturnUseVerdict8616.USED,
            raw=1,
            classified=1,
            failures=0,
            target_addr=original_addr,
        ),
    )

    assert proven_function_return_class_8616(project, function.addr) is None
    assert function_result_is_proven_unobserved_8616(project, function.addr) is False
    assert isinstance(function.prototype.returnty, SimTypeShort)
    assert function.is_prototype_guessed is True
