from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import CStatements, CVariable
from angr.sim_type import SimTypeFunction, SimTypePointer, SimTypeShort
from angr.sim_variable import SimStackVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.lowering.callee_argument_count_evidence import (
    CalleeArgumentCountEvidence8616,
    CalleeArgumentCountVerdict8616,
)
from inertia.lowering.callee_argument_interface import (
    CalleeArgumentInterfaceDecision8616,
    materialize_callee_pointer_codegen_interface_8616,
    reconcile_callee_argument_interface_8616,
)
from inertia.lowering.callee_pointer_evidence import (
    CalleePointerArgumentEvidence8616,
)
from inertia.lowering.positive_bp_arguments import materialize_positive_bp_arguments_8616


def test_callee_argument_interface_materializes_binary_proven_zero_args() -> None:
    arch = Arch86_16()
    word_type = SimTypeShort(False).with_arch(arch)
    one_arg = SimTypeFunction([word_type], word_type, arg_names=["stale"]).with_arch(arch)
    function = SimpleNamespace(prototype=one_arg, is_prototype_guessed=True)
    project = SimpleNamespace(
        arch=arch,
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: function),
        ),
        _inertia_callee_argument_count_evidence_8616={
            0x1000: CalleeArgumentCountEvidence8616(
                target_addr=0x1000,
                verdict=CalleeArgumentCountVerdict8616.CONSISTENT,
                argument_count=0,
                raw_fact_count=1,
                normalized_fact_count=1,
                classified_fact_count=1,
                materialized_count=1,
            )
        },
    )
    cfunc = SimpleNamespace(
        addr=0x1000,
        arg_list=[SimpleNamespace(name="stale")],
        functy=one_arg,
    )
    codegen = SimpleNamespace(cfunc=cfunc)

    result = reconcile_callee_argument_interface_8616(project, codegen, candidate_count=1)

    assert result.decision is CalleeArgumentInterfaceDecision8616.MATERIALIZED_ZERO
    assert result.changed is True
    assert cfunc.arg_list == []
    assert tuple(cfunc.functy.args or ()) == ()
    assert tuple(function.prototype.args or ()) == ()
    assert function.is_prototype_guessed is False
    assert codegen._inertia_authoritative_zero_arg_prototype_8616 is True


def test_callee_argument_interface_refuses_conflicting_arity_without_mutation() -> None:
    evidence = CalleeArgumentCountEvidence8616(
        target_addr=0x1000,
        verdict=CalleeArgumentCountVerdict8616.CONFLICT,
        raw_fact_count=2,
        normalized_fact_count=2,
        classified_fact_count=2,
        materialized_count=2,
        failure_count=1,
    )
    cfunc = SimpleNamespace(addr=0x1000, arg_list=[object()])
    project = SimpleNamespace(
        _inertia_callee_argument_count_evidence_8616={0x1000: evidence},
    )
    codegen = SimpleNamespace(cfunc=cfunc)

    result = reconcile_callee_argument_interface_8616(project, codegen, candidate_count=1)

    assert result.decision is CalleeArgumentInterfaceDecision8616.REFUSE
    assert result.changed is False
    assert len(cfunc.arg_list) == 1


def test_callee_argument_interface_refuses_incomplete_consistent_cache_without_mutation() -> None:
    evidence = CalleeArgumentCountEvidence8616(
        target_addr=0x1000,
        verdict=CalleeArgumentCountVerdict8616.CONSISTENT,
        argument_count=0,
        raw_fact_count=2,
        normalized_fact_count=1,
        classified_fact_count=1,
        materialized_count=1,
        failure_count=1,
    )
    cfunc = SimpleNamespace(addr=0x1000, arg_list=[object()])
    project = SimpleNamespace(
        _inertia_callee_argument_count_evidence_8616={0x1000: evidence},
    )
    codegen = SimpleNamespace(cfunc=cfunc)

    result = reconcile_callee_argument_interface_8616(project, codegen, candidate_count=1)

    assert evidence.closes_census is False
    assert result.decision is CalleeArgumentInterfaceDecision8616.REFUSE
    assert result.changed is False
    assert len(cfunc.arg_list) == 1


def test_callee_argument_interface_refuses_incomplete_unknown_census_without_mutation() -> None:
    evidence = CalleeArgumentCountEvidence8616(
        target_addr=0x1000,
        verdict=CalleeArgumentCountVerdict8616.UNKNOWN,
        raw_fact_count=2,
        normalized_fact_count=1,
        classified_fact_count=1,
        materialized_count=1,
        failure_count=1,
    )
    cfunc = SimpleNamespace(addr=0x1000, arg_list=[object()])
    project = SimpleNamespace(
        _inertia_callee_argument_count_evidence_8616={0x1000: evidence},
    )
    codegen = SimpleNamespace(cfunc=cfunc)

    result = reconcile_callee_argument_interface_8616(project, codegen, candidate_count=1)

    assert result.decision is CalleeArgumentInterfaceDecision8616.REFUSE
    assert result.changed is False
    assert len(cfunc.arg_list) == 1


def test_callee_argument_interface_accepts_body_evidence_without_discovered_callers() -> None:
    evidence = CalleeArgumentCountEvidence8616(
        target_addr=0x1000,
        verdict=CalleeArgumentCountVerdict8616.UNKNOWN,
    )
    cfunc = SimpleNamespace(addr=0x1000, arg_list=[object()])
    project = SimpleNamespace(
        _inertia_callee_argument_count_evidence_8616={0x1000: evidence},
    )
    codegen = SimpleNamespace(cfunc=cfunc)

    result = reconcile_callee_argument_interface_8616(project, codegen, candidate_count=1)

    assert result.decision is CalleeArgumentInterfaceDecision8616.ACCEPT
    assert result.changed is False
    assert len(cfunc.arg_list) == 1


def test_positive_bp_lowering_clears_stale_unused_header_from_binary_zero_evidence() -> None:
    arch = Arch86_16()
    word_type = SimTypeShort(False).with_arch(arch)
    one_arg = SimTypeFunction([word_type], word_type, arg_names=["stale"]).with_arch(arch)
    function = SimpleNamespace(prototype=one_arg, is_prototype_guessed=True)
    project = SimpleNamespace(
        arch=arch,
        kb=SimpleNamespace(functions=SimpleNamespace(function=lambda addr, create=False: function)),
        _inertia_callee_argument_count_evidence_8616={
            0x1000: CalleeArgumentCountEvidence8616(
                target_addr=0x1000,
                verdict=CalleeArgumentCountVerdict8616.CONSISTENT,
                argument_count=0,
                raw_fact_count=1,
                normalized_fact_count=1,
                classified_fact_count=1,
                materialized_count=1,
            )
        },
    )
    codegen = SimpleNamespace(project=project, next_idx=lambda name: 1, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    argument = CVariable(
        SimStackVariable(4, 2, base="bp", name="stale", region=0x1000),
        variable_type=word_type,
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        arg_list=[argument],
        functy=one_arg,
        statements=CStatements([], codegen=codegen),
        variables_in_use={argument.variable: argument},
        unified_local_vars={},
    )

    assert materialize_positive_bp_arguments_8616(project, codegen) is True
    assert codegen.cfunc.arg_list == []
    assert tuple(codegen.cfunc.functy.args or ()) == ()


def test_pointer_interface_materializes_binary_proven_trailing_bp_argument() -> None:
    arch = Arch86_16()
    word_type = SimTypeShort(False).with_arch(arch)
    one_arg = SimTypeFunction([word_type], word_type, arg_names=["bar1"]).with_arch(arch)
    function = SimpleNamespace(prototype=one_arg, is_prototype_guessed=True)
    project = SimpleNamespace(
        arch=arch,
        kb=SimpleNamespace(functions=SimpleNamespace(function=lambda addr, create=False: function)),
    )
    codegen = SimpleNamespace(project=project, next_idx=lambda name: 1, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    bar1 = CVariable(
        SimStackVariable(4, 2, base="bp", name="bar1", region=0x1000),
        variable_type=word_type,
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        arg_list=[bar1],
        functy=one_arg,
        unified_local_vars={},
        variables_in_use={bar1.variable: bar1},
    )
    evidence = CalleePointerArgumentEvidence8616(
        target_addr=0x1000,
        raw_fact_count=4,
        normalized_fact_count=2,
        classified_fact_count=2,
        materialized_count=2,
        failure_count=0,
        pointer_stack_offsets=(4, 6),
        pointer_argument_indices=(0, 1),
        ambiguous_displaced_stack_offsets=(),
    )

    result = materialize_callee_pointer_codegen_interface_8616(project, codegen, evidence)

    assert result.materialized_count == 2
    assert result.failure_count == 0
    assert result.changed is True
    assert [argument.variable.offset for argument in codegen.cfunc.arg_list] == [4, 6]
    assert isinstance(codegen.cfunc.functy.args[1], SimTypePointer)


def test_pointer_interface_refuses_to_invent_missing_scalar_prefix() -> None:
    arch = Arch86_16()
    word_type = SimTypeShort(False).with_arch(arch)
    prototype = SimTypeFunction([word_type], word_type).with_arch(arch)
    function = SimpleNamespace(prototype=prototype, is_prototype_guessed=True)
    project = SimpleNamespace(
        arch=arch,
        kb=SimpleNamespace(functions=SimpleNamespace(function=lambda addr, create=False: function)),
    )
    codegen = SimpleNamespace(project=project, next_idx=lambda name: 1, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    first = CVariable(
        SimStackVariable(4, 2, base="bp", name="value", region=0x1000),
        variable_type=word_type,
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        arg_list=[first],
        functy=prototype,
        unified_local_vars={},
        variables_in_use={first.variable: first},
    )
    evidence = CalleePointerArgumentEvidence8616(
        target_addr=0x1000,
        raw_fact_count=1,
        normalized_fact_count=1,
        classified_fact_count=1,
        materialized_count=1,
        failure_count=0,
        pointer_stack_offsets=(8,),
        pointer_argument_indices=(2,),
        ambiguous_displaced_stack_offsets=(),
    )

    result = materialize_callee_pointer_codegen_interface_8616(project, codegen, evidence)

    assert result.materialized_count == 0
    assert result.failure_count == 1
    assert result.changed is False
    assert len(codegen.cfunc.arg_list) == 1
