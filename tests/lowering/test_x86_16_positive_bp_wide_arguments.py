from __future__ import annotations

from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import CReturn, CStatements, CVariable
from angr.knowledge_plugins.functions.function import PrototypeSource
from angr.sim_type import SimTypeChar, SimTypeFunction, SimTypeLong, SimTypeShort
from angr.sim_variable import SimStackVariable

import inertia.lowering.positive_bp_arguments as positive_bp_arguments
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.lowering.callee_argument_count_evidence import (
    CalleeArgumentCountEvidence8616,
    CalleeArgumentCountVerdict8616,
)
from inertia.lowering.callee_argument_width_evidence import (
    CalleeArgumentWidthEvidence8616,
    CalleeArgumentWidthVerdict8616,
)
from inertia.lowering.positive_bp_arguments import (
    materialize_positive_bp_arguments_8616,
)
from inertia.semantics.callsite_summary import CallsiteSummary8616


@pytest.mark.parametrize("body_signed", [False, True])
def test_body_owned_wide_slot_is_not_narrowed_by_contained_word_access(
    monkeypatch: pytest.MonkeyPatch,
    body_signed: bool,
) -> None:
    arch = Arch86_16()
    long_type = SimTypeLong(True).with_arch(arch)
    return_type = SimTypeShort(False).with_arch(arch)
    prototype = SimTypeFunction([long_type], return_type, arg_names=("wait",)).with_arch(arch)
    summary = CallsiteSummary8616(
        callsite_addr=0x10537,
        target_addr=0x10F38,
        return_addr=0x1053A,
        kind="near",
        arg_count=2,
        arg_widths=(2, 2),
        logical_arg_widths=(4,),
        stack_cleanup=4,
        return_register="ax",
        return_used=False,
        push_arg_sources=(None, None),
    )
    count_evidence = CalleeArgumentCountEvidence8616(
        target_addr=0x10F38,
        verdict=CalleeArgumentCountVerdict8616.CONSISTENT,
        argument_count=1,
        raw_fact_count=1,
        normalized_fact_count=1,
        classified_fact_count=1,
        materialized_count=1,
        callsite_addrs=(summary.callsite_addr,),
        callsite_summaries=(summary,),
    )
    function = SimpleNamespace(
        addr=0x10F38,
        prototype=prototype,
        prototype_source=PrototypeSource.CCA_DECOMPILER,
        is_prototype_guessed=False,
        info={},
    )
    project = SimpleNamespace(
        arch=arch,
        # No binary body is supplied by this argument-storage fixture.
        factory=SimpleNamespace(
            block=lambda *_args, **_kwargs: SimpleNamespace(capstone=SimpleNamespace(insns=())),
        ),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: function),
        ),
        _inertia_callee_argument_count_evidence_8616={0x10F38: count_evidence},
    )
    codegen = SimpleNamespace(
        project=project,
        next_idx=lambda _name: 1,
        next_ident=lambda name: f"{name}_0",
        next_node_idx=lambda: 1,
    )
    body_variable = SimStackVariable(4, 4, base="bp", name="local_4", region=0x10F38)
    body_cvar = CVariable(body_variable, variable_type=SimTypeLong(body_signed).with_arch(arch), codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=0x10F38,
        arg_list=[],
        functy=prototype,
        prototype=prototype,
        statements=CStatements([body_cvar], codegen=codegen),
        variables_in_use={body_variable: body_cvar},
        unified_local_vars={},
    )
    monkeypatch.setattr(
        positive_bp_arguments,
        "collect_bp_word_stack_access_offsets_8616",
        lambda _project, _function: frozenset({4}),
    )

    assert materialize_positive_bp_arguments_8616(project, codegen) is True

    argument = codegen.cfunc.arg_list[0]
    assert argument.variable.size == 4
    assert argument.variable.name == "arg_4"
    assert argument.variable_type.size == 32
    assert argument.variable_type.signed is True
    stats = codegen._inertia_positive_bp_argument_stats_8616
    assert stats.materialized_count == 1
    assert stats.failure_count == 0


@pytest.mark.parametrize("offset,width", [(6, 2), (4, 4), (4, 0), (4, -1)])
def test_unmaterialized_prototype_refuses_mismatched_storage(offset, width):
    arch = Arch86_16()
    word = SimTypeShort(True).with_arch(arch)
    prototype = SimTypeFunction([word], word).with_arch(arch)
    codegen = SimpleNamespace(project=SimpleNamespace(arch=arch), next_node_idx=lambda: 0, next_ident=lambda name: name)
    candidate = CVariable(SimStackVariable(offset, width, base="bp"), variable_type=word, codegen=codegen)
    cfunc = SimpleNamespace(functy=prototype, prototype=prototype, arg_list=[])
    assert not positive_bp_arguments._existing_interface_matches_8616(codegen, cfunc, [candidate])


@pytest.mark.parametrize("signed", [False, True])
@pytest.mark.parametrize("value_width", [1, 2])
def test_word_slot_replay_preserves_typed_value_view(
    monkeypatch: pytest.MonkeyPatch, signed: bool, value_width: int,
) -> None:
    """ABI word padding must not widen a body-owned byte argument on replay."""
    arch = Arch86_16()
    value_type = (SimTypeChar(signed) if value_width == 1 else SimTypeShort(signed)).with_arch(arch)
    prototype = SimTypeFunction([value_type], value_type, arg_names=("arg_4",)).with_arch(arch)
    summary = CallsiteSummary8616(
        callsite_addr=0x1200, return_addr=0x1203, target_addr=0x1300, kind="near", arg_count=1,
        arg_widths=(2,), logical_arg_widths=(2,), stack_cleanup=2,
        return_register="ax", return_used=False, push_arg_sources=(None,),
    )
    count = CalleeArgumentCountEvidence8616(
        target_addr=0x1300, verdict=CalleeArgumentCountVerdict8616.CONSISTENT,
        argument_count=1, raw_fact_count=1, normalized_fact_count=1,
        classified_fact_count=1, materialized_count=1,
        callsite_addrs=(summary.callsite_addr,), callsite_summaries=(summary,),
    )
    function = SimpleNamespace(
        addr=0x1300, prototype=prototype, prototype_source=PrototypeSource.CCA_DECOMPILER,
        is_prototype_guessed=False, info={},
    )
    project = SimpleNamespace(
        arch=arch,
        factory=SimpleNamespace(block=lambda *_args, **_kwargs: SimpleNamespace(capstone=SimpleNamespace(insns=()))),
        kb=SimpleNamespace(functions=SimpleNamespace(function=lambda addr, create=False: function)),
        _inertia_callee_argument_count_evidence_8616={function.addr: count},
    )
    codegen = SimpleNamespace(project=project, next_idx=lambda _name: 1,
                              next_ident=lambda name: f"{name}_0", next_node_idx=lambda: 1)
    variable = SimStackVariable(4, value_width, base="bp", name="arg_4", region=function.addr)
    candidate = CVariable(variable, variable_type=value_type, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=function.addr, arg_list=[candidate, candidate], functy=prototype, prototype=prototype,
        statements=CStatements([CReturn(candidate, codegen=codegen)], codegen=codegen),
        variables_in_use={variable: candidate}, unified_local_vars={},
    )
    # Reconcile a stale duplicate interface against one body-owned value. The
    # caller census describes ABI storage, independently of the typed value.
    monkeypatch.setattr(positive_bp_arguments, "collect_bp_word_stack_access_offsets_8616",
                        lambda _project, _function: frozenset({4}) if value_width == 2 else frozenset())
    monkeypatch.setattr(positive_bp_arguments, "collect_callee_argument_width_evidence_8616",
                        lambda _project, addr: CalleeArgumentWidthEvidence8616(addr, CalleeArgumentWidthVerdict8616.UNKNOWN))
    assert materialize_positive_bp_arguments_8616(project, codegen)
    assert candidate.variable.size == value_width
    assert candidate.variable_type.size == value_width * 8
    assert materialize_positive_bp_arguments_8616(project, codegen) is False
    assert candidate.variable.size == value_width
