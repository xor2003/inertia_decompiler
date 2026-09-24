from __future__ import annotations

from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import CStatements, CVariable
from angr.knowledge_plugins.functions.function import PrototypeSource
from angr.sim_type import SimTypeFunction, SimTypeLong, SimTypeShort
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.callsite_summary import CallsiteSummary8616
from angr_platforms.X86_16.lowering import positive_bp_arguments
from angr_platforms.X86_16.lowering.callee_argument_count_evidence import (
    CalleeArgumentCountEvidence8616,
    CalleeArgumentCountVerdict8616,
)
from angr_platforms.X86_16.lowering.positive_bp_arguments import (
    materialize_positive_bp_arguments_8616,
)


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
