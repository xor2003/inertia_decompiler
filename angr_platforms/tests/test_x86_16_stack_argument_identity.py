from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CFunctionCall,
    CIndexedVariable,
    CStatements,
    CVariable,
)
from angr.knowledge_plugins.functions.function import PrototypeSource
from angr.sim_type import SimTypeChar, SimTypeFunction, SimTypePointer, SimTypeShort
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.lowering.positive_bp_arguments import (
    materialize_positive_bp_arguments_8616,
)
from angr_platforms.X86_16.lowering.stack_argument_identity import (
    unify_positive_bp_argument_identity_8616,
)
from angr_platforms.X86_16.lowering.stack_prototype_materialization import (
    materialize_annotated_stack_prototype_8616,
    reconcile_exact_stack_argument_prototype_8616,
)


def test_unify_positive_bp_argument_identity_propagates_pointer_type() -> None:
    arch = Arch86_16()
    codegen = SimpleNamespace(
        project=SimpleNamespace(arch=arch),
        next_idx=lambda _name: 1,
    next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    pointer_type = SimTypePointer(SimTypeShort(False)).with_arch(arch)
    scalar_type = SimTypeShort(False).with_arch(arch)
    argument = CVariable(
        SimStackVariable(6, 2, base="bp", name="argv", region=0x1000),
        variable_type=pointer_type,
        codegen=codegen,
    )
    duplicate = CVariable(
        SimStackVariable(6, 2, base="bp", name="local_6", region=0x1000),
        variable_type=scalar_type,
        codegen=codegen,
    )
    index = CVariable(
        SimStackVariable(-2, 2, base="bp", name="index", region=0x1000),
        variable_type=scalar_type,
        codegen=codegen,
    )
    indexed = CIndexedVariable(duplicate, index, codegen=codegen)
    call = CFunctionCall("consume", None, [indexed], codegen=codegen)
    statements = CStatements([call], codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        arg_list=[argument],
        statements=statements,
        variables_in_use={
            argument.variable: argument,
            duplicate.variable: duplicate,
        },
        unified_local_vars={
            duplicate.variable: {(duplicate, duplicate.variable_type)},
        },
    )

    changed = unify_positive_bp_argument_identity_8616(codegen)

    assert changed is True
    rewritten = call.args[0]
    assert isinstance(rewritten, CIndexedVariable)
    assert rewritten.variable.variable is argument.variable
    assert rewritten.variable.variable_type is pointer_type
    assert list(codegen.cfunc.variables_in_use.values()) == [argument]
    assert codegen.cfunc.unified_local_vars == {}
    stats = codegen._inertia_arg_stack_identity_stats_8616
    assert stats.classified_fact_count == stats.materialized_count == 1
    assert stats.failure_count == 0


def test_unify_positive_bp_argument_identity_refuses_ambiguous_header() -> None:
    arch = Arch86_16()
    codegen = SimpleNamespace(
        project=SimpleNamespace(arch=arch),
        next_idx=lambda _name: 1,
    next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    scalar_type = SimTypeShort(False).with_arch(arch)
    arguments = [
        CVariable(
            SimStackVariable(6, 2, base="bp", name=name, region=0x1000),
            variable_type=scalar_type,
            codegen=codegen,
        )
        for name in ("first", "second")
    ]
    duplicate = CVariable(
        SimStackVariable(6, 2, base="bp", name="body", region=0x1000),
        variable_type=scalar_type,
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        arg_list=arguments,
        statements=CStatements([duplicate], codegen=codegen),
        variables_in_use={duplicate.variable: duplicate},
        unified_local_vars={},
    )

    assert unify_positive_bp_argument_identity_8616(codegen) is False
    assert codegen._inertia_arg_stack_identity_stats_8616.failure_count == 0


def test_reconcile_renames_provisional_local_positive_bp_argument() -> None:
    arch = Arch86_16()
    scalar_type = SimTypeShort(False).with_arch(arch)
    prototype = SimTypeFunction(
        [scalar_type],
        scalar_type,
        arg_names=["local"],
    ).with_arch(arch)
    function = SimpleNamespace(
        prototype=prototype,
        is_prototype_guessed=True,
    )
    project = SimpleNamespace(
        arch=arch,
        kb=SimpleNamespace(
            functions=SimpleNamespace(
                function=lambda addr, create=False: (
                    function if addr == 0x1000 else None
                )
            )
        ),
    )
    codegen = SimpleNamespace(
        project=project,
        next_idx=lambda _name: 1,
    next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    argument = CVariable(
        SimStackVariable(6, 2, base="bp", name="local_6", region=0x1000),
        variable_type=scalar_type,
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        arg_list=[argument],
        functy=prototype,
        statements=CStatements([], codegen=codegen),
        variables_in_use={argument.variable: argument},
        unified_local_vars={},
    )
    codegen._inertia_callsite_summaries = {
        0x1010: SimpleNamespace(
            arg_widths=(2,),
            push_arg_sources=(("bp", 6),),
        )
    }

    assert reconcile_exact_stack_argument_prototype_8616(project, codegen) is True
    assert argument.variable.name == "arg_6"
    assert tuple(codegen.cfunc.functy.arg_names or ()) == ("arg_6",)


def test_materialize_positive_bp_body_slot_replaces_guessed_zero_arg_interface() -> None:
    arch = Arch86_16()
    scalar_type = SimTypeShort(False).with_arch(arch)
    prototype = SimTypeFunction([], scalar_type).with_arch(arch)
    function = SimpleNamespace(
        prototype=prototype,
        prototype_source=PrototypeSource.GUESSED,
        is_prototype_guessed=False,
        info={},
    )
    project = SimpleNamespace(
        arch=arch,
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: function),
        ),
    )
    codegen = SimpleNamespace(project=project, next_idx=lambda _name: 1, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    body_argument = CVariable(
        SimStackVariable(4, 2, base="bp", name="local_4", region=0x1000),
        variable_type=scalar_type,
        codegen=codegen,
    )
    statements = CStatements([body_argument], codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        arg_list=[],
        functy=prototype,
        prototype=prototype,
        statements=statements,
        variables_in_use={body_argument.variable: body_argument},
        unified_local_vars={body_argument.variable: {(body_argument, scalar_type)}},
    )

    assert materialize_annotated_stack_prototype_8616(
        project,
        codegen,
        fallback_to_positive_bp=False,
    ) is False
    assert not hasattr(codegen, "_inertia_authoritative_zero_arg_prototype_8616")
    assert materialize_positive_bp_arguments_8616(project, codegen) is True
    assert unify_positive_bp_argument_identity_8616(codegen) is False
    assert codegen.cfunc.arg_list == [body_argument]
    assert body_argument.variable.name == "arg_4"
    assert tuple(codegen.cfunc.functy.arg_names or ()) == ("arg_4",)
    assert codegen.cfunc.unified_local_vars == {}
    stats = codegen._inertia_positive_bp_argument_stats_8616
    assert stats.classified_fact_count == stats.materialized_count == 1
    assert stats.failure_count == 0


def test_materialize_positive_bp_arguments_replaces_contained_stale_byte_arg() -> None:
    arch = Arch86_16()
    word_type = SimTypeShort(False).with_arch(arch)
    byte_type = SimTypeChar().with_arch(arch)
    prototype = SimTypeFunction([byte_type, word_type], word_type).with_arch(arch)
    function = SimpleNamespace(
        prototype=prototype,
        prototype_source=PrototypeSource.GUESSED,
        is_prototype_guessed=True,
    )
    project = SimpleNamespace(
        arch=arch,
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: function),
        ),
    )
    codegen = SimpleNamespace(project=project, next_idx=lambda _name: 1, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    frequency = CVariable(
        SimStackVariable(4, 2, base="bp", name="local_5", region=0x1000),
        variable_type=word_type,
        codegen=codegen,
    )
    stale_byte = CVariable(
        SimStackVariable(5, 1, base="bp", name="local", region=0x1000),
        variable_type=byte_type,
        codegen=codegen,
    )
    duration = CVariable(
        SimStackVariable(6, 2, base="bp", name="local_6", region=0x1000),
        variable_type=word_type,
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        arg_list=[stale_byte, duration],
        functy=prototype,
        prototype=prototype,
        statements=CStatements([frequency, duration], codegen=codegen),
        variables_in_use={
            frequency.variable: frequency,
            stale_byte.variable: stale_byte,
            duration.variable: duration,
        },
        unified_local_vars={},
    )

    assert materialize_positive_bp_arguments_8616(project, codegen) is True
    assert codegen.cfunc.arg_list == [frequency, duration]
    assert tuple(codegen.cfunc.functy.arg_names or ()) == ("arg_4", "arg_6")
    assert stale_byte.variable not in codegen.cfunc.variables_in_use


def test_materialize_positive_bp_arguments_respects_authoritative_zero_args() -> None:
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(),
        _inertia_authoritative_zero_arg_prototype_8616=True,
    )

    assert materialize_positive_bp_arguments_8616(SimpleNamespace(), codegen) is False


def test_materialize_positive_bp_arguments_ignores_stale_unused_stack_cvar() -> None:
    arch = Arch86_16()
    scalar_type = SimTypeShort(False).with_arch(arch)
    prototype = SimTypeFunction([], scalar_type).with_arch(arch)
    codegen = SimpleNamespace(
        project=SimpleNamespace(arch=arch),
        next_idx=lambda _name: 1,
    next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    stale = CVariable(
        SimStackVariable(4, 2, base="bp", name="local_4", region=0x1000),
        variable_type=scalar_type,
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        arg_list=[],
        functy=prototype,
        prototype=prototype,
        statements=CStatements([], codegen=codegen),
        variables_in_use={stale.variable: stale},
        unified_local_vars={},
    )

    assert materialize_positive_bp_arguments_8616(SimpleNamespace(arch=arch), codegen) is False
    stats = codegen._inertia_positive_bp_argument_stats_8616
    assert stats.raw_fact_count == stats.normalized_fact_count == 1
    assert stats.classified_fact_count == stats.materialized_count == 0


def test_materialize_positive_bp_arguments_preserves_coherent_signed_types() -> None:
    arch = Arch86_16()
    signed_type = SimTypeShort(True).with_arch(arch)
    prototype = SimTypeFunction(
        [signed_type, signed_type],
        signed_type,
        arg_names=["low", "high"],
    ).with_arch(arch)
    codegen = SimpleNamespace(
        project=SimpleNamespace(arch=arch),
        next_idx=lambda _name: 1,
    next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    arguments = [
        CVariable(
            SimStackVariable(offset, 2, base="bp", name=name, region=0x1000),
            variable_type=signed_type,
            codegen=codegen,
        )
        for offset, name in ((4, "low"), (6, "high"))
    ]
    body_arguments = [
        CVariable(
            SimStackVariable(offset, 2, base="bp", name=f"local_{offset}", region=0x1000),
            variable_type=SimTypeShort(False).with_arch(arch),
            codegen=codegen,
        )
        for offset in (4, 6)
    ]
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        arg_list=arguments,
        functy=prototype,
        prototype=prototype,
        statements=CStatements(body_arguments, codegen=codegen),
        variables_in_use={argument.variable: argument for argument in arguments},
        unified_local_vars={},
    )

    assert materialize_positive_bp_arguments_8616(SimpleNamespace(arch=arch), codegen) is True
    assert codegen.cfunc.arg_list == body_arguments
    assert tuple(codegen.cfunc.functy.args or ()) == (signed_type, signed_type)
    assert all(argument.variable_type is signed_type for argument in body_arguments)
    stats = codegen._inertia_positive_bp_argument_stats_8616
    assert stats.classified_fact_count == stats.materialized_count == 2
