from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CForLoop,
    CIndexedVariable,
    CReturn,
    CStatements,
    CVariable,
    CWhileLoop,
)
from angr.knowledge_plugins.functions.function import PrototypeSource
from angr.sim_type import SimTypeChar, SimTypeFunction, SimTypePointer, SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.lowering.authoritative_function_prototypes import (
    authoritative_function_prototype_8616,
    capture_authoritative_function_prototype_8616,
)
from angr_platforms.X86_16.lowering.pointer_memory_idioms import (
    PointerMemoryIdiomCallbacks8616,
    PointerMemoryIdiomKind8616,
    PointerMemoryIdiomMaterializationFact8616,
    PointerSwapSpliceStats8616,
    _normalize_materialized_counted_loop_8616,
    materialize_pointer_memory_idioms_from_evidence_8616,
    pointer_memory_loop_validation_delta_is_precision_only_8616,
    pointer_swap_validation_delta_is_precision_only_8616,
    splice_proven_pointer_swap_statements_8616,
)


class _SlottedCFunction:
    """Minimal real angr CFunction shape: statements exists, body does not."""

    __slots__ = ("statements",)


def test_pointer_memory_idiom_dispatches_first_proven_materializer() -> None:
    calls: list[str] = []
    insns = (SimpleNamespace(address=0x1000), SimpleNamespace(address=0x1002))

    def linear(_project: object, _codegen: object) -> tuple[object, ...]:
        calls.append("linear")
        return insns

    def refuse(name: str):
        def _refuse(
            _project: object,
            _codegen: object,
            _insns: tuple[object, ...],
            index_by_addr: dict[int, int],
        ) -> bool:
            assert index_by_addr == {0x1000: 0, 0x1002: 1}
            calls.append(name)
            return False

        return _refuse

    def materialize(
        _project: object,
        _codegen: object,
        _insns: tuple[object, ...],
        index_by_addr: dict[int, int],
    ) -> bool:
        assert index_by_addr == {0x1000: 0, 0x1002: 1}
        calls.append("word-first-gt")
        return True

    callbacks = PointerMemoryIdiomCallbacks8616(
        linear_function_insns=linear,
        word_pair_pointer_accumulation_loop=refuse("pair-accum"),
        word_pointer_first_gt_loop=materialize,
        word_pointer_rotate3=refuse("rotate3"),
        pointer_swap=refuse("swap"),
    )

    codegen = SimpleNamespace()

    assert materialize_pointer_memory_idioms_from_evidence_8616(object(), codegen, callbacks) is True
    assert calls == ["linear", "pair-accum", "word-first-gt"]
    assert codegen._inertia_pointer_memory_idiom_facts_8616 == (
        PointerMemoryIdiomMaterializationFact8616(
            kind=PointerMemoryIdiomKind8616.WORD_FIRST_GREATER_LOOP,
            raw_fact_count=1,
            normalized_fact_count=1,
            classified_fact_count=1,
            materialized_count=1,
            failure_count=0,
            counted_loop_normalized=True,
            pointer_stack_offset=None,
            index_stack_offset=None,
            element_stride=None,
        ),
    )


def test_pointer_memory_idiom_dispatch_refuses_without_instruction_evidence() -> None:
    callbacks = PointerMemoryIdiomCallbacks8616(
        linear_function_insns=lambda _project, _codegen: (),
        word_pair_pointer_accumulation_loop=lambda *_args: True,
        word_pointer_first_gt_loop=lambda *_args: True,
        word_pointer_rotate3=lambda *_args: True,
        pointer_swap=lambda *_args: True,
    )

    assert materialize_pointer_memory_idioms_from_evidence_8616(object(), object(), callbacks) is False


def test_pointer_memory_idiom_publishes_materialized_pointer_interface() -> None:
    stale = SimTypeFunction([SimTypeShort(False)], SimTypeShort(False))
    recovered = SimTypeFunction(
        [SimTypePointer(SimTypeChar(False))],
        SimTypeShort(False),
    )
    function = SimpleNamespace(
        addr=0x1000,
        prototype=stale,
        prototype_source=PrototypeSource.CCA_DECOMPILER,
        info={},
    )
    project = SimpleNamespace(
        kb=SimpleNamespace(
            functions=SimpleNamespace(
                function=lambda *, addr, create: function if addr == function.addr and not create else None
            )
        )
    )
    capture_authoritative_function_prototype_8616(project, function)
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=function.addr, functy=stale))
    insns = (SimpleNamespace(address=0x1000),)

    def materialize(*_args: object) -> bool:
        codegen.cfunc.functy = recovered
        return True

    callbacks = PointerMemoryIdiomCallbacks8616(
        linear_function_insns=lambda _project, _codegen: insns,
        word_pair_pointer_accumulation_loop=lambda *_args: False,
        word_pointer_first_gt_loop=materialize,
        word_pointer_rotate3=lambda *_args: False,
        pointer_swap=lambda *_args: False,
    )

    assert materialize_pointer_memory_idioms_from_evidence_8616(project, codegen, callbacks)
    assert authoritative_function_prototype_8616(
        project,
        function,
        argument_count=1,
    ) == recovered


def test_legacy_byte_fill_projection_normalizes_as_for_loop_with_return() -> None:
    """Retain old projection compatibility without invoking a body replacement."""
    codegen = SimpleNamespace(
        cstyle_null_cmp=False,
        next_idx=lambda _name: 0,
        project=SimpleNamespace(arch=Arch86_16()),
    next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 0)
    index = CVariable(SimStackVariable(-2, 2, base="bp", name="index"), codegen=codegen)
    initializer = CAssignment(index, CConstant(0, SimTypeShort(False), codegen=codegen), codegen=codegen)
    iterator = CAssignment(
        index,
        CBinaryOp("Add", index, CConstant(1, SimTypeShort(False), codegen=codegen), codegen=codegen),
        codegen=codegen,
    )
    body_statement = CAssignment(
        CVariable(SimRegisterVariable(0, 2, name="target"), codegen=codegen),
        CConstant(3, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    loop = CWhileLoop(
        CConstant(1, SimTypeShort(False), codegen=codegen),
        CStatements([body_statement, iterator], codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        statements=CStatements([initializer, loop], codegen=codegen),
    )
    assert _normalize_materialized_counted_loop_8616(codegen, PointerMemoryIdiomKind8616.BYTE_FILL_LOOP)
    normalized = codegen.cfunc.statements.statements
    assert len(normalized) == 2
    assert isinstance(normalized[0], CForLoop)
    assert normalized[0].initializer is initializer
    assert normalized[0].iterator is iterator
    assert normalized[0].body.statements == [body_statement]
    assert isinstance(normalized[1], CReturn)
    assert normalized[1].retval is None


def test_pointer_memory_byte_fill_accepts_only_exact_write_precision_delta() -> None:
    fact = PointerMemoryIdiomMaterializationFact8616(
        kind=PointerMemoryIdiomKind8616.BYTE_FILL_LOOP,
        raw_fact_count=1,
        normalized_fact_count=1,
        classified_fact_count=1,
        materialized_count=1,
        failure_count=0,
        counted_loop_normalized=True,
        pointer_stack_offset=4,
        index_stack_offset=-2,
        element_stride=1,
    )
    added = "deref:Add(Mul(reg:ds,const:16),stack_slot:SS:BP+0x4:size2,stack_slot:SS:BP-0x2:size2)"
    removed = "deref:Add(stack_slot:SS:BP+0x0:size4,stack_slot:SS:BP-0x2:size2,stack_slot:SS:BP+0x4:size2)"
    condition = "CmpLT(stack_slot:SS:BP-0x2:size2,stack_slot:SS:BP+0x8:size2)"
    validation: dict[str, object] = {
        "delta": {
            "segmented_writes": {"added": (added,), "removed": (removed,)},
            "control_flow_effects": {
                "added": (
                    f"for-body-writes:{condition}:"
                    "deref:Add(Mul(reg:ds,const:16),stack_arg:dst:size2:bp+0x4,"
                    "stack_slot:SS:BP-0x2:size2)",
                ),
                "removed": (f"for-body-writes:{condition}:{removed}",),
            },
        }
    }

    assert pointer_memory_loop_validation_delta_is_precision_only_8616(fact, validation)
    validation["delta"]["segmented_writes"]["added"] = (
        "deref:Add(Mul(reg:ds,const:16),stack_slot:SS:BP+0x6:size2,stack_slot:SS:BP-0x2:size2)",
    )
    assert not pointer_memory_loop_validation_delta_is_precision_only_8616(fact, validation)


def test_pointer_swap_validation_accepts_only_symbolic_write_precision_delta() -> None:
    stats = PointerSwapSpliceStats8616(
        raw_fact_count=9,
        normalized_fact_count=1,
        classified_fact_count=1,
        materialized_count=1,
        failure_count=0,
        left_machine_bp_offset=4,
        right_machine_bp_offset=6,
    )
    validation: dict[str, object] = {
        "delta": {
            "segmented_writes": {
                "added": (
                    "deref:Add(Mul(reg:ds,const:16),stack_slot:SS:BP+0x4:size2)",
                    "deref:Add(Mul(reg:ds,const:16),stack_slot:SS:BP+0x6:size2)",
                ),
                "removed": (
                    "deref:Add(Reference(global:0x1),stack_slot:SS:BP+0x2:size4)",
                    "deref:Add(stack_slot:SS:BP+0x0:size2,stack_slot:SS:BP+0x4:size2)",
                ),
            }
        }
    }

    assert pointer_swap_validation_delta_is_precision_only_8616(stats, validation)
    validation["delta"]["helper_calls"] = {"added": ("addr:0x1234",), "removed": ()}
    assert not pointer_swap_validation_delta_is_precision_only_8616(stats, validation)


def test_pointer_swap_splice_preserves_unrelated_counter_effect() -> None:
    project = SimpleNamespace(arch=Arch86_16())
    cfunc = _SlottedCFunction()
    codegen = SimpleNamespace(project=project, cfunc=cfunc, next_idx=lambda _name: 0, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 0)
    word_type = SimTypeShort(False).with_arch(project.arch)
    pointer_type = SimTypePointer(word_type).with_arch(project.arch)
    left = CVariable(
        SimStackVariable(4, 2, base="bp", name="left"),
        variable_type=pointer_type,
        tags={"ins_addr": 0x9999},
        codegen=codegen,
    )
    right = CVariable(SimStackVariable(6, 2, base="bp", name="right"), variable_type=pointer_type, codegen=codegen)
    temporary = CVariable(
        SimStackVariable(-2, 2, base="bp", name="temporary"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    counter = CVariable(SimRegisterVariable(0, 2, name="counter"), variable_type=SimTypeShort(False), codegen=codegen)
    carrier = CVariable(SimRegisterVariable(2, 2, name="carrier"), variable_type=SimTypeShort(False), codegen=codegen)
    counter_effect = CAssignment(
        counter,
        CConstant(1, SimTypeShort(False), codegen=codegen),
        tags={"ins_addr": 0x1000},
        codegen=codegen,
    )
    stale_temp_load = CAssignment(temporary, left, tags={"ins_addr": 0x1006}, codegen=codegen)
    setup = CAssignment(carrier, CConstant(0, word_type, codegen=codegen), tags={"ins_addr": 0x1008}, codegen=codegen)
    epilogue = CAssignment(
        carrier, CConstant(3, word_type, codegen=codegen), tags={"ins_addr": 0x1018}, codegen=codegen
    )
    swap_region = [
        CAssignment(carrier, left, tags={"ins_addr": 0x1010}, codegen=codegen),
        CAssignment(
            carrier,
            CConstant(2, SimTypeShort(False), codegen=codegen),
            tags={"ins_addr": 0x1012},
            codegen=codegen,
        ),
        CAssignment(left, right, tags={"ins_addr": 0x1014}, codegen=codegen),
        CAssignment(right, temporary, tags={"ins_addr": 0x1016}, codegen=codegen),
    ]
    nested = CStatements([setup, *swap_region, epilogue], codegen=codegen)
    root = CStatements([stale_temp_load, counter_effect, nested], codegen=codegen)
    cfunc.statements = root

    proven = frozenset({0x1010, 0x1012, 0x1014, 0x1016})
    assert splice_proven_pointer_swap_statements_8616(
        codegen,
        left,
        right,
        temporary,
        proven,
        frozenset({0x1014, 0x1016}),
    ) is True
    assert cfunc.statements.statements[0] is counter_effect
    assert cfunc.statements.statements[1] is nested
    assert stale_temp_load not in cfunc.statements.statements
    assert nested.statements[0] is setup
    assert nested.statements[-1] is epilogue
    assert len(nested.statements) == 5
    stats = codegen._inertia_pointer_swap_splice_stats_8616
    assert stats.raw_fact_count == 4
    assert stats.normalized_fact_count == 1
    assert stats.classified_fact_count == 1
    assert stats.materialized_count == 1
    assert stats.failure_count == 0
    assert stats.idempotent_count == 0
    assert stats.proven_ins_addrs == (0x1010, 0x1012, 0x1014, 0x1016)
    assert stats.required_write_ins_addrs == (0x1014, 0x1016)
    assert stats.observed_ins_addrs == (0x1000, 0x1006, 0x1008, 0x1010, 0x1012, 0x1014, 0x1016, 0x1018)
    assert stats.statement_ins_addrs == (
        (0x1006,),
        (0x1000,),
        (0x1008,),
        (0x1010,),
        (0x1012,),
        (0x1014,),
        (0x1016,),
        (0x1018,),
    )


def test_pointer_swap_splice_refuses_without_exact_statement_provenance() -> None:
    project = SimpleNamespace(arch=Arch86_16())
    cfunc = _SlottedCFunction()
    codegen = SimpleNamespace(project=project, cfunc=cfunc, next_idx=lambda _name: 0, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 0)
    word_type = SimTypeShort(False).with_arch(project.arch)
    pointer_type = SimTypePointer(word_type).with_arch(project.arch)
    left = CVariable(SimStackVariable(4, 2, base="bp", name="left"), variable_type=pointer_type, codegen=codegen)
    right = CVariable(SimStackVariable(6, 2, base="bp", name="right"), variable_type=pointer_type, codegen=codegen)
    temporary = CVariable(
        SimStackVariable(-2, 2, base="bp", name="temporary"), variable_type=word_type, codegen=codegen
    )
    unowned = CAssignment(temporary, left, codegen=codegen)
    root = CStatements([unowned], codegen=codegen)
    cfunc.statements = root

    assert splice_proven_pointer_swap_statements_8616(
        codegen,
        left,
        right,
        temporary,
        frozenset({0x1010}),
        frozenset({0x1010}),
    ) is False
    assert cfunc.statements.statements == [unowned]
    stats = codegen._inertia_pointer_swap_splice_stats_8616
    assert stats.raw_fact_count == 0
    assert stats.materialized_count == 0
    assert stats.failure_count == 1
    assert stats.proven_ins_addrs == (0x1010,)
    assert stats.required_write_ins_addrs == (0x1010,)
    assert stats.observed_ins_addrs == ()
    assert stats.statement_ins_addrs == ((),)


def test_pointer_swap_splice_is_idempotent_for_exact_materialized_sequence() -> None:
    project = SimpleNamespace(arch=Arch86_16())
    cfunc = _SlottedCFunction()
    codegen = SimpleNamespace(project=project, cfunc=cfunc, next_idx=lambda _name: 0, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 0)
    word_type = SimTypeShort(False).with_arch(project.arch)
    pointer_type = SimTypePointer(word_type).with_arch(project.arch)
    left = CVariable(SimStackVariable(4, 2, base="bp", name="left"), variable_type=pointer_type, codegen=codegen)
    right = CVariable(
        SimStackVariable(6, 2, base="bp", name="right"),
        variable_type=pointer_type,
        codegen=codegen,
    )
    temporary = CVariable(
        SimStackVariable(-2, 2, base="bp", name="temporary"),
        variable_type=word_type,
        codegen=codegen,
    )
    zero = CConstant(0, word_type, codegen=codegen)
    statements = [
        CAssignment(temporary, CIndexedVariable(left, zero, variable_type=word_type, codegen=codegen), codegen=codegen),
        CAssignment(
            CIndexedVariable(left, zero, variable_type=word_type, codegen=codegen),
            CIndexedVariable(right, zero, variable_type=word_type, codegen=codegen),
            codegen=codegen,
        ),
        CAssignment(
            CIndexedVariable(right, zero, variable_type=word_type, codegen=codegen),
            temporary,
            codegen=codegen,
        ),
    ]
    cfunc.statements = CStatements(statements, codegen=codegen)

    assert not splice_proven_pointer_swap_statements_8616(
        codegen,
        left,
        right,
        temporary,
        frozenset({0x1010, 0x1012, 0x1014, 0x1016}),
        frozenset({0x1014, 0x1016}),
    )
    assert cfunc.statements.statements == statements
    stats = codegen._inertia_pointer_swap_splice_stats_8616
    assert stats.materialized_count == 1
    assert stats.idempotent_count == 1
    assert stats.failure_count == 0

    stale_temp_load = CAssignment(
        temporary,
        CIndexedVariable(left, zero, variable_type=word_type, codegen=codegen),
        tags={"ins_addr": 0x1012},
        codegen=codegen,
    )
    cfunc.statements.statements.append(stale_temp_load)
    assert splice_proven_pointer_swap_statements_8616(
        codegen,
        left,
        right,
        temporary,
        frozenset({0x1010, 0x1012, 0x1014, 0x1016}),
        frozenset({0x1014, 0x1016}),
    )
    assert cfunc.statements.statements == statements
    stats = codegen._inertia_pointer_swap_splice_stats_8616
    assert stats.stale_temp_assignment_count == 1
    assert stats.materialized_count == 1
    assert stats.idempotent_count == 1
    assert stats.failure_count == 0
