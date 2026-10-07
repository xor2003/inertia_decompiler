from dataclasses import replace
from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CConstant,
    CFunctionCall,
    CStatements,
    CUnaryOp,
    CVariable,
)
from angr.rustylib.ailment import Tags
from angr.sim_type import (
    SimStruct,
    SimTypeChar,
    SimTypeFixedSizeArray,
    SimTypeFunction,
    SimTypeLong,
    SimTypePointer,
    SimTypeShort,
    TypeRef,
)
from angr.sim_variable import SimStackVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.semantics.callsite_summary import (
    CallerReturnUseEvidence8616,
    CallerReturnUseVerdict8616,
    CallsiteArgumentClass8616,
    CallsiteSummary8616,
    record_caller_return_use_evidence_8616,
)
import inertia.lowering.callsite_prototype_declarations as declaration_lowering
import inertia.lowering.stack_prototype_materialization as prototype_lowering
from inertia.lowering.call_argument_shape import (
    CallerStackObject8616,
    CallsiteArgumentShapeDecision8616,
    LogicalArgumentShapeEvidence8616,
    LogicalArgumentShapeEvidenceSource8616,
    accounted_target_prototype_shape_evidence_8616,
    accounted_variadic_target_shape_evidence_8616,
    carry_forward_logical_call_argument_shape_8616,
    exact_call_return_pair_shape_evidence_8616,
    exact_caller_stack_object_for_word_pair_8616,
    exact_caller_stack_object_shape_evidence_8616,
    reconcile_materialized_call_argument_shape_8616,
)
from inertia.lowering.callee_argument_count_evidence import (
    CalleeArgumentCountEvidence8616,
    CalleeArgumentCountVerdict8616,
)
from inertia.lowering.callsite_prototype_declarations import (
    canonicalize_callsite_target_identities_8616,
    materialize_callsite_prototype_declarations_8616,
)


class _Codegen:
    def __init__(self) -> None:
        self._next_index = 0
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cfunc = None
        self._inertia_callsite_summaries = {}
        self._inertia_callsite_summary_inventory_8616 = {}
        self._inertia_callsite_prototype_decls = ()

    def next_idx(self, _kind: str) -> int:
        index = self._next_index
        self._next_index += 1
        return index
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


class _BytesMemory:
    def __init__(self, base: int, data: bytes) -> None:
        self.base = base
        self.data = data

    def load(self, addr: int, size: int) -> bytes:
        start = int(addr) - self.base
        return self.data[start : start + int(size)]


class _Functions:
    def __init__(self) -> None:
        self.raw = SimpleNamespace(addr=0x1075B, name="sub_1075b")
        self.canonical = SimpleNamespace(addr=0x10768, name="sub_10768")

    def function(self, *, addr: int, create: bool) -> object | None:
        assert create is False
        return {
            0x1075B: self.raw,
            0x10768: self.canonical,
        }.get(addr)


def _summary(callsite_addr: int, *, arg_count: int = 2) -> CallsiteSummary8616:
    return CallsiteSummary8616(
        callsite_addr=callsite_addr,
        target_addr=0x2000,
        return_addr=callsite_addr + 3,
        kind="direct_near",
        arg_count=arg_count,
        arg_widths=(2,) * arg_count,
        stack_cleanup=2 * arg_count,
        return_register="ax",
        return_used=True,
    )


def test_canonicalizes_padding_alias_call_to_typed_summary_target() -> None:
    codegen = _Codegen()
    functions = _Functions()
    project = SimpleNamespace(
        arch=Arch86_16(),
        loader=SimpleNamespace(
            memory=_BytesMemory(
                0x1075B,
                b"\x90" * 13 + b"\x55\x8b\xec",
            ),
        ),
        kb=SimpleNamespace(functions=functions),
    )
    call = CFunctionCall(
        "sub_1075b",
        functions.raw,
        [],
        tags={"ins_addr": 0x10C9E},
        codegen=codegen,
    )
    root = CStatements([call], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root, body=root)
    codegen._inertia_callsite_summaries = {
        id(call): replace(
            _summary(0x10C9E),
            target_addr=0x10768,
        ),
    }

    changed = canonicalize_callsite_target_identities_8616(project, codegen)

    assert changed is True
    assert call.callee_func is functions.canonical
    assert call.callee_target == "sub_10768"
    assert codegen._inertia_call_target_identity_stats_8616.raw_fact_count == 1
    assert codegen._inertia_call_target_identity_stats_8616.normalized_fact_count == 1
    assert codegen._inertia_call_target_identity_stats_8616.classified_fact_count == 1
    assert codegen._inertia_call_target_identity_stats_8616.materialized_count == 1
    assert codegen._inertia_call_target_identity_stats_8616.failure_count == 0

    functions.canonical.name = "clock"
    assert canonicalize_callsite_target_identities_8616(project, codegen) is True
    assert call.callee_func is functions.canonical
    assert call.callee_target == "clock"


def test_call_target_identity_refuses_nonpadding_target_mismatch() -> None:
    codegen = _Codegen()
    functions = _Functions()
    project = SimpleNamespace(
        arch=Arch86_16(),
        loader=SimpleNamespace(
            memory=_BytesMemory(
                0x1075B,
                b"\x55\x8b\xec",
            ),
        ),
        kb=SimpleNamespace(functions=functions),
    )
    call = CFunctionCall(
        "sub_1075b",
        functions.raw,
        [],
        tags={"ins_addr": 0x10C9E},
        codegen=codegen,
    )
    root = CStatements([call], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root, body=root)
    codegen._inertia_callsite_summaries = {
        id(call): replace(
            _summary(0x10C9E),
            target_addr=0x10768,
        ),
    }

    changed = canonicalize_callsite_target_identities_8616(project, codegen)

    assert changed is False
    assert call.callee_func is functions.raw
    assert call.callee_target == "sub_1075b"
    assert codegen._inertia_call_target_identity_stats_8616.failure_count == 1


def test_call_target_identity_uses_address_name_without_canonical_kb_function() -> None:
    codegen = _Codegen()
    functions = _Functions()

    class _RawOnlyFunctions:
        @staticmethod
        def function(*, addr: int, create: bool) -> object | None:
            assert create is False
            return functions.raw if addr == 0x1075B else None

    project = SimpleNamespace(
        arch=Arch86_16(),
        loader=SimpleNamespace(
            memory=_BytesMemory(
                0x1075B,
                b"\x90" * 13 + b"\x55\x8b\xec",
            ),
        ),
        kb=SimpleNamespace(functions=_RawOnlyFunctions()),
    )
    call = CFunctionCall(
        "sub_1075b",
        functions.raw,
        [],
        tags={"ins_addr": 0x10C9E},
        codegen=codegen,
    )
    root = CStatements([call], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root, body=root)
    codegen._inertia_callsite_summaries = {
        id(call): replace(
            _summary(0x10C9E),
            target_addr=0x10768,
        ),
    }

    changed = canonicalize_callsite_target_identities_8616(project, codegen)

    assert changed is True
    assert call.callee_func is None
    assert call.callee_target == "sub_10768"
    assert codegen._inertia_call_target_identity_stats_8616.materialized_count == 1
    assert codegen._inertia_call_target_identity_stats_8616.failure_count == 0


def test_call_target_identity_uses_exact_far_summary_over_offset_only_callee() -> None:
    codegen = _Codegen()
    offset_only = SimpleNamespace(addr=0x15D5, name="sub_15d5")

    class _OffsetOnlyFunctions:
        @staticmethod
        def function(*, addr: int, create: bool) -> object | None:
            assert create is False
            return offset_only if addr == 0x15D5 else None

    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(functions=_OffsetOnlyFunctions()),
        _inertia_original_linear_delta=0xF000,
    )
    call = CFunctionCall(
        "sub_15d5",
        offset_only,
        [],
        tags=Tags({"ins_addr": 0x1051}),
        codegen=codegen,
    )
    root = CStatements([call], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root, body=root)
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x10051,
            target_addr=0x1DE05,
            return_addr=0x10056,
            kind="direct_far",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register=None,
            return_used=False,
        )
    }

    changed = canonicalize_callsite_target_identities_8616(project, codegen)

    assert changed is True
    assert call.callee_func is None
    assert call.callee_target == "sub_1de05"
    assert codegen._inertia_call_target_identity_stats_8616.failure_count == 0


def test_call_target_identity_materializes_constant_register_call_branch() -> None:
    """A proven 16-bit constant AX branch becomes one linked near-call name."""
    codegen = _Codegen()

    class _NoFunctions:
        @staticmethod
        def function(*, addr: int, create: bool) -> object | None:
            assert create is False
            assert addr == 0x100BD
            return None

    project = SimpleNamespace(
        arch=Arch86_16(),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(linked_base=0x10000, max_addr=0xFFFF),
        ),
        kb=SimpleNamespace(functions=_NoFunctions()),
    )
    target = CConstant(
        0xBD,
        SimTypePointer(SimTypeShort(False)),
        codegen=codegen,
    )
    call = CFunctionCall(
        target,
        None,
        [],
        tags={"ins_addr": 0x10069},
        codegen=codegen,
    )
    root = CStatements([call], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root, body=root)
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x10069,
            target_addr=None,
            return_addr=0x1006B,
            kind=None,
            arg_count=0,
            arg_widths=(),
            stack_cleanup=None,
            return_register=None,
            return_used=False,
            return_shape="ax",
            target_source=("reg", "ax"),
        )
    }

    assert canonicalize_callsite_target_identities_8616(project, codegen) is True
    assert call.callee_func is None
    assert call.callee_target == "sub_100bd"
    stats = codegen._inertia_call_target_identity_stats_8616
    assert (
        stats.raw_fact_count,
        stats.normalized_fact_count,
        stats.classified_fact_count,
        stats.materialized_count,
        stats.failure_count,
    ) == (1, 1, 1, 1, 0)

    assert materialize_callsite_prototype_declarations_8616(project, codegen) is True
    assert codegen._inertia_callsite_prototype_decls == ("int sub_100bd(void);",)


def test_reconcile_call_shape_preserves_complete_binary_push_widths() -> None:
    summary = replace(
        _summary(0x1010),
        push_arg_sources=(("bp", 6), ("bp", -2)),
    )

    result = reconcile_materialized_call_argument_shape_8616(summary, (4, 4))

    assert result.summary is summary
    assert result.summary.arg_widths == (2, 2)
    assert result.decision is CallsiteArgumentShapeDecision8616.PRESERVED_COMPLETE_BINARY
    assert (
        result.raw_fact_count,
        result.normalized_fact_count,
        result.classified_fact_count,
        result.materialized_count,
        result.failure_count,
    ) == (2, 2, 1, 1, 0)


def test_reconcile_call_shape_records_proven_far_pointer_logical_width() -> None:
    summary = replace(
        _summary(0x1010),
        push_arg_sources=(("seg", "ss"), ("bp_addr", -112)),
    )

    result = reconcile_materialized_call_argument_shape_8616(summary, (2,))

    assert result.summary.arg_count == 2
    assert result.summary.arg_widths == (2, 2)
    assert result.summary.logical_arg_widths == (4,)
    assert result.summary.logical_arg_classes == (CallsiteArgumentClass8616.POINTER,)
    assert result.decision is CallsiteArgumentShapeDecision8616.MATERIALIZED_LOGICAL_FAR_POINTER
    assert result.failure_count == 0


def test_reconcile_call_shape_refuses_unproven_two_word_logical_width() -> None:
    summary = replace(
        _summary(0x1010),
        push_arg_sources=(("bp", 6), ("bp_addr", -112)),
    )

    result = reconcile_materialized_call_argument_shape_8616(summary, (2,))

    assert result.summary is summary
    assert result.summary.logical_arg_widths == ()
    assert result.decision is CallsiteArgumentShapeDecision8616.PRESERVED_COMPLETE_BINARY


def test_reconcile_call_shape_records_proven_two_dword_logical_widths() -> None:
    summary = replace(
        _summary(0x1010),
        arg_count=4,
        arg_widths=(2, 2, 2, 2),
        stack_cleanup=8,
        push_arg_sources=(("imm", 0), ("imm", 30), ("global", 0x134, 2), ("global", 0x132, 2)),
        logical_arg_widths=(2, 2, 2, 2),
        logical_arg_classes=(CallsiteArgumentClass8616.VALUE,) * 4,
    )
    evidence = LogicalArgumentShapeEvidence8616(
        widths=(4, 4),
        source=LogicalArgumentShapeEvidenceSource8616.ACCOUNTED_TARGET_PROTOTYPE,
    )

    result = reconcile_materialized_call_argument_shape_8616(
        summary,
        (4, 4),
        logical_evidence=evidence,
    )

    assert result.summary.arg_count == 4
    assert result.summary.arg_widths == (2, 2, 2, 2)
    assert result.summary.logical_arg_widths == (4, 4)
    assert result.summary.logical_arg_classes == ()
    assert result.decision is CallsiteArgumentShapeDecision8616.MATERIALIZED_PROVEN_LOGICAL_SHAPE
    assert (
        result.raw_fact_count,
        result.normalized_fact_count,
        result.classified_fact_count,
        result.materialized_count,
        result.failure_count,
    ) == (4, 4, 2, 1, 0)


def test_reconcile_call_shape_groups_exact_nested_dx_ax_return_argument() -> None:
    summary = replace(
        _summary(0x1010),
        arg_count=4,
        arg_widths=(2, 2, 2, 2),
        stack_cleanup=8,
        push_arg_sources=(
            ("ret_reg", 0x1008, "dx"),
            ("ret_reg", 0x1008, "ax"),
            ("imm", 0x16A),
            ("bp_addr", -18),
        ),
        logical_arg_widths=(2, 2, 2, 2),
        logical_arg_classes=(CallsiteArgumentClass8616.VALUE,) * 4,
    )

    evidence = exact_call_return_pair_shape_evidence_8616(summary)
    result = reconcile_materialized_call_argument_shape_8616(summary, (16, 4, 2))

    assert evidence == LogicalArgumentShapeEvidence8616(
        widths=(2, 2, 4),
        source=LogicalArgumentShapeEvidenceSource8616.EXACT_CALL_RETURN_PAIR,
        return_argument_indices=(2,),
    )
    assert result.summary.logical_arg_widths == (2, 2, 4)
    assert result.summary.logical_arg_classes == ()
    assert result.decision is CallsiteArgumentShapeDecision8616.MATERIALIZED_PROVEN_LOGICAL_SHAPE
    assert result.materialized_count == 1
    assert result.failure_count == 0


def test_reconcile_call_shape_refuses_unrelated_dx_ax_pushes() -> None:
    summary = replace(
        _summary(0x1010),
        arg_count=4,
        arg_widths=(2, 2, 2, 2),
        stack_cleanup=8,
        push_arg_sources=(
            ("ret_reg", 0x1006, "dx"),
            ("ret_reg", 0x1008, "ax"),
            ("imm", 0x16A),
            ("bp_addr", -18),
        ),
    )

    result = reconcile_materialized_call_argument_shape_8616(summary, (2, 2, 4))

    assert result.summary is summary
    assert result.decision is CallsiteArgumentShapeDecision8616.PRESERVED_COMPLETE_BINARY


def test_accounted_target_prototype_proves_nested_two_dword_shape() -> None:
    summary = replace(
        _summary(0x1010),
        arg_count=4,
        arg_widths=(2, 2, 2, 2),
        stack_cleanup=8,
        push_arg_sources=(("imm", 0), ("imm", 30), ("global", 0x134, 2), ("global", 0x132, 2)),
    )

    evidence = accounted_target_prototype_shape_evidence_8616(summary, (4, 4), (4, 4))

    assert evidence == LogicalArgumentShapeEvidence8616(
        widths=(4, 4),
        source=LogicalArgumentShapeEvidenceSource8616.ACCOUNTED_TARGET_PROTOTYPE,
    )


def test_accounted_variadic_target_proves_wide_suffix_from_complete_stack() -> None:
    summary = replace(
        _summary(0x1010),
        arg_count=4,
        arg_widths=(2, 2, 2, 2),
        stack_cleanup=8,
        push_arg_sources=(
            ("ret_reg", 0x1006, "dx"),
            ("ret_reg", 0x1006, "ax"),
            ("imm", 0x16A),
            ("bp_addr", -18),
        ),
    )

    evidence = accounted_variadic_target_shape_evidence_8616(
        summary,
        (2, 2, 4),
        (2, 2),
    )

    assert evidence == LogicalArgumentShapeEvidence8616(
        widths=(2, 2, 4),
        source=LogicalArgumentShapeEvidenceSource8616.ACCOUNTED_VARIADIC_TARGET_PROTOTYPE,
    )


def test_accounted_variadic_target_refuses_bad_prefix_or_incomplete_stack() -> None:
    summary = replace(
        _summary(0x1010),
        arg_count=4,
        arg_widths=(2, 2, 2, 2),
        stack_cleanup=8,
        push_arg_sources=(),
    )

    assert accounted_variadic_target_shape_evidence_8616(summary, (4, 2, 2), (2, 2)) is None
    incomplete = replace(summary, stack_cleanup=None)
    assert accounted_variadic_target_shape_evidence_8616(
        incomplete,
        (2, 2, 4),
        (2, 2),
    ) is None


def test_exact_caller_stack_object_groups_reversed_word_pushes() -> None:
    """Group adjacent high/low PUSH slices into one logical caller argument."""
    summary = replace(
        _summary(0x1010),
        arg_count=5,
        arg_widths=(2, 2, 2, 2, 2),
        stack_cleanup=10,
        push_arg_sources=(("bp", 8), ("bp", 6), ("imm", 1), ("imm", 0), ("bp", 4)),
    )

    evidence = exact_caller_stack_object_shape_evidence_8616(
        summary,
        (
            CallerStackObject8616(4, 2),
            CallerStackObject8616(6, 4),
            CallerStackObject8616(10, 2),
        ),
    )

    assert evidence == LogicalArgumentShapeEvidence8616(
        widths=(2, 2, 2, 4),
        source=LogicalArgumentShapeEvidenceSource8616.EXACT_CALLER_STACK_OBJECT,
    )


def test_carry_forward_logical_shape_requires_identical_physical_call_facts() -> None:
    fresh = replace(
        _summary(0x1010, arg_count=5),
        push_arg_sources=(("bp", 8), ("bp", 6), ("imm", 1), ("imm", 0), ("bp", 4)),
    )
    previous = replace(fresh, logical_arg_widths=(2, 2, 2, 4))

    carried = carry_forward_logical_call_argument_shape_8616(fresh, previous)

    assert carried.logical_arg_widths == (2, 2, 2, 4)
    changed_physical_facts = replace(fresh, push_arg_sources=(("bp", 10), *fresh.push_arg_sources[1:]))
    assert (
        carry_forward_logical_call_argument_shape_8616(changed_physical_facts, previous)
        is changed_physical_facts
    )
    assert changed_physical_facts.logical_arg_widths == ()


def test_exact_caller_stack_object_identifies_low_high_word_owner() -> None:
    """Bind a physical BP word pair to its exact widened caller object."""
    owner = exact_caller_stack_object_for_word_pair_8616(
        ("bp", 6),
        ("bp", 8),
        (
            CallerStackObject8616(4, 2),
            CallerStackObject8616(6, 4),
            CallerStackObject8616(10, 2),
        ),
    )

    assert owner == CallerStackObject8616(6, 4)


def test_accounted_target_prototype_refuses_unaccounted_nested_shape() -> None:
    summary = replace(
        _summary(0x1010),
        arg_count=4,
        arg_widths=(2, 2, 2, 2),
        stack_cleanup=8,
        push_arg_sources=(("imm", 0), ("imm", 30), ("global", 0x134, 2), ("global", 0x132, 2)),
    )

    assert accounted_target_prototype_shape_evidence_8616(summary, (4, 2), (4, 2)) is None
    assert accounted_target_prototype_shape_evidence_8616(summary, (4, 4), (2, 2, 2, 2)) is None


def test_reconcile_call_shape_refuses_contradictory_logical_evidence() -> None:
    summary = replace(
        _summary(0x1010),
        arg_count=4,
        arg_widths=(2, 2, 2, 2),
        stack_cleanup=8,
        push_arg_sources=(("imm", 0), ("imm", 30), ("global", 0x134, 2), ("global", 0x132, 2)),
    )
    evidence = LogicalArgumentShapeEvidence8616(
        widths=(4,),
        source=LogicalArgumentShapeEvidenceSource8616.ACCOUNTED_TARGET_PROTOTYPE,
    )

    result = reconcile_materialized_call_argument_shape_8616(
        summary,
        (4,),
        logical_evidence=evidence,
    )

    assert result.summary is summary
    assert result.decision is CallsiteArgumentShapeDecision8616.INVALID_LOGICAL_EVIDENCE
    assert result.materialized_count == 0
    assert result.failure_count == 1


def test_reconcile_call_shape_expands_incomplete_widths_from_exact_cleanup() -> None:
    summary = replace(
        _summary(0x1010),
        arg_count=1,
        arg_widths=(2,),
        push_arg_sources=(("bp", 6), ("bp", -2)),
    )

    result = reconcile_materialized_call_argument_shape_8616(summary, (2, 2))

    assert result.summary.arg_count == 2
    assert result.summary.arg_widths == (2, 2)
    assert result.decision is CallsiteArgumentShapeDecision8616.MATERIALIZED_LIVE_SHAPE
    assert result.failure_count == 0


def test_reconcile_call_shape_refuses_invalid_live_width() -> None:
    summary = _summary(0x1010)

    result = reconcile_materialized_call_argument_shape_8616(summary, (2, 0))

    assert result.summary is summary
    assert result.decision is CallsiteArgumentShapeDecision8616.INVALID_LIVE_SHAPE
    assert result.materialized_count == 0
    assert result.failure_count == 1


def test_materializes_function_pointer_argument_without_mutating_call() -> None:
    codegen = _Codegen()
    fn_type = SimTypePointer(SimTypeFunction([SimTypeShort(False)], SimTypeShort(False)))
    fn = CVariable(
        SimStackVariable(-2, 2, base="bp", name="fn"),
        variable_type=fn_type,
        codegen=codegen,
    )
    value = CVariable(
        SimStackVariable(6, 2, base="bp", name="value"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    call = CFunctionCall(
        "apply_twice",
        None,
        [fn, value],
        tags={"ins_addr": 0x1010},
        codegen=codegen,
    )
    root = CStatements([call], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root, body=root)
    codegen._inertia_callsite_summaries = {id(call): _summary(0x1010)}

    changed = materialize_callsite_prototype_declarations_8616(codegen.project, codegen)

    assert changed is True
    assert codegen._inertia_callsite_prototype_decls == (
        "unsigned short apply_twice(unsigned short (*a0)(unsigned short), unsigned short a1);",
    )
    assert codegen.cfunc._inertia_callsite_prototype_decls == codegen._inertia_callsite_prototype_decls
    assert root.statements == [call]
    assert call.callee_func is None


def test_materializes_array_argument_as_canonical_parameter_pointer() -> None:
    codegen = _Codegen()
    array = CVariable(
        SimStackVariable(-82, 80, base="bp", name="buffer"),
        variable_type=SimTypeFixedSizeArray(SimTypeChar(False), 80).with_arch(codegen.project.arch),
        codegen=codegen,
    )
    call = CFunctionCall(
        "fill",
        None,
        [array],
        tags={"ins_addr": 0x1010},
        codegen=codegen,
    )
    root = CStatements([call], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root, body=root)
    codegen._inertia_callsite_summaries = {id(call): _summary(0x1010, arg_count=1)}

    assert materialize_callsite_prototype_declarations_8616(codegen.project, codegen) is True
    assert codegen._inertia_callsite_prototype_decls == (
        "unsigned short fill(char *a0);",
    )


def test_materializes_one_logical_long_argument_from_two_word_pushes() -> None:
    codegen = _Codegen()
    wait = CVariable(
        SimStackVariable(-4, 4, base="bp", name="wait"),
        variable_type=SimTypeLong(False),
        codegen=codegen,
    )
    call = CFunctionCall(
        "sleep_ticks",
        None,
        [wait],
        tags={"ins_addr": 0x1010},
        codegen=codegen,
    )
    root = CStatements([call], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root, body=root)
    codegen._inertia_callsite_summaries = {
        id(call): replace(
            _summary(0x1010, arg_count=2),
            logical_arg_widths=(4,),
        )
    }

    assert materialize_callsite_prototype_declarations_8616(codegen.project, codegen) is True
    assert codegen._inertia_callsite_prototype_decls == (
        "unsigned short sleep_ticks(unsigned long a0);",
    )


def test_keeps_conservative_return_type_when_all_callers_ignore_result() -> None:
    codegen = _Codegen()
    wait = CVariable(
        SimStackVariable(-4, 4, base="bp", name="wait"),
        variable_type=SimTypeLong(False),
        codegen=codegen,
    )
    call = CFunctionCall(
        "sleep_ticks",
        None,
        [wait],
        tags={"ins_addr": 0x1010},
        codegen=codegen,
    )
    root = CStatements([call], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root, body=root)
    codegen._inertia_callsite_summaries = {
        id(call): replace(
            _summary(0x1010, arg_count=2),
            return_register=None,
            return_used=False,
            logical_arg_widths=(4,),
        )
    }
    record_caller_return_use_evidence_8616(
        codegen.project,
        0x2000,
        CallerReturnUseEvidence8616(
            target_addr=0x2000,
            verdict=CallerReturnUseVerdict8616.UNUSED,
            raw_fact_count=3,
            normalized_fact_count=3,
            classified_fact_count=3,
            materialized_count=3,
            failure_count=0,
            used_callsite_count=0,
            unused_callsite_count=3,
            callsite_addrs=(0x1010, 0x1020, 0x1030),
        ),
    )

    assert materialize_callsite_prototype_declarations_8616(codegen.project, codegen) is True
    assert codegen._inertia_callsite_prototype_decls == (
        "int sleep_ticks(unsigned long a0);",
    )


def test_internal_declaration_uses_whole_program_source_order_widths(monkeypatch) -> None:
    codegen = _Codegen()
    short_type = SimTypeShort(False).with_arch(codegen.project.arch)
    call = CFunctionCall(
        "mixed_widths",
        None,
        [
            CConstant(1, short_type, codegen=codegen),
            CConstant(2, short_type, codegen=codegen),
        ],
        tags={"ins_addr": 0x1010},
        codegen=codegen,
    )
    root = CStatements([call], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root, body=root)
    codegen._inertia_callsite_summaries = {
        id(call): replace(
            _summary(0x1010),
            arg_widths=(2, 4),
            stack_cleanup=6,
        )
    }
    monkeypatch.setattr(
        declaration_lowering,
        "collect_callee_argument_width_evidence_8616",
        lambda _project, _target: SimpleNamespace(
            raw_fact_count=2,
            closes_census=True,
            argument_widths=(4, 2),
            required_count_evidence=CalleeArgumentCountEvidence8616(
                target_addr=0x2000,
                verdict=CalleeArgumentCountVerdict8616.CONSISTENT,
                argument_count=2,
                raw_fact_count=2,
                normalized_fact_count=2,
                classified_fact_count=2,
                materialized_count=2,
            ),
        ),
    )

    assert materialize_callsite_prototype_declarations_8616(codegen.project, codegen) is True
    assert codegen._inertia_callsite_prototype_decls == (
        "unsigned short mixed_widths(unsigned long a0, unsigned short a1);",
    )


def test_incomplete_whole_program_caller_evidence_keeps_conservative_int() -> None:
    codegen = _Codegen()
    call = CFunctionCall("probe", None, [], tags={"ins_addr": 0x1010}, codegen=codegen)
    root = CStatements([call], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root, body=root)
    codegen._inertia_callsite_summaries = {
        id(call): replace(
            _summary(0x1010, arg_count=0),
            return_register=None,
            return_used=False,
        )
    }
    record_caller_return_use_evidence_8616(
        codegen.project,
        0x2000,
        CallerReturnUseEvidence8616(
            target_addr=0x2000,
            verdict=CallerReturnUseVerdict8616.UNKNOWN,
            raw_fact_count=2,
            normalized_fact_count=2,
            classified_fact_count=1,
            materialized_count=1,
            failure_count=1,
            used_callsite_count=0,
            unused_callsite_count=1,
            callsite_addrs=(0x1010, 0x1020),
        ),
    )

    assert materialize_callsite_prototype_declarations_8616(codegen.project, codegen) is True
    assert codegen._inertia_callsite_prototype_decls == ("int probe(void);",)


def test_materializes_struct_tag_forward_declaration_before_pointer_prototype() -> None:
    codegen = _Codegen()
    object_type = SimStruct({"field_0": SimTypeShort(False)}, name="recovered_object").with_arch(codegen.project.arch)
    object_value = CVariable(
        SimStackVariable(-4, 2, base="bp", name="object_pointer"),
        variable_type=object_type,
        codegen=codegen,
    )
    pointer = CUnaryOp("Reference", object_value, codegen=codegen)
    call = CFunctionCall(
        "fill_object",
        None,
        [pointer],
        tags={"ins_addr": 0x1010},
        codegen=codegen,
    )
    root = CStatements([call], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root, body=root)
    codegen._inertia_callsite_summaries = {id(call): _summary(0x1010, arg_count=1)}

    assert materialize_callsite_prototype_declarations_8616(codegen.project, codegen) is True
    assert codegen._inertia_callsite_prototype_decls == (
        "struct recovered_object;",
        "unsigned short fill_object(struct recovered_object *a0);",
    )
    pointer._type = None
    object_value.variable_type = None
    assert materialize_callsite_prototype_declarations_8616(codegen.project, codegen) is True
    assert codegen._inertia_callsite_prototype_decls[-1] == "unsigned short fill_object(void* a0);"


def test_struct_referent_type_replaces_stale_scalar_pointer_wrapper_type() -> None:
    codegen = _Codegen()
    object_type = SimStruct({"field_0": SimTypeShort(False)}, name="recovered_object").with_arch(codegen.project.arch)
    object_value = CVariable(
        SimStackVariable(-4, 2, base="bp", name="object_pointer"),
        variable_type=object_type,
        codegen=codegen,
    )
    pointer = CUnaryOp("Reference", object_value, codegen=codegen)
    pointer._type = SimTypePointer(SimTypeShort(False)).with_arch(codegen.project.arch)
    call = CFunctionCall(
        "fill_object",
        None,
        [pointer],
        tags={"ins_addr": 0x1010},
        codegen=codegen,
    )
    root = CStatements([call], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root, body=root)
    codegen._inertia_callsite_summaries = {id(call): _summary(0x1010, arg_count=1)}

    assert materialize_callsite_prototype_declarations_8616(codegen.project, codegen) is True
    assert codegen._inertia_callsite_prototype_decls == (
        "struct recovered_object;",
        "unsigned short fill_object(struct recovered_object *a0);",
    )


def test_struct_pointer_prototype_normalizes_registered_type_refs_to_tags() -> None:
    codegen = _Codegen()
    object_type = SimStruct({"field_0": SimTypeShort(False)}, name="recovered_object").with_arch(
        codegen.project.arch
    )
    direct = CVariable(
        SimStackVariable(-4, 2, base="bp", name="direct"),
        variable_type=object_type,
        codegen=codegen,
    )
    registered = CVariable(
        SimStackVariable(-6, 2, base="bp", name="registered"),
        variable_type=TypeRef("recovered_object", object_type),
        codegen=codegen,
    )
    call = CFunctionCall(
        "copy_object",
        None,
        [
            CUnaryOp("Reference", direct, codegen=codegen),
            CUnaryOp("Reference", registered, codegen=codegen),
        ],
        tags={"ins_addr": 0x1010},
        codegen=codegen,
    )
    root = CStatements([call], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root, body=root)
    codegen._inertia_callsite_summaries = {id(call): _summary(0x1010, arg_count=2)}

    assert materialize_callsite_prototype_declarations_8616(codegen.project, codegen) is True
    assert codegen._inertia_callsite_prototype_decls == (
        "struct recovered_object;",
        "unsigned short copy_object(struct recovered_object *a0, struct recovered_object *a1);",
    )


def test_runtime_abi_replaces_unproved_callsite_return_type() -> None:
    codegen = _Codegen()
    call = CFunctionCall(
        "rand",
        None,
        [],
        tags={"ins_addr": 0x1010},
        codegen=codegen,
    )
    root = CStatements([call], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root, body=root)
    codegen._inertia_callsite_summary_inventory_8616 = {0x1010: _summary(0x1010, arg_count=0)}

    assert materialize_callsite_prototype_declarations_8616(codegen.project, codegen) is True
    assert codegen._inertia_callsite_prototype_decls == ("int rand(void);",)


def test_portable_compiler_runtime_abi_replaces_callsite_width_inference() -> None:
    codegen = _Codegen()
    codegen.project._inertia_c_target = "portable-flat"
    dividend = CVariable(
        SimStackVariable(-4, 4, base="bp", name="dividend"),
        variable_type=SimTypeLong(False),
        codegen=codegen,
    )
    divisor = CVariable(
        SimStackVariable(-8, 4, base="bp", name="divisor"),
        variable_type=SimTypeLong(False),
        codegen=codegen,
    )
    call = CFunctionCall(
        "aNldiv",
        None,
        [dividend, divisor],
        tags={"ins_addr": 0x1010},
        codegen=codegen,
    )
    root = CStatements([call], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root, body=root)
    codegen._inertia_callsite_summaries = {
        id(call): replace(
            _summary(0x1010),
            arg_widths=(4, 4),
            logical_arg_widths=(4, 4),
            stack_cleanup=8,
        )
    }

    assert materialize_callsite_prototype_declarations_8616(codegen.project, codegen) is True
    assert codegen._inertia_callsite_prototype_decls == (
        "int32_t aNldiv(int32_t dividend, int32_t divisor);",
    )


def test_known_outtext_abi_replaces_incorrect_pointer_pointee_inference() -> None:
    codegen = _Codegen()
    text = CVariable(
        SimStackVariable(-4, 2, base="bp", name="text"),
        variable_type=SimTypePointer(SimTypeShort(False)),
        codegen=codegen,
    )
    call = CFunctionCall(
        "outtext",
        None,
        [text],
        tags={"ins_addr": 0x1010},
        codegen=codegen,
    )
    root = CStatements([call], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root, body=root)
    codegen._inertia_callsite_summaries = {id(call): _summary(0x1010, arg_count=1)}

    assert materialize_callsite_prototype_declarations_8616(codegen.project, codegen) is True
    assert codegen._inertia_callsite_prototype_decls == ("void outtext(char *a0);",)


def test_known_external_return_abi_survives_closed_unused_caller_evidence() -> None:
    codegen = _Codegen()
    buffer = CVariable(
        SimStackVariable(-82, 80, base="bp", name="buffer"),
        variable_type=SimTypeFixedSizeArray(SimTypeChar(False), 80).with_arch(codegen.project.arch),
        codegen=codegen,
    )
    value = CVariable(
        SimStackVariable(-84, 2, base="bp", name="value"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    count = CVariable(
        SimStackVariable(-86, 2, base="bp", name="count"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    call = CFunctionCall(
        "memset",
        None,
        [buffer, value, count],
        tags={"ins_addr": 0x1010},
        codegen=codegen,
    )
    root = CStatements([call], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root, body=root)
    codegen._inertia_callsite_summaries = {
        id(call): replace(
            _summary(0x1010, arg_count=3),
            return_register=None,
            return_used=False,
        )
    }
    record_caller_return_use_evidence_8616(
        codegen.project,
        0x2000,
        CallerReturnUseEvidence8616(
            target_addr=0x2000,
            verdict=CallerReturnUseVerdict8616.UNUSED,
            raw_fact_count=1,
            normalized_fact_count=1,
            classified_fact_count=1,
            materialized_count=1,
            failure_count=0,
            used_callsite_count=0,
            unused_callsite_count=1,
            callsite_addrs=(0x1010,),
        ),
    )

    assert materialize_callsite_prototype_declarations_8616(codegen.project, codegen) is True
    assert codegen._inertia_callsite_prototype_decls == (
        "void * memset(void *dst, int value, unsigned short count);",
    )


def test_getvideoconfig_return_abi_survives_closed_unused_caller_evidence() -> None:
    codegen = _Codegen()
    config_type = SimStruct(
        {"monitor": SimTypeShort(False)},
        name="video_config",
    ).with_arch(codegen.project.arch)
    config = CVariable(
        SimStackVariable(-4, 2, base="bp", name="config"),
        variable_type=SimTypePointer(config_type).with_arch(codegen.project.arch),
        codegen=codegen,
    )
    call = CFunctionCall(
        "getvideoconfig",
        None,
        [config],
        tags={"ins_addr": 0x1010},
        codegen=codegen,
    )
    root = CStatements([call], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root, body=root)
    codegen._inertia_callsite_summaries = {
        id(call): replace(
            _summary(0x1010, arg_count=1),
            return_register=None,
            return_used=False,
        )
    }
    record_caller_return_use_evidence_8616(
        codegen.project,
        0x2000,
        CallerReturnUseEvidence8616(
            target_addr=0x2000,
            verdict=CallerReturnUseVerdict8616.UNUSED,
            raw_fact_count=1,
            normalized_fact_count=1,
            classified_fact_count=1,
            materialized_count=1,
            failure_count=0,
            used_callsite_count=0,
            unused_callsite_count=1,
            callsite_addrs=(0x1010,),
        ),
    )

    assert materialize_callsite_prototype_declarations_8616(codegen.project, codegen) is True
    assert codegen._inertia_callsite_prototype_decls == (
        "struct video_config;",
        "unsigned short getvideoconfig(struct video_config *a0);",
    )


def test_known_external_abi_overrides_physical_word_argument_shape() -> None:
    codegen = _Codegen()
    codegen.project._inertia_c_target = "portable-flat"
    short_type = SimTypeShort(False).with_arch(codegen.project.arch)
    arguments = tuple(
        CConstant(value, short_type, codegen=codegen)
        for value in range(4)
    )
    setbkcolor = CFunctionCall(
        "setbkcolor",
        None,
        [arguments[0]],
        tags={"ins_addr": 0x1010},
        codegen=codegen,
    )
    sprintf = CFunctionCall(
        "sprintf",
        None,
        list(arguments[:3]),
        tags={"ins_addr": 0x1020},
        codegen=codegen,
    )
    root = CStatements([setbkcolor, sprintf], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root, body=root)
    codegen._inertia_callsite_summaries = {
        id(setbkcolor): _summary(0x1010, arg_count=2),
        id(sprintf): _summary(0x1020, arg_count=4),
    }

    assert materialize_callsite_prototype_declarations_8616(
        codegen.project,
        codegen,
    ) is True
    assert codegen._inertia_callsite_prototype_decls == (
        "int32_t setbkcolor(int32_t color);",
        "int sprintf(char *buf, const char *fmt, ...);",
    )


def test_rebinds_unique_stale_summary_by_callsite_address() -> None:
    codegen = _Codegen()
    first = CVariable(
        SimStackVariable(4, 2, base="bp", name="a"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    second = CVariable(
        SimStackVariable(6, 2, base="bp", name="b"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    call = CFunctionCall("combine", None, [first, second], tags={"ins_addr": 0x1010}, codegen=codegen)
    root = CStatements([call], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root, body=root)
    codegen._inertia_callsite_summaries = {0xDEADBEEF: _summary(0x1010)}

    assert materialize_callsite_prototype_declarations_8616(codegen.project, codegen) is True
    assert codegen._inertia_callsite_prototype_decls == (
        "unsigned short combine(unsigned short a0, unsigned short a1);",
    )


def test_rebinds_repeated_target_summaries_with_identical_typed_interface() -> None:
    codegen = _Codegen()
    codegen.project.kb = SimpleNamespace(
        functions=SimpleNamespace(
            function=lambda *, addr, create: (
                SimpleNamespace(addr=addr, name="render") if addr == 0x2000 and create is False else None
            )
        )
    )
    buffer = CVariable(
        SimStackVariable(-82, 80, base="bp", name="buffer"),
        variable_type=SimTypeFixedSizeArray(SimTypeChar(False), 80).with_arch(codegen.project.arch),
        codegen=codegen,
    )
    call = CFunctionCall("render", None, [buffer], tags={}, codegen=codegen)
    root = CStatements([call], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root, body=root)
    codegen._inertia_callsite_summaries = {
        1: _summary(0x1010, arg_count=1),
        2: _summary(0x1020, arg_count=1),
        3: _summary(0x1030, arg_count=1),
    }

    assert materialize_callsite_prototype_declarations_8616(codegen.project, codegen) is True
    assert codegen._inertia_callsite_prototype_decls == (
        "unsigned short render(char *a0);",
    )


def test_refuses_repeated_target_summaries_with_conflicting_typed_interfaces() -> None:
    codegen = _Codegen()
    codegen.project.kb = SimpleNamespace(
        functions=SimpleNamespace(
            function=lambda *, addr, create: (
                SimpleNamespace(addr=addr, name="combine") if addr == 0x2000 and create is False else None
            )
        )
    )
    argument = CVariable(
        SimStackVariable(4, 2, base="bp", name="a"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    call = CFunctionCall("combine", None, [argument], tags={}, codegen=codegen)
    root = CStatements([call], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root, body=root)
    codegen._inertia_callsite_summaries = {
        1: _summary(0x1010, arg_count=1),
        2: _summary(0x1020, arg_count=2),
    }
    codegen._inertia_callsite_prototype_decls = ("unsigned short existing(void);",)

    assert materialize_callsite_prototype_declarations_8616(codegen.project, codegen) is False
    assert codegen._inertia_callsite_prototype_decls == ("unsigned short existing(void);",)


def test_joins_used_ax_return_with_unused_callsites_for_same_target() -> None:
    codegen = _Codegen()
    first_argument = CVariable(
        SimStackVariable(4, 2, base="bp", name="a"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    second_argument = CVariable(
        SimStackVariable(4, 2, base="bp", name="a"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    first_call = CFunctionCall("render", None, [first_argument], tags={"ins_addr": 0x1010}, codegen=codegen)
    second_call = CFunctionCall("render", None, [second_argument], tags={"ins_addr": 0x1020}, codegen=codegen)
    root = CStatements([first_call, second_call], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root, body=root)
    codegen._inertia_callsite_summaries = {
        id(first_call): replace(
            _summary(0x1010, arg_count=1),
            return_register=None,
            return_used=False,
        ),
        id(second_call): _summary(0x1020, arg_count=1),
    }

    assert materialize_callsite_prototype_declarations_8616(codegen.project, codegen) is True
    assert codegen._inertia_callsite_prototype_decls == (
        "unsigned short render(unsigned short a0);",
    )


def test_refuses_conflicting_used_return_classes_for_same_target() -> None:
    codegen = _Codegen()
    first_argument = CVariable(
        SimStackVariable(4, 2, base="bp", name="a"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    second_argument = CVariable(
        SimStackVariable(4, 2, base="bp", name="a"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    first_call = CFunctionCall("render", None, [first_argument], tags={"ins_addr": 0x1010}, codegen=codegen)
    second_call = CFunctionCall("render", None, [second_argument], tags={"ins_addr": 0x1020}, codegen=codegen)
    root = CStatements([first_call, second_call], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root, body=root)
    codegen._inertia_callsite_summaries = {
        id(first_call): _summary(0x1010, arg_count=1),
        id(second_call): replace(
            _summary(0x1020, arg_count=1),
            return_register=None,
            return_shape="dx_ax",
        ),
    }

    assert materialize_callsite_prototype_declarations_8616(codegen.project, codegen) is False
    assert codegen._inertia_callsite_prototype_decls == ()


def test_replaces_stale_declaration_for_same_callee() -> None:
    """Current typed AST evidence replaces an earlier width approximation."""
    codegen = _Codegen()
    first = CVariable(
        SimStackVariable(4, 2, base="bp", name="a"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    call = CFunctionCall("combine", None, [first], tags={"ins_addr": 0x1010}, codegen=codegen)
    root = CStatements([call], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root, body=root)
    codegen._inertia_callsite_summaries = {id(call): _summary(0x1010, arg_count=1)}
    codegen._inertia_callsite_prototype_decls = ("unsigned short combine(unsigned long a0);",)

    assert materialize_callsite_prototype_declarations_8616(codegen.project, codegen) is True
    assert codegen._inertia_callsite_prototype_decls == ("unsigned short combine(unsigned short a0);",)


def test_named_target_removes_obsolete_numeric_declaration() -> None:
    """One typed target identity must not retain its earlier numeric projection."""
    codegen = _Codegen()
    argument = CVariable(
        SimStackVariable(4, 2, base="bp", name="row"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    call = CFunctionCall("DrawBar", None, [argument], tags={"ins_addr": 0x1010}, codegen=codegen)
    root = CStatements([call], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root, body=root)
    codegen._inertia_callsite_summaries = {id(call): _summary(0x1010, arg_count=1)}
    codegen._inertia_callsite_prototype_decls = (
        "unsigned short sub_2000(unsigned short a0);",
    )

    assert materialize_callsite_prototype_declarations_8616(codegen.project, codegen) is True
    assert codegen._inertia_callsite_prototype_decls == (
        "unsigned short DrawBar(unsigned short a0);",
    )


def test_conflicting_ast_argument_types_replace_stale_prototype_with_unprototyped_declaration() -> None:
    """One proven physical ABI must not retain a guessed logical argument type."""
    codegen = _Codegen()
    scalar = CVariable(
        SimStackVariable(4, 2, base="bp", name="offset"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    array = CVariable(
        SimStackVariable(-18, 16, base="bp", name="buffer"),
        variable_type=SimTypeFixedSizeArray(SimTypeChar(False), 16).with_arch(
            codegen.project.arch
        ),
        codegen=codegen,
    )
    scalar_call = CFunctionCall(
        "render",
        None,
        [scalar],
        tags={"ins_addr": 0x1010},
        codegen=codegen,
    )
    array_call = CFunctionCall(
        "render",
        None,
        [array],
        tags={"ins_addr": 0x1020},
        codegen=codegen,
    )
    root = CStatements([scalar_call, array_call], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root, body=root)
    codegen._inertia_callsite_summaries = {
        id(scalar_call): _summary(0x1010, arg_count=1),
        id(array_call): _summary(0x1020, arg_count=1),
    }
    codegen._inertia_callsite_prototype_decls = (
        "unsigned short render(unsigned short a0);",
    )

    assert materialize_callsite_prototype_declarations_8616(
        codegen.project,
        codegen,
    ) is True
    assert codegen._inertia_callsite_prototype_decls == (
        "unsigned short render();",
    )
    assert root.statements == [scalar_call, array_call]


def test_program_arity_conflict_materializes_unprototyped_declaration(monkeypatch) -> None:
    """Cross-caller binary arity conflict must not emit a local fixed prototype."""
    codegen = _Codegen()
    first = CVariable(
        SimStackVariable(4, 2, base="bp", name="a"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    call = CFunctionCall(
        "format_value",
        None,
        [first],
        tags={"ins_addr": 0x1010},
        codegen=codegen,
    )
    root = CStatements([call], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root, body=root)
    codegen._inertia_callsite_summaries = {id(call): _summary(0x1010, arg_count=1)}
    evidence = CalleeArgumentCountEvidence8616(
        target_addr=0x2000,
        verdict=CalleeArgumentCountVerdict8616.CONFLICT,
        raw_fact_count=2,
        normalized_fact_count=2,
        classified_fact_count=2,
        materialized_count=2,
        failure_count=1,
        callsite_addrs=(0x1010, 0x2010),
    )
    monkeypatch.setattr(
        declaration_lowering,
        "collect_callee_argument_width_evidence_8616",
        lambda _project, _target_addr: SimpleNamespace(
            raw_fact_count=2,
            closes_census=False,
            argument_widths=(),
            required_count_evidence=evidence,
        ),
    )

    assert materialize_callsite_prototype_declarations_8616(
        codegen.project,
        codegen,
    ) is True
    assert codegen._inertia_callsite_prototype_decls == (
        "unsigned short format_value();",
    )


def test_interface_finalizer_does_not_report_metadata_only_change(monkeypatch) -> None:
    """Declaration persistence alone must not activate semantic validation."""
    monkeypatch.setattr(
        prototype_lowering,
        "reconcile_exact_stack_argument_prototype_8616",
        lambda _project, _codegen: False,
    )
    monkeypatch.setattr(
        declaration_lowering,
        "materialize_callsite_prototype_declarations_8616",
        lambda _project, _codegen: True,
    )

    assert prototype_lowering.reconcile_callsite_interface_declarations_8616(object(), object()) is False
