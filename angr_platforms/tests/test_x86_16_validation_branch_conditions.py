from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CDoWhileLoop,
    CFunctionCall,
    CIfElse,
    CStatements,
    CVariable,
)
from angr.sim_type import SimTypeInt, SimTypeShort
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16 import validation_branch_conditions
from angr_platforms.X86_16.callsite_summary import (
    CallsiteReturnUseKind8616,
    CallsiteSummary8616,
    bind_structured_callsite_identity_8616,
)
from angr_platforms.X86_16.ir.condition_ir import ConditionIR
from angr_platforms.X86_16.ir.core import (
    AddressStatus,
    IRAddress,
    IRBinaryValue,
    IRInstr,
    IRValue,
    MemSpace,
    SegmentOrigin,
)
from angr_platforms.X86_16.ir.function_ssa_registry import FunctionSSAArtifactVerdict8616
from angr_platforms.X86_16.ir.indexed_address_contracts import IndexedAddressDefinitionSite8616
from angr_platforms.X86_16.ir.logical_memory_contracts import IRMemoryAccessKind8616
from angr_platforms.X86_16.ir.logical_memory_register_transfer_contracts import (
    LogicalMemoryRegisterTransfer8616,
    LogicalMemoryRegisterTransferKind8616,
)
from angr_platforms.X86_16.ir.ssa import SSABlock
from angr_platforms.X86_16.lowering.semantic_cast import CSemanticCast8616
from angr_platforms.X86_16.tail_validation import (
    _canonicalize_final_branch_condition_fingerprint_8616,
)
from angr_platforms.X86_16.validation_branch_conditions import (
    BranchConditionIssueKind8616,
    validate_materialized_branch_conditions_8616,
)
from angr_platforms.X86_16.validation_condition_precision import (
    ConditionPrecisionEvidence8616,
)
from archinfo import ArchX86


class _Codegen:
    def __init__(self, condition: ConditionIR | None) -> None:
        self._next_index = 0
        self.project = SimpleNamespace(arch=ArchX86())
        self.cstyle_null_cmp = False
        self._inertia_typed_conditions = (
            (condition,) if condition is not None else ()
        )
        self._inertia_condition_precision_evidence_8616 = ()

    def next_idx(self, _kind: str) -> int:
        index = self._next_index
        self._next_index += 1
        return index
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def _fact() -> ConditionIR:
    local = IRValue(MemSpace.SS, name="bp", offset=-4, size=2)
    one = IRValue(MemSpace.CONST, const=1, size=2)
    argument = IRValue(MemSpace.SS, name="bp", offset=4, size=2)
    return ConditionIR(
        "sle",
        IRBinaryValue("add", local, one, size=2),
        argument,
        src_insn=0x4015,
        block_addr=0x4010,
        producer_insn=0x4012,
        taken_target=0x4020,
        fallthrough_target=0x4017,
    )


def _variable(codegen: _Codegen, offset: int, name: str) -> CVariable:
    return CVariable(
        SimStackVariable(offset, 2, base="bp", name=name),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )


def _root(codegen: _Codegen, *, keep_increment: bool) -> CStatements:
    local = _variable(codegen, -4, "local_4")
    argument = _variable(codegen, 4, "arg")
    lhs = (
        CBinaryOp(
            "Add",
            local,
            CConstant(1, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        )
        if keep_increment
        else local
    )
    condition = CBinaryOp(
        "CmpLE",
        lhs,
        argument,
        codegen=codegen,
        tags={
            "ins_addr": 0x4015,
            "vex_block_addr": 0x4010,
            "inertia_structuring_condition_cfg_materialized_8616": True,
        },
    )
    body = CStatements(
        [
            CAssignment(
                local,
                CConstant(2, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            )
        ],
        codegen=codegen,
    )
    return CStatements(
        [
            CIfElse(
                [(condition, body)],
                else_node=None,
                cstyle_ifs=True,
                codegen=codegen,
            )
        ],
        codegen=codegen,
    )


def _fingerprint(expression: object) -> str:
    if isinstance(expression, CBinaryOp):
        return (
            f"{expression.op}("
            f"{_fingerprint(expression.lhs)},"
            f"{_fingerprint(expression.rhs)})"
        )
    if isinstance(expression, CVariable):
        return f"var:{expression.variable.name}"
    if isinstance(expression, CConstant):
        return f"const:{expression.value}"
    if isinstance(expression, CSemanticCast8616):
        return f"SemanticCast({_fingerprint(expression.expr)})"
    raise TypeError(type(expression).__name__)


def _fact_fingerprint(_condition: ConditionIR) -> str:
    return "CmpLE(Add(var:local_4,const:1),var:arg)"


def test_materialized_branch_condition_accepts_exact_typed_predicate() -> None:
    codegen = _Codegen(_fact())

    report = validate_materialized_branch_conditions_8616(
        codegen,
        _root(codegen, keep_increment=True),
        condition_fingerprint=_fingerprint,
        condition_ir_fingerprint=_fact_fingerprint,
    )

    assert report.passed
    assert report.raw_fact_count == 1
    assert report.classified_fact_count == 1
    assert report.materialized_count == 1


@pytest.mark.parametrize("source_addr,block_addr,compare_addr,proven", [
    (0x108, 0x108, 0x108, True),
    (None, 0x108, 0x108, False),
    (0x108, None, 0x108, False),
    (0x108, 0x108, None, False),
])
def test_logical_reload_projection_requires_stable_path(monkeypatch, source_addr, block_addr, compare_addr, proven) -> None:
    """Validation consumes a dominating logical reload without string allowlists."""
    register = IRValue(MemSpace.REG, name="si", size=2, version=1)
    address = IRAddress(
        MemSpace.DS,
        base=("di",),
        offset=0x1805,
        size=2,
        status=AddressStatus.STABLE,
        segment_origin=SegmentOrigin.PROVEN,
        base_values=(IRValue(MemSpace.REG, name="di", size=2),),
    )
    site = IndexedAddressDefinitionSite8616(0x100, 0, 0x104, "MOV")
    access = SimpleNamespace(
        complete=True,
        kind=IRMemoryAccessKind8616.READ,
        address=address,
    )
    transfer = LogicalMemoryRegisterTransfer8616(
        LogicalMemoryRegisterTransferKind8616.RELOAD,
        access,
        register,
        site,
        (site,),
    )
    artifact = SimpleNamespace(
        function_addr=0x100,
        blocks=(
            SSABlock(0x100, (IRInstr("MOV", register, (), 2, 0x104),), (0x108,)),
            SSABlock(0x108, (IRInstr("CMP", None, (register,), 2, compare_addr),), ()),
        ),
        predecessor_map={0x100: (), 0x108: (0x100,)},
        logical_memory=SimpleNamespace(closed=True, accesses=(access,)),
    )
    codegen = _Codegen(None)
    codegen.cfunc = SimpleNamespace(addr=0x100)
    monkeypatch.setattr(
        validation_branch_conditions,
        "registered_function_ssa_artifact_8616",
        lambda *_args: SimpleNamespace(
            verdict=FunctionSSAArtifactVerdict8616.PROVEN,
            artifact=artifact,
        ),
    )
    trace_calls: list[object] = []

    def _trace_reloads(
        _artifact: object,
        accesses: tuple[object, ...],
    ) -> tuple[LogicalMemoryRegisterTransfer8616, ...]:
        trace_calls.extend(accesses)
        return tuple(transfer for _access in accesses)

    monkeypatch.setattr(
        validation_branch_conditions,
        "trace_logical_word_register_transfers_8616",
        _trace_reloads,
    )
    fact = ConditionIR(
        "eq",
        register,
        IRValue(MemSpace.CONST, const=0xFFFF, size=2),
        src_insn=source_addr,
        block_addr=block_addr,
    )

    context = validation_branch_conditions._build_logical_reload_validation_context_8616(codegen)
    projected = validation_branch_conditions._proven_logical_reload_condition_fingerprints_8616(
        codegen,
        fact,
        "CmpEQ(reg:si,const:65535)",
        None,
        context,
    )
    repeated = validation_branch_conditions._proven_logical_reload_condition_fingerprints_8616(
        codegen,
        fact,
        "CmpEQ(reg:si,const:65535)",
        None,
        context,
    )

    assert repeated == projected
    assert trace_calls == [access]
    expected = "CmpEQ(Dereference(Add(Mul(reg:ds,const:16),reg:di,const:6149)),const:65535)"
    assert (expected in projected) is proven
    if not proven:
        assert projected == frozenset()


def test_branch_validation_builds_one_logical_reload_context(monkeypatch) -> None:
    """Multiple register predicates share one function-wide reload index."""
    register = IRValue(MemSpace.REG, name="ax", size=2, version=1)
    facts = tuple(
        ConditionIR(
            "eq",
            register,
            IRValue(MemSpace.CONST, const=0, size=2),
            src_insn=jcc_addr,
            block_addr=block_addr,
        )
        for jcc_addr, block_addr in ((0x4015, 0x4010), (0x4025, 0x4020))
    )
    codegen = _Codegen(None)
    codegen._inertia_typed_conditions = facts
    codegen.cfunc = SimpleNamespace(addr=0x4000)
    conditions = tuple(
        CBinaryOp(
            "CmpEQ",
            _variable(codegen, -offset, "ax"),
            CConstant(0, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
            tags={
                "ins_addr": fact.src_insn,
                "vex_block_addr": fact.block_addr,
                "inertia_structuring_condition_cfg_materialized_8616": True,
            },
        )
        for offset, fact in enumerate(facts, start=1)
    )
    root = CStatements(
        [
            CIfElse(
                [(condition, CStatements([], codegen=codegen))],
                else_node=None,
                cstyle_ifs=True,
                codegen=codegen,
            )
            for condition in conditions
        ],
        codegen=codegen,
    )
    context_builds: list[object] = []

    def _build_context(active_codegen: object):
        context_builds.append(active_codegen)
        return validation_branch_conditions._empty_logical_reload_validation_context_8616()

    monkeypatch.setattr(
        validation_branch_conditions,
        "_build_logical_reload_validation_context_8616",
        _build_context,
    )

    report = validate_materialized_branch_conditions_8616(
        codegen,
        root,
        condition_fingerprint=_fingerprint,
        condition_ir_fingerprint=lambda _fact: "CmpEQ(var:ax,const:0)",
    )

    assert report.passed
    assert context_builds == [codegen]


def test_materialized_branch_condition_refuses_dropped_additive_operand() -> None:
    codegen = _Codegen(_fact())

    report = validate_materialized_branch_conditions_8616(
        codegen,
        _root(codegen, keep_increment=False),
        condition_fingerprint=_fingerprint,
        condition_ir_fingerprint=_fact_fingerprint,
    )

    assert not report.passed
    assert report.materialized_count == 0
    assert report.issues[0].kind is BranchConditionIssueKind8616.PREDICATE_MISMATCH
    assert report.issues[0].expected == _fact_fingerprint(_fact())
    assert report.issues[0].actual == "CmpLE(var:local_4,var:arg)"


def test_bound_loop_condition_refuses_wrong_stack_slot() -> None:
    """Validation must cover uniquely bound loops even before replacement."""
    codegen = _Codegen(_fact())
    condition = CBinaryOp(
        "CmpLE",
        _variable(codegen, -6, "local_6"),
        _variable(codegen, 4, "arg"),
        codegen=codegen,
        tags={
            "ins_addr": 0x4015,
            "vex_block_addr": 0x4010,
            "inertia_typed_loop_condition_bound_8616": True,
            "inertia_typed_loop_condition_key_8616": (0x4015, 0x4010),
        },
    )
    root = CStatements(
        [
            CDoWhileLoop(
                condition,
                CStatements([], codegen=codegen),
                codegen=codegen,
            )
        ],
        codegen=codegen,
    )

    report = validate_materialized_branch_conditions_8616(
        codegen,
        root,
        condition_fingerprint=_fingerprint,
        condition_ir_fingerprint=_fact_fingerprint,
    )

    assert not report.passed
    assert report.issues[0].kind is BranchConditionIssueKind8616.PREDICATE_MISMATCH
    assert report.issues[0].actual == "CmpLE(var:local_6,var:arg)"


def _semantic_cast_loop_root(
    codegen: _Codegen,
    *,
    destination_type: SimTypeShort | SimTypeInt,
) -> CStatements:
    """Build one fallthrough-oriented loop condition with explicit value views."""
    source_type = SimTypeShort(False)

    def _view(offset: int, name: str) -> CSemanticCast8616:
        return CSemanticCast8616(
            source_type,
            destination_type,
            _variable(codegen, offset, name),
            codegen=codegen,
        )

    condition = CBinaryOp(
        "CmpGT",
        _view(-4, "local_4"),
        _view(4, "arg"),
        codegen=codegen,
        tags={
            "ins_addr": 0x4015,
            "vex_block_addr": 0x4010,
            "inertia_typed_loop_condition_bound_8616": True,
            "inertia_typed_loop_condition_key_8616": (0x4015, 0x4010),
            "inertia_typed_loop_continuation_edge_8616": "fallthrough",
        },
    )
    return CStatements(
        [CDoWhileLoop(condition, CStatements([], codegen=codegen), codegen=codegen)],
        codegen=codegen,
    )


def test_bound_loop_accepts_exact_signed_semantic_views() -> None:
    """Same-width signed views preserve a fallthrough-oriented typed compare."""
    fact = ConditionIR(
        "sle",
        IRValue(MemSpace.SS, name="bp", offset=-4, size=2),
        IRValue(MemSpace.SS, name="bp", offset=4, size=2),
        src_insn=0x4015,
        block_addr=0x4010,
    )
    codegen = _Codegen(fact)

    report = validate_materialized_branch_conditions_8616(
        codegen,
        _semantic_cast_loop_root(codegen, destination_type=SimTypeShort(True)),
        condition_fingerprint=_fingerprint,
        condition_ir_fingerprint=lambda _condition: "CmpLE(var:local_4,var:arg)",
    )

    assert report.passed
    assert report.materialized_count == 1


def test_bound_loop_refuses_wrong_semantic_view_signedness() -> None:
    """An unsigned destination view cannot satisfy a signed ConditionIR fact."""
    fact = ConditionIR(
        "sle",
        IRValue(MemSpace.SS, name="bp", offset=-4, size=2),
        IRValue(MemSpace.SS, name="bp", offset=4, size=2),
        src_insn=0x4015,
        block_addr=0x4010,
    )
    codegen = _Codegen(fact)

    report = validate_materialized_branch_conditions_8616(
        codegen,
        _semantic_cast_loop_root(codegen, destination_type=SimTypeShort(False)),
        condition_fingerprint=_fingerprint,
        condition_ir_fingerprint=lambda _condition: "CmpLE(var:local_4,var:arg)",
    )

    assert not report.passed
    assert report.issues[0].kind is BranchConditionIssueKind8616.PREDICATE_MISMATCH


def test_bound_loop_refuses_width_changing_semantic_view() -> None:
    """A widening cast changes the typed value domain and remains visible."""
    fact = ConditionIR(
        "sle",
        IRValue(MemSpace.SS, name="bp", offset=-4, size=2),
        IRValue(MemSpace.SS, name="bp", offset=4, size=2),
        src_insn=0x4015,
        block_addr=0x4010,
    )
    codegen = _Codegen(fact)

    report = validate_materialized_branch_conditions_8616(
        codegen,
        _semantic_cast_loop_root(codegen, destination_type=SimTypeInt(True)),
        condition_fingerprint=_fingerprint,
        condition_ir_fingerprint=lambda _condition: "CmpLE(var:local_4,var:arg)",
    )

    assert not report.passed
    assert report.issues[0].kind is BranchConditionIssueKind8616.PREDICATE_MISMATCH


def test_bound_do_while_condition_accepts_proven_terminal_induction_state() -> None:
    """A do-while JCC observes the exact affine update at the body tail."""
    codegen = _Codegen(_fact())
    local = _variable(codegen, -4, "local_4")
    condition = CBinaryOp(
        "CmpLE",
        CBinaryOp(
            "Add",
            _variable(codegen, -4, "local_4"),
            CConstant(1, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        _variable(codegen, 4, "arg"),
        codegen=codegen,
        tags={
            "ins_addr": 0x4015,
            "vex_block_addr": 0x4010,
            "inertia_typed_loop_condition_bound_8616": True,
            "inertia_typed_loop_condition_key_8616": (0x4015, 0x4010),
        },
    )
    iterator = CAssignment(
        local,
        CBinaryOp(
            "Add",
            _variable(codegen, -4, "local_4"),
            CConstant(1, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    root = CStatements(
        [
            CDoWhileLoop(
                condition,
                CStatements([iterator], codegen=codegen),
                codegen=codegen,
            )
        ],
        codegen=codegen,
    )

    report = validate_materialized_branch_conditions_8616(
        codegen,
        root,
        condition_fingerprint=_fingerprint,
        condition_ir_fingerprint=lambda _condition: (
            "CmpLE(Add(Add(var:local_4,const:1),const:1),var:arg)"
        ),
    )

    assert report.passed
    assert report.materialized_count == 1


@pytest.mark.parametrize("ir_fingerprint", ["CmpNE(reg:ax,const:0)", None])
@pytest.mark.parametrize("wrong_return_block", [False, True])
def test_materialized_branch_accepts_exact_bound_call_return_predicate(ir_fingerprint, wrong_return_block) -> None:
    """An exact callsite binding proves replacement of its AX zero test."""
    fact = ConditionIR(
        "ne",
        IRValue(MemSpace.REG, name="ax", offset=8, size=2),
        IRValue(MemSpace.CONST, const=0, size=2),
        src_insn=0x4015,
        block_addr=0x4010,
    )
    codegen = _Codegen(fact)
    callee = SimpleNamespace(addr=0x4000, name="sub_4000", prototype=None)
    call = CFunctionCall("sub_4000", callee, [], codegen=codegen)
    summary = CallsiteSummary8616(
        callsite_addr=0x400D,
        target_addr=0x4000,
        return_addr=0x4020 if wrong_return_block else 0x4010,
        kind="near",
        arg_count=0,
        arg_widths=(),
        stack_cleanup=0,
        return_register="ax",
        return_used=True,
        return_use_kind=CallsiteReturnUseKind8616.CONDITION,
    )
    bind_structured_callsite_identity_8616(call, summary)
    codegen._inertia_callsite_summaries = {id(call): summary}
    condition = CBinaryOp(
        "CmpNE",
        call,
        CConstant(0, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={
            "ins_addr": 0x4015,
            "vex_block_addr": 0x4010,
            "inertia_structuring_condition_cfg_materialized_8616": True,
        },
    )
    root = CStatements(
        [CIfElse([(condition, CStatements([], codegen=codegen))], codegen=codegen)],
        codegen=codegen,
    )

    report = validate_materialized_branch_conditions_8616(
        codegen,
        root,
        condition_fingerprint=lambda expression: (
            "CmpNE(call:addr:0x4000,const:0)" if expression is condition else _fingerprint(expression)
        ),
        condition_ir_fingerprint=lambda _condition: ir_fingerprint,
    )

    assert report.passed is not wrong_return_block
    assert report.materialized_count == (0 if wrong_return_block else 1)


def test_materialized_branch_accepts_bound_call_return_comparison_with_nonzero_constant() -> None:
    """A call replacing AX remains equivalent when the branch compares with one."""
    fact = ConditionIR(
        "ne",
        IRValue(MemSpace.REG, name="ax", offset=8, size=2),
        IRValue(MemSpace.CONST, const=1, size=2),
        src_insn=0x4015,
        block_addr=0x4010,
    )
    codegen = _Codegen(fact)
    callee = SimpleNamespace(addr=0x4000, name="sub_4000", prototype=None)
    call = CFunctionCall("sub_4000", callee, [], codegen=codegen)
    summary = CallsiteSummary8616(
        callsite_addr=0x400D,
        target_addr=0x4000,
        return_addr=0x4010,
        kind="near",
        arg_count=0,
        arg_widths=(),
        stack_cleanup=0,
        return_register="ax",
        return_used=True,
        return_use_kind=CallsiteReturnUseKind8616.CONDITION,
    )
    bind_structured_callsite_identity_8616(call, summary)
    codegen._inertia_callsite_summaries = {id(call): summary}
    condition = CBinaryOp(
        "CmpNE",
        call,
        CConstant(1, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={
            "ins_addr": 0x4015,
            "vex_block_addr": 0x4010,
            "inertia_structuring_condition_cfg_materialized_8616": True,
        },
    )
    root = CStatements(
        [CIfElse([(condition, CStatements([], codegen=codegen))], codegen=codegen)],
        codegen=codegen,
    )

    report = validate_materialized_branch_conditions_8616(
        codegen,
        root,
        condition_fingerprint=lambda expression: (
            "CmpNE(call:addr:0x4000,const:1)" if expression is condition else _fingerprint(expression)
        ),
        condition_ir_fingerprint=lambda _condition: "CmpNE(reg:ax,const:1)",
    )

    assert report.passed
    assert report.materialized_count == 1


def test_materialized_branch_condition_accepts_exact_jcc_precision_evidence() -> None:
    codegen = _Codegen(_fact())
    codegen._inertia_condition_precision_evidence_8616 = (
        ConditionPrecisionEvidence8616(
            "CmpLE(Add(var:local_4,const:1),var:arg)",
            "CmpLE(var:local_4,var:arg)",
            0x4015,
        ),
    )

    report = validate_materialized_branch_conditions_8616(
        codegen,
        _root(codegen, keep_increment=False),
        condition_fingerprint=_fingerprint,
        condition_ir_fingerprint=_fact_fingerprint,
    )

    assert report.passed
    assert report.materialized_count == 1


def test_materialized_branch_condition_refuses_wrong_jcc_precision_evidence() -> None:
    codegen = _Codegen(_fact())
    codegen._inertia_condition_precision_evidence_8616 = (
        ConditionPrecisionEvidence8616(
            "CmpLE(Add(var:local_4,const:1),var:arg)",
            "CmpLE(var:local_4,var:arg)",
            0x4016,
        ),
    )

    report = validate_materialized_branch_conditions_8616(
        codegen,
        _root(codegen, keep_increment=False),
        condition_fingerprint=_fingerprint,
        condition_ir_fingerprint=_fact_fingerprint,
    )

    assert not report.passed
    assert report.issues[0].kind is BranchConditionIssueKind8616.PREDICATE_MISMATCH


def test_materialized_branch_condition_refuses_missing_typed_fact() -> None:
    codegen = _Codegen(None)

    report = validate_materialized_branch_conditions_8616(
        codegen,
        _root(codegen, keep_increment=True),
        condition_fingerprint=_fingerprint,
        condition_ir_fingerprint=_fact_fingerprint,
    )

    assert not report.passed
    assert report.issues[0].kind is BranchConditionIssueKind8616.MISSING_FACT


def test_final_branch_condition_normalizes_proven_dword_storage_views() -> None:
    normalize = _canonicalize_final_branch_condition_fingerprint_8616

    assert normalize("And(ds_global:0x132,const:65535)") == "ds_global:0x132"
    assert normalize("Shr(ds_global:0x132,const:16)") == "ds_global:0x134"
    assert normalize("CmpEQ(Or(ds_global:0x134,ds_global:0x132),const:0)") == (
        "CmpEQ(ds_global:0x132,const:0)"
    )
    assert normalize(
        "CmpEQ(Or("
        "Dereference(Add(Mul(reg:ds,const:16),const:308)),"
        "Dereference(Add(Mul(reg:ds,const:16),const:306))"
        "),const:0)"
    ) == "CmpEQ(ds_global:0x132,const:0)"
