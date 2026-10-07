"""Regress typed zero-argument call-return stores into stack locals."""

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CExpressionStatement,
    CFunctionCall,
    CStatements,
    CVariable,
)
from angr.sim_type import SimTypeChar, SimTypeShort
from angr.sim_variable import SimStackVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.semantics.callsite_argument_value_sources import (
    CallArgumentStackValueSource8616,
    call_argument_stack_value_source_8616,
)
from inertia.semantics.callsite_summary import (
    CallsiteReturnUseKind8616,
    CallsiteSummary8616,
    _push_arg_source_from_context,
)
from inertia.postprocess.decompiler_postprocess_calls import (
    _materialize_callsite_stack_arguments_8616,
)
from inertia.lowering.call_return_stack_stores import (
    ZeroArgCallReturnStackStoreEvidence8616,
    recover_zero_arg_call_return_stack_store_8616,
)
from inertia.lowering.real_mode_linear import (
    DirectStackMoveFact8616,
    DirectStackMoveSourceKind8616,
    _direct_stack_move_instruction_facts_8616,
    _same_stack_move_rhs_8616,
    _tree_has_zero_arg_call_return_assignment_8616,
)
from capstone.x86_const import (
    X86_INS_MOV,
    X86_OP_MEM,
    X86_OP_REG,
    X86_REG_AL,
    X86_REG_AX,
    X86_REG_BP,
    X86_REG_INVALID,
)


def _summary() -> CallsiteSummary8616:
    """Build one exact zero-argument AL-to-local return-store summary."""
    return CallsiteSummary8616(
        callsite_addr=0x4010,
        target_addr=0x5000,
        return_addr=0x4013,
        kind="direct_near",
        arg_count=0,
        arg_widths=(),
        stack_cleanup=None,
        return_register="ax",
        return_used=True,
        return_shape="ax",
        return_store_destination=("bp", -2),
        return_store_width=1,
        return_use_kind=CallsiteReturnUseKind8616.VALUE,
    )


def _recover(
    summary: CallsiteSummary8616,
) -> ZeroArgCallReturnStackStoreEvidence8616 | None:
    """Classify one summary against the exact byte-store instruction."""
    return recover_zero_arg_call_return_stack_store_8616(
        {summary.callsite_addr: summary},
        store_ins_addr=0x4013,
        dst_offset=-2,
        width=1,
        source_register_name="al",
    )


class _Codegen:
    """Minimal structured-C codegen boundary for call identity tests."""

    def __init__(self, project: object) -> None:
        """Initialize deterministic node indexing for structured-C fixtures."""
        self._idx = 0
        self.project = project
        self.cstyle_null_cmp = False

    def next_idx(self, _name: str) -> int:
        """Return the next deterministic structured-C node identifier."""
        self._idx += 1
        return self._idx
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def _zero_arg_fact() -> DirectStackMoveFact8616:
    """Build the Lowering fact corresponding to the typed summary fixture."""
    return DirectStackMoveFact8616(
        dst_offset=-2,
        width=1,
        source_kind=DirectStackMoveSourceKind8616.ZERO_ARG_CALL_RETURN,
        ins_addr=0x4013,
        source_call_target=0x5000,
        source_call_name="sub_5000",
        source_call_ins_addr=0x4010,
    )


@pytest.mark.parametrize("stack_cleanup", (None, 0))
def test_recovers_exact_zero_arg_call_return_stack_store(stack_cleanup: int | None) -> None:
    """Accept current and legacy zero-argument cleanup representations."""
    evidence = _recover(replace(_summary(), stack_cleanup=stack_cleanup))

    assert evidence is not None
    assert evidence.callsite_addr == 0x4010
    assert evidence.target_addr == 0x5000
    assert evidence.dst_offset == -2
    assert evidence.width == 1


@pytest.mark.parametrize(
    "summary",
    (
        replace(_summary(), return_store_destination=("bp", -4)),
        replace(_summary(), return_store_width=2),
        replace(_summary(), arg_count=1, arg_widths=(2,), stack_cleanup=2),
        replace(_summary(), stack_cleanup=2),
        replace(_summary(), return_use_kind=CallsiteReturnUseKind8616.CONDITION),
    ),
)
def test_refuses_inexact_call_return_stack_store(summary: CallsiteSummary8616) -> None:
    """Refuse mismatched storage, width, arguments, or return-use evidence."""
    assert _recover(summary) is None


def test_direct_stack_move_collector_emits_typed_call_return_fact() -> None:
    """Promote the exact callsite summary into the Lowering move-fact lane."""
    memory = SimpleNamespace(
        base=X86_REG_BP,
        index=X86_REG_INVALID,
        disp=-2,
    )
    destination = SimpleNamespace(type=X86_OP_MEM, size=1, mem=memory)
    source = SimpleNamespace(type=X86_OP_REG, size=1, reg=X86_REG_AL)
    store = SimpleNamespace(
        address=0x4013,
        id=X86_INS_MOV,
        operands=(destination, source),
    )

    class _Functions:
        """Minimal angr function-manager boundary for target naming."""

        def function(self, *, addr: int, create: bool) -> None:
            """Return no named callee so Lowering uses an address label."""
            del addr, create
            return None

    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(functions=_Functions(), labels={}),
    )
    function = SimpleNamespace(
        blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(store,))),),
    )
    summary = _summary()

    assert _direct_stack_move_instruction_facts_8616(project, function) == ()

    facts = _direct_stack_move_instruction_facts_8616(
        project,
        function,
        {summary.callsite_addr: summary},
    )

    assert len(facts) == 1
    fact = facts[0]
    assert fact.source_kind is DirectStackMoveSourceKind8616.ZERO_ARG_CALL_RETURN
    assert fact.dst_offset == -2
    assert fact.width == 1
    assert fact.source_call_ins_addr == 0x4010
    assert fact.source_call_target == 0x5000
    assert fact.source_call_name == "sub_5000"


def test_call_return_assignment_survives_resolved_target_identity_rewrite() -> None:
    """Recognize an exact materialized call when AST target metadata is enriched."""
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _Codegen(project)
    dst_var = SimStackVariable(-2, 1, base="bp", name="local_2", region=0x4000)
    dst_cvar = CVariable(
        dst_var,
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    resolved_call = CFunctionCall(
        "sub_5000",
        SimpleNamespace(name="sub_5000", addr=0x5000),
        [],
        codegen=codegen,
        tags={"ins_addr": 0x4010},
    )
    name_only_call = CFunctionCall(
        "sub_5000",
        None,
        [],
        codegen=codegen,
        tags={"ins_addr": 0x4010},
    )
    assignment = CAssignment(
        dst_cvar,
        resolved_call,
        codegen=codegen,
        tags={"ins_addr": 0x4010},
    )
    root = CStatements([assignment], codegen=codegen)

    assert not _same_stack_move_rhs_8616(resolved_call, name_only_call)
    assert _tree_has_zero_arg_call_return_assignment_8616(
        root,
        project,
        _zero_arg_fact(),
        dst_cvar,
    )


def test_call_return_assignment_refuses_wrong_callsite() -> None:
    """Do not accept a same-name call without the exact binary callsite tag."""
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _Codegen(project)
    dst_var = SimStackVariable(-2, 1, base="bp", name="local_2", region=0x4000)
    dst_cvar = CVariable(
        dst_var,
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    call = CFunctionCall(
        "sub_5000",
        None,
        [],
        codegen=codegen,
        tags={"ins_addr": 0x4020},
    )
    root = CStatements(
        [CAssignment(dst_cvar, call, codegen=codegen)],
        codegen=codegen,
    )

    assert not _tree_has_zero_arg_call_return_assignment_8616(
        root,
        project,
        _zero_arg_fact(),
        dst_cvar,
    )


def test_cbw_push_source_preserves_byte_stack_storage_width() -> None:
    """Keep AL's byte storage identity when CBW promotes it for a word PUSH."""
    register_names = {
        X86_REG_AL: "al",
        X86_REG_AX: "ax",
        X86_REG_BP: "bp",
    }

    def instruction(
        address: int,
        mnemonic: str,
        operands: tuple[object, ...],
    ) -> SimpleNamespace:
        """Build one minimal Capstone-backed instruction fixture."""
        return SimpleNamespace(
            address=address,
            mnemonic=mnemonic,
            insn=SimpleNamespace(
                operands=operands,
                reg_name=lambda register: register_names.get(register, ""),
            ),
        )

    memory = SimpleNamespace(base=X86_REG_BP, index=X86_REG_INVALID, disp=-2)
    instructions = (
        instruction(
            0x4000,
            "mov",
            (
                SimpleNamespace(type=X86_OP_REG, size=1, reg=X86_REG_AL),
                SimpleNamespace(type=X86_OP_MEM, size=1, mem=memory),
            ),
        ),
        instruction(0x4003, "cbw", ()),
        instruction(
            0x4004,
            "push",
            (SimpleNamespace(type=X86_OP_REG, size=2, reg=X86_REG_AX),),
        ),
    )

    assert _push_arg_source_from_context(
        SimpleNamespace(),
        instructions,
        2,
    ) == ("bp", -2, 1)


def test_normalizes_exact_stack_value_call_argument_source() -> None:
    """Expose structured BP value evidence to call-argument Lowering consumers."""
    assert call_argument_stack_value_source_8616(("bp", -2, 1)) == (
        CallArgumentStackValueSource8616(offset=-2, width=1)
    )


def test_exact_stack_value_width_replaces_stale_same_offset_call_argument() -> None:
    """Replace a stale word view when binary evidence proves a byte value."""
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _Codegen(project)
    stale_slot = SimStackVariable(-2, 2, base="bp", name="local_2", region=0x4000)
    stale_arg = CVariable(
        stale_slot,
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    byte_slot = SimStackVariable(-2, 1, base="bp", name="local_2", region=0x4000)
    byte_view = CVariable(
        byte_slot,
        variable_type=SimTypeChar(False),
        codegen=codegen,
    )
    call = CFunctionCall(
        "toupper",
        SimpleNamespace(name="toupper", addr=0x5000),
        [stale_arg],
        codegen=codegen,
    )
    root = CStatements(
        [CExpressionStatement(call, codegen=codegen)],
        addr=0x4000,
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        addr=0x4000,
        statements=root,
        body=root,
        variables_in_use={stale_slot: stale_arg, byte_slot: byte_view},
        unified_local_vars={
            stale_slot: {(stale_arg, stale_arg.variable_type)},
            byte_slot: {(byte_view, byte_view.variable_type)},
        },
    )
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4010,
            target_addr=0x5000,
            return_addr=0x4013,
            kind="direct_near",
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=2,
            return_register="ax",
            return_used=True,
            push_arg_sources=(("bp", -2, 1),),
        )
    }

    assert _materialize_callsite_stack_arguments_8616(project, codegen)
    assert len(call.args) == 1
    assert isinstance(call.args[0].variable, SimStackVariable)
    assert call.args[0].variable.offset == -2
    assert call.args[0].variable.size == 1


@pytest.mark.parametrize(
    "source",
    (
        ("bp", -2),
        ("bp", -2, 3),
        ("bp_addr", -2, 1),
        ("bp", True, 1),
        ("bp", -2, False),
    ),
)
def test_refuses_inexact_stack_value_call_argument_source(source: object) -> None:
    """Refuse missing, invalid, address, or boolean pseudo-width evidence."""
    assert call_argument_stack_value_source_8616(source) is None
