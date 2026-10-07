from __future__ import annotations

from types import SimpleNamespace

import networkx
import pytest
from angr import ailment
from angr.sim_type import SimTypeBottom, SimTypeFunction, SimTypeLong, SimTypePointer, SimTypeShort
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.semantics.callsite_summary import (
    CallerReturnUseVerdict8616,
    CallsitePushExprOp8616,
    CallsiteReturnShape8616,
    CallsiteReturnUseKind8616,
    CallsiteSummary8616,
    StructuredCallKind8616,
    _decode_linear_insns_at_8616,
    _logical_arg_interface_for_target_8616,
    _logical_arg_widths_for_target_8616,
    _return_shape_after_call,
    _return_use_after_call,
    bind_structured_callsite_identity_8616,
    callsite_summary_inventory_8616,
    collect_caller_return_use_evidence_8616,
    logical_argument_widths_from_callsite_8616,
    rebind_cloned_structured_callsite_identity_8616,
    structured_call_kind_8616,
    structured_callsite_target_addr_8616,
    summarize_x86_16_callsite,
)
from inertia.pipeline.errors import PipelineHardError
from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_OP_REG

from inertia.alias.callsite_stack_merge import CallsitePredecessorStackMerge8616
from inertia.lowering.analysis_helpers import CallTargetSeed, resolve_direct_call_target_from_block

MSC_ANCHKSTK_BYTES = bytes.fromhex("59 8b dc 2b d8 72 0a 3b 1e b6 00 72 04 8b e3 ff e1")


def test_follow_decode_refuses_unmapped_lazy_capstone_bytes() -> None:
    class UnmappedBlock:
        @property
        def capstone(self) -> object:
            raise KeyError(0x10BB)

    factory = SimpleNamespace(block=lambda *_args, **_kwargs: UnmappedBlock())
    function = SimpleNamespace(project=SimpleNamespace(factory=factory))

    assert _decode_linear_insns_at_8616(function, 0x10BB, limit=1) == ()


def test_structured_call_kind_separates_codegen_insert_from_machine_calls() -> None:
    intrinsic = SimpleNamespace(callee_target="_INSERT", callee_func=None)
    machine_call = SimpleNamespace(callee_target="sub_1234", callee_func=None)

    assert structured_call_kind_8616(intrinsic) is StructuredCallKind8616.CODEGEN_INSERT_INTRINSIC
    assert structured_call_kind_8616(machine_call) is StructuredCallKind8616.MACHINE_CALL


def _identity_summary(
    callsite_addr: int,
    *,
    target_addr: int = 0x5000,
) -> CallsiteSummary8616:
    """Build a minimal typed summary for structured identity tests."""
    return CallsiteSummary8616(
        callsite_addr,
        target_addr,
        callsite_addr + 3,
        "direct_near",
        0,
        (),
        0,
        None,
        False,
    )


def test_cloned_structured_callsite_rebind_requires_exact_inherited_identity() -> None:
    source = _identity_summary(0x4010)
    replacement = _identity_summary(0x4020)
    call = SimpleNamespace(tags={"ins_addr": source.callsite_addr, "block_addr": 0x4000})

    rebind_cloned_structured_callsite_identity_8616(call, source, replacement)

    assert call.tags == {
        "ins_addr": replacement.callsite_addr,
        "block_addr": 0x4000,
        "inertia_target_addr_8616": replacement.target_addr,
    }


def test_cloned_structured_callsite_rebind_refuses_unproven_source_tag() -> None:
    source = _identity_summary(0x4010)
    replacement = _identity_summary(0x4020)
    call = SimpleNamespace(tags={"ins_addr": 0x4008})

    with pytest.raises(PipelineHardError, match="proven source identity"):
        rebind_cloned_structured_callsite_identity_8616(call, source, replacement)


def test_cloned_structured_callsite_rebind_refuses_callee_change() -> None:
    source = _identity_summary(0x4010)
    replacement = _identity_summary(0x4020, target_addr=0x6000)
    call = SimpleNamespace(tags={"ins_addr": source.callsite_addr})

    with pytest.raises(PipelineHardError, match="cannot change typed callee identity"):
        rebind_cloned_structured_callsite_identity_8616(call, source, replacement)


def test_regular_structured_callsite_bind_still_refuses_conflict() -> None:
    summary = _identity_summary(0x4010)
    call = SimpleNamespace(tags={"ins_addr": 0x4020})

    with pytest.raises(PipelineHardError, match="identity conflicts"):
        bind_structured_callsite_identity_8616(call, summary)


def test_structured_callsite_identity_accepts_rust_backed_ail_tags() -> None:
    summary = _identity_summary(0x4010)
    call = ailment.Expr.Register(None, 0, 16, block_addr=0x4000)

    bind_structured_callsite_identity_8616(call, summary)

    assert call.tags["ins_addr"] == summary.callsite_addr
    assert structured_callsite_target_addr_8616(call) == summary.target_addr
    assert call.tags["block_addr"] == 0x4000


def test_callsite_summary_inventory_requires_matching_owned_key() -> None:
    summary = CallsiteSummary8616(
        0x4010,
        0x5000,
        0x4013,
        "direct_near",
        0,
        (),
        0,
        None,
        False,
    )
    owner = SimpleNamespace(_inertia_callsite_summary_inventory_8616={0x4011: summary})

    with pytest.raises(ValueError, match="key must match"):
        callsite_summary_inventory_8616(owner)


def test_logical_arg_widths_use_binary_seeded_callee_prototype() -> None:
    arch = Arch86_16()
    callee = SimpleNamespace(
        prototype=SimTypeFunction(
            [SimTypeLong()],
            SimTypeBottom(label="void"),
        ).with_arch(arch)
    )
    functions = SimpleNamespace(function=lambda *, addr, create=False: callee if addr == 0x5000 else None)
    function = SimpleNamespace(project=SimpleNamespace(kb=SimpleNamespace(functions=functions)))

    assert _logical_arg_widths_for_target_8616(function, 0x5000) == (4,)


def test_logical_arg_interface_refuses_classes_from_width_only_prototype() -> None:
    arch = Arch86_16()
    callee = SimpleNamespace(
        prototype=SimTypeFunction(
            [SimTypePointer(SimTypeLong()), SimTypeLong()],
            SimTypeBottom(label="void"),
        ).with_arch(arch)
    )
    functions = SimpleNamespace(function=lambda *, addr, create=False: callee if addr == 0x5000 else None)
    function = SimpleNamespace(project=SimpleNamespace(kb=SimpleNamespace(functions=functions)))

    widths, classes = _logical_arg_interface_for_target_8616(function, 0x5000)

    assert widths == (2, 4)
    assert classes == ()


def test_logical_arg_interface_prefers_binary_proven_rebased_prototype() -> None:
    arch = Arch86_16()
    guessed_words = SimpleNamespace(
        prototype=SimTypeFunction(
            [SimTypeShort(), SimTypeShort()],
            SimTypeBottom(label="void"),
        ).with_arch(arch),
        is_prototype_guessed=True,
    )
    proven_wide = SimpleNamespace(
        prototype=SimTypeFunction(
            [SimTypeLong()],
            SimTypeBottom(label="void"),
        ).with_arch(arch),
        is_prototype_guessed=False,
    )

    def lookup(*, addr: int, create: bool = False) -> object | None:
        del create
        return {
            0x10F18: guessed_words,
            0x10F38: proven_wide,
        }.get(addr)

    project = SimpleNamespace(
        kb=SimpleNamespace(functions=SimpleNamespace(function=lookup)),
        _inertia_original_linear_delta=-0x20,
    )
    function = SimpleNamespace(project=project)

    widths, classes = _logical_arg_interface_for_target_8616(function, 0x10F18)

    assert widths == (4,)
    assert classes == ()


def test_logical_argument_widths_reverse_one_push_per_argument() -> None:
    summary = CallsiteSummary8616(
        0x4010,
        0x5000,
        0x4013,
        "direct_near",
        2,
        (2, 4),
        6,
        None,
        False,
        push_arg_sources=(("bp", 6), ("bp_addr", -44)),
    )

    assert logical_argument_widths_from_callsite_8616(summary, expected_arg_count=2) == (4, 2)


def test_logical_argument_widths_refuse_multi_push_far_pointer() -> None:
    summary = CallsiteSummary8616(
        0x4010,
        0x5000,
        0x4013,
        "direct_near",
        2,
        (2, 2),
        4,
        None,
        False,
        push_arg_sources=(("seg", "ss"), ("bp_addr", -44)),
    )

    assert logical_argument_widths_from_callsite_8616(summary, expected_arg_count=1) is None


class _Operand:
    def __init__(
        self,
        *,
        reg: int | None = None,
        imm: int | None = None,
        size: int | None = None,
        mem: object | None = None,
        operand_type: int | None = None,
    ):
        self.reg = reg
        self.imm = imm
        self.size = size
        self.mem = mem
        if isinstance(operand_type, int):
            self.type = operand_type


class _Insn:
    def __init__(
        self,
        address: int,
        mnemonic: str,
        operands: list[_Operand] | None = None,
        reg_names: dict[int, str] | None = None,
        size: int | None = None,
    ):
        self.address = address
        self.mnemonic = mnemonic
        if isinstance(size, int):
            self.size = size
        for operand in operands or ():
            if not hasattr(operand, "type"):
                if getattr(operand, "mem", None) is not None:
                    operand.type = X86_OP_MEM
                elif isinstance(getattr(operand, "reg", None), int):
                    operand.type = X86_OP_REG
                elif isinstance(getattr(operand, "imm", None), int):
                    operand.type = X86_OP_IMM
                else:
                    operand.type = None
        self.insn = SimpleNamespace(operands=tuple(operands or ()), reg_name=lambda reg: (reg_names or {}).get(reg, ""))


def _function_with_block(insns):
    block = SimpleNamespace(capstone=SimpleNamespace(insns=tuple(insns)))
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        factory=SimpleNamespace(block=lambda addr, opt_level=0: block),
    )
    return SimpleNamespace(project=project)


class _Memory:
    def __init__(self, chunks: dict[int, bytes]):
        self._chunks = chunks

    def load(self, addr: int, size: int) -> bytes:
        for base, data in self._chunks.items():
            if base <= addr < base + len(data):
                offset = addr - base
                return data[offset : offset + size]
        raise KeyError(addr)


def _project_with_call_insn(
    insn,
    *,
    linked_base: int = 0x10000,
    max_addr: int = 0x1000,
    memory: _Memory | None = None,
):
    block = SimpleNamespace(capstone=SimpleNamespace(insns=(insn,)))
    return SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        factory=SimpleNamespace(block=lambda addr, opt_level=0: block),
        loader=SimpleNamespace(main_object=SimpleNamespace(linked_base=linked_base, max_addr=max_addr), memory=memory),
    )


def test_direct_call_target_preserves_project_linear_near_immediate():
    project = _project_with_call_insn(_Insn(0x10016, "call", [_Operand(imm=0x105D2)]))

    assert resolve_direct_call_target_from_block(project, 0x10016) == 0x105D2


def test_direct_call_target_rebases_unbased_near_immediate_with_image_evidence():
    project = _project_with_call_insn(_Insn(0x10016, "call", [_Operand(imm=0x05D2)]))

    assert resolve_direct_call_target_from_block(project, 0x10016) == 0x105D2


def test_direct_call_target_canonicalizes_padding_landing_to_frame_prologue():
    project = _project_with_call_insn(
        _Insn(0x10100, "call", [_Operand(imm=0x10CD4)]),
        memory=_Memory({0x10CD4: b"\x90" * 12 + b"\x55\x8b\xec\xb8\x06\x00"}),
    )

    assert resolve_direct_call_target_from_block(project, 0x10100) == 0x10CE0


def test_callsite_summary_reports_push_args_cleanup_and_return_use(monkeypatch):
    function = _function_with_block(
        [
            _Insn(0x1000, "push", [_Operand(imm=1, size=2)]),
            _Insn(0x1001, "push", [_Operand(imm=2, size=2)]),
            _Insn(0x1002, "call"),
            _Insn(0x1005, "add", [_Operand(reg=1), _Operand(imm=4)], reg_names={1: "sp"}),
            _Insn(0x1008, "test", [_Operand(reg=2), _Operand(reg=2)], reg_names={2: "ax"}),
        ]
    )
    monkeypatch.setattr(
        "inertia.semantics.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x1002, 0x1544, 0x1005, "direct_near")],
    )

    summary = summarize_x86_16_callsite(function, 0x1002)

    assert summary == CallsiteSummary8616(
        callsite_addr=0x1002,
        target_addr=0x1544,
        return_addr=0x1005,
        kind="direct_near",
        arg_count=2,
        arg_widths=(2, 2),
        stack_cleanup=4,
        return_register="ax",
        return_used=True,
        return_shape=CallsiteReturnShape8616.AX.value,
        stack_probe_helper=False,
        return_use_kind="condition",
        stack_cleanup_instruction_addr=0x1005,
    )


def test_callsite_summary_preserves_caller_clean_argument_pushes(monkeypatch):
    function = _function_with_block(
        [
            _Insn(0x1000, "push", [_Operand(imm=1, size=2)]),
            _Insn(0x1001, "push", [_Operand(imm=2, size=2)]),
            _Insn(0x1002, "push", [_Operand(imm=3, size=2)]),
            _Insn(0x1003, "call"),
        ]
    )
    callee = SimpleNamespace(returning=True)
    function.project.kb = SimpleNamespace(
        functions=SimpleNamespace(function=lambda *, addr, create=False: callee)
    )
    monkeypatch.setattr(
        "inertia.semantics.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x1003, 0x1544, 0x1006, "direct_near")],
    )
    monkeypatch.setattr(
        "inertia.semantics.callsite_summary._callee_stack_cleanup_bytes_8616",
        lambda *_args, **_kwargs: 0,
    )

    summary = summarize_x86_16_callsite(function, 0x1003)

    assert summary is not None
    assert summary.arg_count == 3
    assert summary.arg_widths == (2, 2, 2)
    assert summary.logical_arg_widths == ()
    assert summary.push_arg_instruction_addrs == (0x1000, 0x1001, 0x1002)


def test_callsite_summary_recovers_far_call_pushes_and_cleanup(monkeypatch):
    """Capstone ``lcall`` must enter the same evidence pipeline as ``call``."""
    function = _function_with_block(
        [
            _Insn(0x1000, "push", [_Operand(imm=1, size=2)]),
            _Insn(0x1001, "push", [_Operand(imm=2, size=2)]),
            _Insn(0x1002, "lcall", size=5),
            _Insn(0x1007, "add", [_Operand(reg=1), _Operand(imm=4)], reg_names={1: "sp"}),
        ]
    )
    monkeypatch.setattr(
        "inertia.semantics.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x1002, 0x11E6, 0x1007, "direct_far")],
    )

    summary = summarize_x86_16_callsite(function, 0x1002)

    assert summary.arg_count == 2
    assert summary.arg_widths == (2, 2)
    assert summary.stack_cleanup == 4
    assert summary.stack_cleanup_instruction_addr == 0x1007


def test_callsite_summary_classifies_inc_ax_jcc_as_return_condition(monkeypatch):
    function = _function_with_block(
        [
            _Insn(0x1000, "call"),
            _Insn(0x1003, "inc", [_Operand(reg=2, size=2)], reg_names={2: "ax"}),
            _Insn(0x1004, "jne", [_Operand(imm=0x1010)]),
        ]
    )
    monkeypatch.setattr(
        "inertia.semantics.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x1000, 0x1544, 0x1003, "direct_near")],
    )

    summary = summarize_x86_16_callsite(function, 0x1000)

    assert summary is not None
    assert summary.return_used is True
    assert summary.return_use_kind is CallsiteReturnUseKind8616.CONDITION


def test_callsite_summary_treats_previous_call_cleanup_as_return_arg_carrier(monkeypatch):
    function = _function_with_block(
        [
            _Insn(0x1000, "push", [_Operand(imm=0, size=2)]),
            _Insn(0x1001, "call"),
            _Insn(0x1004, "add", [_Operand(reg=1), _Operand(imm=2)], reg_names={1: "sp"}),
            _Insn(0x1007, "push", [_Operand(reg=2, size=2)], reg_names={2: "ax"}),
            _Insn(0x1008, "call"),
            _Insn(0x100B, "add", [_Operand(reg=1), _Operand(imm=2)], reg_names={1: "sp"}),
        ]
    )
    monkeypatch.setattr(
        "inertia.semantics.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [
            CallTargetSeed(0x1001, 0x2000, 0x1004, "direct_near"),
            CallTargetSeed(0x1008, 0x2004, 0x100B, "direct_near"),
        ],
    )

    summary = summarize_x86_16_callsite(function, 0x1008)

    assert summary is not None
    assert summary.arg_widths == (2,)
    assert summary.push_arg_sources == (("ret_reg", 0x1001, "ax"),)


def test_callsite_summary_returns_empty_shape_when_block_has_no_neighbors(monkeypatch):
    function = _function_with_block([_Insn(0x1002, "call")])
    monkeypatch.setattr(
        "inertia.semantics.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [],
    )

    summary = summarize_x86_16_callsite(function, 0x1002)

    assert summary == CallsiteSummary8616(
        callsite_addr=0x1002,
        target_addr=None,
        return_addr=None,
        kind=None,
        arg_count=0,
        arg_widths=(),
        stack_cleanup=None,
        return_register=None,
        return_used=False,
        stack_probe_helper=False,
    )


def test_callsite_summary_uses_containing_block_for_push_args_before_call(monkeypatch):
    insns = (
        _Insn(0x1009, "push", [_Operand(reg=3, size=2)], reg_names={3: "di"}),
        _Insn(0x100A, "push", [_Operand(reg=4, size=2)], reg_names={4: "si"}),
        _Insn(0x100B, "push", [_Operand(imm=4, size=2)]),
        _Insn(0x100E, "call"),
        _Insn(0x1011, "add", [_Operand(reg=1), _Operand(imm=2)], reg_names={1: "sp"}),
    )
    block = SimpleNamespace(capstone=SimpleNamespace(insns=insns))
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        factory=SimpleNamespace(block=lambda addr, opt_level=0: block),
    )
    function = SimpleNamespace(project=project, block_addrs_set={0x1009})
    monkeypatch.setattr(
        function,
        "get_call_sites",
        lambda: [0x100E],
        raising=False,
    )
    monkeypatch.setattr(
        "inertia.semantics.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x100E, 0x1544, 0x1011, "direct_near")],
    )

    summary = summarize_x86_16_callsite(function, 0x100E)

    assert summary == CallsiteSummary8616(
        callsite_addr=0x100E,
        target_addr=0x1544,
        return_addr=0x1011,
        kind="direct_near",
        arg_count=1,
        arg_widths=(2,),
        stack_cleanup=2,
        return_register=None,
        return_used=False,
        stack_probe_helper=False,
        stack_cleanup_instruction_addr=0x1011,
    )


def test_callsite_summary_excludes_push_pop_proven_callee_saved_frame_registers(monkeypatch):
    caller_insns = (
        _Insn(0x1000, "push", [_Operand(reg=1, size=2)], reg_names={1: "bp"}),
        _Insn(
            0x1001,
            "mov",
            [_Operand(reg=2, size=2), _Operand(reg=1, size=2)],
            reg_names={1: "bp", 2: "sp"},
        ),
        _Insn(0x1003, "mov", [_Operand(reg=3, size=2), _Operand(imm=4, size=2)], reg_names={3: "ax"}),
        _Insn(0x1006, "call", [_Operand(imm=0x1800, size=2)]),
        _Insn(0x1009, "push", [_Operand(reg=4, size=2)], reg_names={4: "di"}),
        _Insn(0x100A, "push", [_Operand(reg=5, size=2)], reg_names={5: "si"}),
        _Insn(0x100B, "call", [_Operand(imm=0x2000, size=2)]),
        _Insn(0x100E, "add", [_Operand(reg=3, size=2), _Operand(reg=6, size=2)], reg_names={3: "ax", 6: "cx"}),
        _Insn(0x1010, "pop", [_Operand(reg=5, size=2)], reg_names={5: "si"}),
        _Insn(0x1011, "pop", [_Operand(reg=4, size=2)], reg_names={4: "di"}),
        _Insn(
            0x1012,
            "mov",
            [_Operand(reg=2, size=2), _Operand(reg=1, size=2)],
            reg_names={1: "bp", 2: "sp"},
        ),
        _Insn(0x1014, "pop", [_Operand(reg=1, size=2)], reg_names={1: "bp"}),
        _Insn(0x1015, "ret"),
    )
    caller_block = SimpleNamespace(capstone=SimpleNamespace(insns=caller_insns))
    callee_block = SimpleNamespace(capstone=SimpleNamespace(insns=(_Insn(0x2000, "ret"),)))

    def block_for_addr(addr, **_kwargs):
        return callee_block if addr == 0x2000 else caller_block

    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        factory=SimpleNamespace(block=block_for_addr),
    )
    function = SimpleNamespace(
        project=project,
        blocks=(caller_block,),
        block_addrs_set={0x1000},
    )
    monkeypatch.setattr(
        "inertia.semantics.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [
            CallTargetSeed(0x1006, 0x1800, 0x1009, "direct_near"),
            CallTargetSeed(0x100B, 0x2000, 0x100E, "direct_near"),
        ],
    )

    summary = summarize_x86_16_callsite(function, 0x100B)

    assert summary is not None
    assert summary.arg_count == 0
    assert summary.arg_widths == ()
    assert summary.push_arg_sources == ()
    assert summary.push_arg_instruction_addrs == ()
    assert summary.stack_cleanup == 0


def test_callsite_summary_excludes_register_saves_around_far_return_calls(monkeypatch):
    """Far-call frame words and cross-call register saves are not C arguments."""
    reg_names = {1: "ds", 2: "dx", 3: "cs", 4: "ax"}
    caller_insns = (
        _Insn(0x1000, "push", [_Operand(reg=1, size=2)], reg_names=reg_names, size=1),
        _Insn(0x1001, "push", [_Operand(reg=2, size=2)], reg_names=reg_names, size=1),
        _Insn(0x1002, "push", [_Operand(reg=3, size=2)], reg_names=reg_names, size=1),
        _Insn(0x1003, "call", [_Operand(imm=0x2000, size=2)], size=3),
        _Insn(0x1006, "push", [_Operand(reg=3, size=2)], reg_names=reg_names, size=1),
        _Insn(0x1007, "call", [_Operand(imm=0x3000, size=2)], size=3),
        _Insn(0x100A, "pop", [_Operand(reg=2, size=2)], reg_names=reg_names, size=1),
        _Insn(0x100B, "mov", [_Operand(reg=4), _Operand(imm=1)], reg_names=reg_names, size=3),
        _Insn(0x100E, "pop", [_Operand(reg=1, size=2)], reg_names=reg_names, size=1),
        _Insn(0x100F, "stc", size=1),
        _Insn(0x1010, "retf", size=1),
    )
    caller_block = SimpleNamespace(capstone=SimpleNamespace(insns=caller_insns))
    far_return_blocks = {
        address: SimpleNamespace(
            capstone=SimpleNamespace(insns=(_Insn(address, "retf", size=1),))
        )
        for address in (0x2000, 0x3000)
    }

    def block_for_addr(addr, **_kwargs):
        return far_return_blocks.get(addr, caller_block)

    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        factory=SimpleNamespace(block=block_for_addr),
    )
    function = SimpleNamespace(
        project=project,
        blocks=(caller_block,),
        block_addrs_set={0x1000},
    )
    monkeypatch.setattr(
        "inertia.semantics.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [
            CallTargetSeed(0x1003, 0x2000, 0x1006, "direct_near")
        ],
    )

    summary = summarize_x86_16_callsite(function, 0x1003)

    assert summary is not None
    assert summary.arg_count == 0
    assert summary.arg_widths == ()
    assert summary.push_arg_sources == ()
    assert summary.push_arg_instruction_addrs == ()
    assert summary.stack_cleanup == 0


def test_callsite_summary_counts_pushes_separated_by_register_setup(monkeypatch):
    function = _function_with_block(
        [
            _Insn(0x1000, "push", [_Operand(imm=1, size=2)]),
            _Insn(0x1001, "mov", [_Operand(reg=2), _Operand(imm=0x61)], reg_names={2: "ax"}),
            _Insn(0x1004, "push", [_Operand(reg=2, size=2)], reg_names={2: "ax"}),
            _Insn(0x1005, "call"),
            _Insn(0x1008, "add", [_Operand(reg=1), _Operand(imm=4)], reg_names={1: "sp"}),
        ]
    )
    monkeypatch.setattr(
        "inertia.semantics.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x1005, 0x1544, 0x1008, "direct_near")],
    )

    summary = summarize_x86_16_callsite(function, 0x1005)

    assert summary == CallsiteSummary8616(
        callsite_addr=0x1005,
        target_addr=0x1544,
        return_addr=0x1008,
        kind="direct_near",
        arg_count=2,
        arg_widths=(2, 2),
        stack_cleanup=4,
        return_register=None,
        return_used=False,
        stack_probe_helper=False,
        stack_cleanup_instruction_addr=0x1008,
    )


def test_callsite_summary_counts_pushes_separated_by_register_arithmetic_chain(monkeypatch):
    function = _function_with_block(
        [
            _Insn(0x1000, "mov", [_Operand(reg=2), _Operand(imm=3)], reg_names={2: "ax"}),
            _Insn(0x1003, "shl", [_Operand(reg=2), _Operand(imm=1)], reg_names={2: "ax"}),
            _Insn(0x1005, "add", [_Operand(reg=2), _Operand(imm=0x0B4C)], reg_names={2: "ax"}),
            _Insn(0x1008, "push", [_Operand(reg=2, size=2)], reg_names={2: "ax"}),
            _Insn(0x1009, "mov", [_Operand(reg=2), _Operand(imm=5)], reg_names={2: "ax"}),
            _Insn(0x100C, "shl", [_Operand(reg=2), _Operand(imm=1)], reg_names={2: "ax"}),
            _Insn(0x100E, "add", [_Operand(reg=2), _Operand(imm=0x0B4C)], reg_names={2: "ax"}),
            _Insn(0x1011, "push", [_Operand(reg=2, size=2)], reg_names={2: "ax"}),
            _Insn(0x1012, "call"),
            _Insn(0x1015, "add", [_Operand(reg=1), _Operand(imm=4)], reg_names={1: "sp"}),
        ]
    )
    monkeypatch.setattr(
        "inertia.semantics.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x1012, 0x1544, 0x1015, "direct_near")],
    )

    summary = summarize_x86_16_callsite(function, 0x1012)

    assert summary == CallsiteSummary8616(
        callsite_addr=0x1012,
        target_addr=0x1544,
        return_addr=0x1015,
        kind="direct_near",
        arg_count=2,
        arg_widths=(2, 2),
        stack_cleanup=4,
        return_register=None,
        return_used=False,
        stack_probe_helper=False,
        stack_cleanup_instruction_addr=0x1015,
    )


def test_callsite_summary_refuses_nonpositive_caller_cleanup_identity(
    monkeypatch,
) -> None:
    function = _function_with_block(
        [
            _Insn(0x1002, "call"),
            _Insn(
                0x1005,
                "add",
                [_Operand(reg=1), _Operand(imm=0)],
                reg_names={1: "sp"},
            ),
        ]
    )
    monkeypatch.setattr(
        "inertia.semantics.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [
            CallTargetSeed(0x1002, 0x1544, 0x1005, "direct_near")
        ],
    )

    summary = summarize_x86_16_callsite(function, 0x1002)

    assert summary is not None
    assert summary.stack_cleanup is None
    assert summary.stack_cleanup_instruction_addr is None


def test_callsite_summary_recovers_zero_register_push_sources(monkeypatch):
    function = _function_with_block(
        [
            _Insn(0x1000, "sub", [_Operand(reg=2), _Operand(reg=2)], reg_names={2: "ax"}),
            _Insn(0x1002, "push", [_Operand(reg=2, size=2)], reg_names={2: "ax"}),
            _Insn(0x1003, "push", [_Operand(reg=2, size=2)], reg_names={2: "ax"}),
            _Insn(0x1004, "call"),
            _Insn(0x1007, "add", [_Operand(reg=1), _Operand(imm=4)], reg_names={1: "sp"}),
        ]
    )
    monkeypatch.setattr(
        "inertia.semantics.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x1004, 0x1544, 0x1007, "direct_far")],
    )

    summary = summarize_x86_16_callsite(function, 0x1004)

    assert summary is not None
    assert summary.arg_count == 2
    assert summary.arg_widths == (2, 2)
    assert summary.push_arg_sources == (("imm", 0), ("imm", 0))
    assert summary.push_arg_instruction_addrs == (0x1002, 0x1003)


def test_callsite_summary_recovers_zero_extended_byte_register_push_sources(monkeypatch):
    reg_names = {1: "sp", 2: "ax", 5: "bp", 6: "al", 7: "ah", 8: "cl"}
    function = _function_with_block(
        [
            _Insn(
                0x1000,
                "mov",
                [_Operand(reg=8), _Operand(mem=SimpleNamespace(base=5, index=0, disp=-2), size=1)],
                reg_names=reg_names,
            ),
            _Insn(
                0x1003,
                "shr",
                [_Operand(mem=SimpleNamespace(base=5, index=0, disp=-4), size=1), _Operand(reg=8)],
                reg_names=reg_names,
            ),
            _Insn(
                0x1006,
                "mov",
                [_Operand(reg=6), _Operand(mem=SimpleNamespace(base=5, index=0, disp=-4), size=1)],
                reg_names=reg_names,
            ),
            _Insn(0x1009, "sub", [_Operand(reg=7), _Operand(reg=7)], reg_names=reg_names),
            _Insn(0x100B, "push", [_Operand(reg=2, size=2)], reg_names=reg_names),
            _Insn(0x100C, "mov", [_Operand(reg=6), _Operand(reg=8)], reg_names=reg_names),
            _Insn(0x100E, "push", [_Operand(reg=2, size=2)], reg_names=reg_names),
            _Insn(0x100F, "mov", [_Operand(reg=2), _Operand(imm=0x7000)], reg_names=reg_names),
            _Insn(0x1012, "push", [_Operand(reg=2, size=2)], reg_names=reg_names),
            _Insn(0x1013, "call"),
            _Insn(0x1016, "add", [_Operand(reg=1), _Operand(imm=6)], reg_names=reg_names),
        ]
    )
    monkeypatch.setattr(
        "inertia.semantics.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x1013, 0x1544, 0x1016, "direct_near")],
    )

    summary = summarize_x86_16_callsite(function, 0x1013)

    assert summary.push_arg_sources == (
        ("expr", ("bp", -4, 1), ((CallsitePushExprOp8616.AND.value, 0xFF),)),
        ("expr", ("bp", -2, 1), ((CallsitePushExprOp8616.AND.value, 0xFF),)),
        ("imm", 0x7000),
    )
    assert summary.push_arg_instruction_addrs == (0x100B, 0x100E, 0x1012)


def test_callsite_summary_records_register_stack_source_add_push_expr(monkeypatch):
    function = _function_with_block(
        [
            _Insn(
                0x1000,
                "mov",
                [_Operand(reg=2), _Operand(mem=SimpleNamespace(base=5, index=0, disp=-4), size=2)],
                reg_names={1: "sp", 2: "ax", 5: "bp"},
            ),
            _Insn(
                0x1003,
                "add",
                [_Operand(reg=2), _Operand(mem=SimpleNamespace(base=5, index=0, disp=-2), size=2)],
                reg_names={1: "sp", 2: "ax", 5: "bp"},
            ),
            _Insn(0x1006, "push", [_Operand(reg=2, size=2)], reg_names={1: "sp", 2: "ax", 5: "bp"}),
            _Insn(
                0x1007,
                "push",
                [_Operand(mem=SimpleNamespace(base=5, index=0, disp=-4), size=2)],
                reg_names={1: "sp", 2: "ax", 5: "bp"},
            ),
            _Insn(0x1008, "call"),
            _Insn(0x100B, "add", [_Operand(reg=1), _Operand(imm=4)], reg_names={1: "sp"}),
        ]
    )
    monkeypatch.setattr(
        "inertia.semantics.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x1008, 0x1544, 0x100B, "direct_near")],
    )

    summary = summarize_x86_16_callsite(function, 0x1008)

    assert summary.arg_count == 2
    assert summary.arg_widths == (2, 2)
    assert summary.push_arg_sources == (
        (
            "expr",
            ("bp", -4, 2),
            ((CallsitePushExprOp8616.ADD_SOURCE.value, ("bp", -2, 2)),),
        ),
        ("bp", -4, 2),
    )
    assert summary.push_arg_instruction_addrs == (0x1006, 0x1007)


def test_callsite_summary_records_register_stack_source_or_push_expr(monkeypatch):
    reg_names = {1: "sp", 2: "ax", 5: "bp"}
    function = _function_with_block(
        [
            _Insn(
                0x1000,
                "mov",
                [_Operand(reg=2), _Operand(mem=SimpleNamespace(base=5, index=0, disp=-2), size=2)],
                reg_names=reg_names,
            ),
            _Insn(0x1003, "or", [_Operand(reg=2), _Operand(imm=3)], reg_names=reg_names),
            _Insn(0x1005, "push", [_Operand(reg=2, size=2)], reg_names=reg_names),
            _Insn(0x1006, "mov", [_Operand(reg=2), _Operand(imm=0x61)], reg_names=reg_names),
            _Insn(0x1009, "push", [_Operand(reg=2, size=2)], reg_names=reg_names),
            _Insn(0x100A, "call"),
            _Insn(0x100D, "add", [_Operand(reg=1), _Operand(imm=4)], reg_names=reg_names),
        ]
    )
    monkeypatch.setattr(
        "inertia.semantics.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x100A, 0x1544, 0x100D, "direct_near")],
    )

    summary = summarize_x86_16_callsite(function, 0x100A)

    assert summary.arg_count == 2
    assert summary.arg_widths == (2, 2)
    assert summary.push_arg_sources == (
        ("expr", ("bp", -2, 2), ((CallsitePushExprOp8616.OR.value, 3),)),
        ("imm", 0x61),
    )


def test_callsite_summary_records_signed_dx_ax_stack_push_sources(monkeypatch):
    reg_names = {1: "sp", 2: "ax", 3: "dx", 5: "bp"}
    function = _function_with_block(
        [
            _Insn(
                0x1000,
                "mov",
                [_Operand(reg=2), _Operand(mem=SimpleNamespace(base=5, index=0, disp=6), size=2)],
                reg_names=reg_names,
            ),
            _Insn(0x1003, "cdq", reg_names=reg_names),
            _Insn(0x1004, "push", [_Operand(reg=3, size=2)], reg_names=reg_names),
            _Insn(0x1005, "push", [_Operand(reg=2, size=2)], reg_names=reg_names),
            _Insn(0x1006, "call"),
            _Insn(0x1009, "add", [_Operand(reg=1), _Operand(imm=4)], reg_names=reg_names),
        ]
    )
    monkeypatch.setattr(
        "inertia.semantics.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x1006, 0x1544, 0x1009, "direct_near")],
    )

    summary = summarize_x86_16_callsite(function, 0x1006)

    assert summary.arg_count == 2
    assert summary.arg_widths == (2, 2)
    assert summary.push_arg_sources == (
        (
            "expr",
            ("bp", 6, 2),
            ((CallsitePushExprOp8616.SIGN_EXT_HI.value, 16),),
        ),
        ("bp", 6, 2),
    )


def test_callsite_summary_records_proven_imul_ax_memory_push_source(monkeypatch):
    function = _function_with_block(
        [
            _Insn(0x1000, "mov", [_Operand(reg=2), _Operand(imm=75)], reg_names={2: "ax"}),
            _Insn(0x1003, "push", [_Operand(reg=2, size=2)], reg_names={2: "ax"}),
            _Insn(0x1004, "mov", [_Operand(reg=2), _Operand(imm=60)], reg_names={2: "ax"}),
            _Insn(
                0x1007,
                "imul",
                [_Operand(mem=SimpleNamespace(base=5, index=0, disp=4), size=2)],
                reg_names={2: "ax", 5: "bp"},
            ),
            _Insn(0x100A, "push", [_Operand(reg=2, size=2)], reg_names={2: "ax"}),
            _Insn(0x100B, "call"),
            _Insn(0x100E, "add", [_Operand(reg=1), _Operand(imm=4)], reg_names={1: "sp"}),
        ]
    )
    monkeypatch.setattr(
        "inertia.semantics.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x100B, 0x1544, 0x100E, "direct_near")],
    )

    summary = summarize_x86_16_callsite(function, 0x100B)

    assert summary.arg_count == 2
    assert summary.arg_widths == (2, 2)
    assert summary.stack_cleanup == 4
    assert summary.push_arg_sources == (
        ("imm", 75),
        ("expr", ("bp", 4, 2), ((CallsitePushExprOp8616.MUL.value, 60),)),
    )


def test_callsite_summary_records_absolute_memory_push_source(monkeypatch):
    function = _function_with_block(
        [
            _Insn(
                0x1000,
                "push",
                [_Operand(mem=SimpleNamespace(base=0, index=0, disp=0x1234), size=2)],
                reg_names={1: "sp"},
            ),
            _Insn(0x1003, "call"),
            _Insn(0x1006, "add", [_Operand(reg=1), _Operand(imm=2)], reg_names={1: "sp"}),
        ]
    )
    monkeypatch.setattr(
        "inertia.semantics.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x1003, 0x1544, 0x1006, "direct_near")],
    )

    summary = summarize_x86_16_callsite(function, 0x1003)

    assert summary.arg_count == 1
    assert summary.arg_widths == (2,)
    assert summary.push_arg_sources == (("global", 0x1234, 2),)


def test_callsite_summary_records_ax_byte_indexed_global_push_source(monkeypatch):
    reg_names = {1: "sp", 2: "ax", 3: "bx", 5: "bp", 6: "al"}
    function = _function_with_block(
        [
            _Insn(
                0x1000,
                "mov",
                [_Operand(reg=3), _Operand(mem=SimpleNamespace(base=5, index=0, disp=4), size=2)],
                reg_names=reg_names,
            ),
            _Insn(0x1003, "shl", [_Operand(reg=3), _Operand(imm=1)], reg_names=reg_names),
            _Insn(
                0x1005,
                "mov",
                [_Operand(reg=6), _Operand(mem=SimpleNamespace(base=3, index=0, disp=0x0B4C), size=1)],
                reg_names=reg_names,
            ),
            _Insn(0x1009, "cwde"),
            _Insn(0x100A, "push", [_Operand(reg=2, size=2)], reg_names=reg_names),
            _Insn(0x100B, "call"),
            _Insn(0x100E, "add", [_Operand(reg=1), _Operand(imm=2)], reg_names=reg_names),
        ]
    )
    monkeypatch.setattr(
        "inertia.semantics.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x100B, 0x1544, 0x100E, "direct_near")],
    )

    summary = summarize_x86_16_callsite(function, 0x100B)

    assert summary.arg_count == 1
    assert summary.arg_widths == (2,)
    assert summary.push_arg_sources == (
        ("global_index", 0x0B4C, 1, ("bp", 4, 2), ((CallsitePushExprOp8616.SHL.value, 1),)),
    )


def test_callsite_summary_records_direct_indexed_global_memory_push_source(monkeypatch):
    reg_names = {1: "sp", 3: "bx", 5: "bp"}
    function = _function_with_block(
        [
            _Insn(
                0x1000,
                "mov",
                [_Operand(reg=3), _Operand(mem=SimpleNamespace(base=5, index=0, disp=-2), size=2)],
                reg_names=reg_names,
            ),
            _Insn(0x1003, "shl", [_Operand(reg=3), _Operand(imm=1)], reg_names=reg_names),
            _Insn(0x1005, "push", [_Operand(reg=0, size=2)], reg_names={0: "ds"}),
            _Insn(
                0x1006,
                "push",
                [_Operand(mem=SimpleNamespace(base=3, index=0, disp=0x00F4), size=2)],
                reg_names=reg_names,
            ),
            _Insn(0x100A, "call"),
            _Insn(0x100D, "add", [_Operand(reg=1), _Operand(imm=4)], reg_names=reg_names),
        ]
    )
    monkeypatch.setattr(
        "inertia.semantics.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x100A, 0x1544, 0x100D, "direct_near")],
    )

    summary = summarize_x86_16_callsite(function, 0x100A)

    assert summary.arg_count == 2
    assert summary.arg_widths == (2, 2)
    assert summary.push_arg_sources == (
        ("seg", "ds"),
        ("global_index", 0x00F4, 2, ("bp", -2, 2), ((CallsitePushExprOp8616.SHL.value, 1),)),
    )


def test_callsite_summary_records_segmented_indirect_argument_value(monkeypatch):
    reg_names = {1: "sp", 2: "ax", 3: "bx", 5: "bp"}
    function = _function_with_block(
        [
            _Insn(
                0x1000,
                "mov",
                [_Operand(reg=2), _Operand(mem=SimpleNamespace(base=5, index=0, disp=-2), size=2)],
                reg_names=reg_names,
            ),
            _Insn(0x1003, "shl", [_Operand(reg=2), _Operand(imm=1)], reg_names=reg_names),
            _Insn(
                0x1005,
                "mov",
                [_Operand(reg=3), _Operand(mem=SimpleNamespace(base=5, index=0, disp=6), size=2)],
                reg_names=reg_names,
            ),
            _Insn(0x1008, "add", [_Operand(reg=3), _Operand(reg=2)], reg_names=reg_names),
            _Insn(0x100A, "push", [_Operand(imm=0x68, size=2)], reg_names=reg_names),
            _Insn(
                0x100C,
                "push",
                [_Operand(mem=SimpleNamespace(base=3, index=0, disp=0), size=2)],
                reg_names=reg_names,
            ),
            _Insn(0x100E, "call"),
            _Insn(0x1011, "add", [_Operand(reg=1), _Operand(imm=4)], reg_names=reg_names),
        ]
    )
    monkeypatch.setattr(
        "inertia.semantics.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x100E, 0x1544, 0x1011, "direct_near")],
    )

    summary = summarize_x86_16_callsite(function, 0x100E)

    assert summary.arg_count == 2
    assert summary.arg_widths == (2, 2)
    assert summary.push_arg_sources == (
        ("imm", 0x68),
        (
            "seg_indirect",
            "ds",
            2,
            (
                    "expr",
                    ("bp", 6, 2),
                    (
                        (
                            CallsitePushExprOp8616.ADD_SOURCE.value,
                            ("expr", ("bp", -2, 2), ((CallsitePushExprOp8616.SHL.value, 1),)),
                        ),
                    ),
            ),
        ),
    )


def test_callsite_summary_prefers_linear_window_when_block_sources_are_unknown(monkeypatch):
    reg_names = {1: "sp", 2: "ax", 3: "dx", 5: "bp"}
    full_insns = (
        _Insn(0x1113, "mov", [_Operand(reg=2), _Operand(imm=30)], reg_names=reg_names),
        _Insn(0x1116, "mov", [_Operand(reg=3), _Operand(imm=0)], reg_names=reg_names),
        _Insn(0x1119, "push", [_Operand(reg=3, size=2)], reg_names=reg_names),
        _Insn(0x111A, "push", [_Operand(reg=2, size=2)], reg_names=reg_names),
        _Insn(
            0x111B, "push", [_Operand(mem=SimpleNamespace(base=0, index=0, disp=0x0134), size=2)], reg_names=reg_names
        ),
        _Insn(
            0x111F, "push", [_Operand(mem=SimpleNamespace(base=0, index=0, disp=0x0132), size=2)], reg_names=reg_names
        ),
        _Insn(0x1123, "call", [_Operand(imm=0x2000)], reg_names=reg_names),
        _Insn(0x1126, "push", [_Operand(reg=3, size=2)], reg_names=reg_names),
        _Insn(0x1127, "push", [_Operand(reg=2, size=2)], reg_names=reg_names),
        _Insn(0x1128, "mov", [_Operand(reg=2), _Operand(imm=0x016A)], reg_names=reg_names),
        _Insn(0x112B, "push", [_Operand(reg=2, size=2)], reg_names=reg_names),
        _Insn(
            0x112C,
            "lea",
            [_Operand(reg=2), _Operand(mem=SimpleNamespace(base=5, index=0, disp=-18), size=2)],
            reg_names=reg_names,
        ),
        _Insn(0x112F, "push", [_Operand(reg=2, size=2)], reg_names=reg_names),
        _Insn(0x1130, "call", [_Operand(imm=0x3000)], reg_names=reg_names),
        _Insn(0x1133, "add", [_Operand(reg=1), _Operand(imm=8)], reg_names=reg_names),
    )
    short_insns = full_insns[7:]
    full_block = SimpleNamespace(capstone=SimpleNamespace(insns=full_insns))
    short_block = SimpleNamespace(capstone=SimpleNamespace(insns=short_insns))

    def block(addr, **kwargs):
        if addr == 0x1126 and "size" not in kwargs:
            return short_block
        return full_block

    project = SimpleNamespace(arch=SimpleNamespace(name="86_16"), factory=SimpleNamespace(block=block))
    function = SimpleNamespace(project=project, addr=0x1113, block_addrs_set={0x1113, 0x1126})
    monkeypatch.setattr(
        "inertia.semantics.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x1130, 0x3000, 0x1133, "direct_near")],
    )

    summary = summarize_x86_16_callsite(function, 0x1130)

    assert summary.arg_count == 4
    assert summary.arg_widths == (2, 2, 2, 2)
    assert summary.push_arg_sources == (
        ("ret_reg", 0x1123, "dx"),
        ("ret_reg", 0x1123, "ax"),
        ("imm", 0x016A),
        ("bp_addr", -18),
    )


def test_callsite_summary_records_dx_ax_global_sub_borrow_push_sources(monkeypatch):
    reg_names = {1: "sp", 2: "ax", 3: "dx"}
    function = _function_with_block(
        [
            _Insn(
                0x1000,
                "mov",
                [_Operand(reg=2), _Operand(mem=SimpleNamespace(base=0, index=0, disp=0x132), size=2)],
                reg_names=reg_names,
            ),
            _Insn(
                0x1003,
                "mov",
                [_Operand(reg=3), _Operand(mem=SimpleNamespace(base=0, index=0, disp=0x134), size=2)],
                reg_names=reg_names,
            ),
            _Insn(0x1006, "sub", [_Operand(reg=2), _Operand(imm=75)], reg_names=reg_names),
            _Insn(0x1009, "sbb", [_Operand(reg=3), _Operand(imm=0)], reg_names=reg_names),
            _Insn(0x100C, "push", [_Operand(reg=3, size=2)], reg_names=reg_names),
            _Insn(0x100D, "push", [_Operand(reg=2, size=2)], reg_names=reg_names),
            _Insn(0x100E, "call"),
            _Insn(0x1011, "add", [_Operand(reg=1), _Operand(imm=4)], reg_names=reg_names),
        ]
    )
    monkeypatch.setattr(
        "inertia.semantics.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x100E, 0x1544, 0x1011, "direct_near")],
    )

    summary = summarize_x86_16_callsite(function, 0x100E)

    assert summary.arg_count == 2
    assert summary.arg_widths == (2, 2)
    assert summary.push_arg_sources == (
        ("expr", ("global", 0x134, 2), ((CallsitePushExprOp8616.SBB.value, 0),)),
        ("expr", ("global", 0x132, 2), ((CallsitePushExprOp8616.SUB.value, 75),)),
    )


def test_callsite_summary_does_not_treat_register_union_mem_as_global(monkeypatch):
    function = _function_with_block(
        [
            _Insn(0x1000, "mov", [_Operand(reg=2), _Operand(imm=15)], reg_names={1: "sp", 2: "ax"}),
            _Insn(
                0x1003,
                "push",
                [
                    _Operand(
                        reg=2,
                        size=2,
                        mem=SimpleNamespace(base=0, index=0, disp=0),
                        operand_type=X86_OP_REG,
                    )
                ],
                reg_names={1: "sp", 2: "ax"},
            ),
            _Insn(0x1004, "call"),
            _Insn(0x1007, "add", [_Operand(reg=1), _Operand(imm=2)], reg_names={1: "sp"}),
        ]
    )
    monkeypatch.setattr(
        "inertia.semantics.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x1004, 0x1544, 0x1007, "direct_near")],
    )

    summary = summarize_x86_16_callsite(function, 0x1004)

    assert summary.arg_count == 1
    assert summary.arg_widths == (2,)
    assert summary.push_arg_sources == (("imm", 15),)


def test_callsite_summary_records_forwarded_dx_ax_return_push_sources(monkeypatch):
    reg_names = {1: "sp", 2: "ax", 3: "dx", 5: "bp"}
    function = _function_with_block(
        [
            _Insn(0x1000, "push", [_Operand(imm=0x1111, size=2)], reg_names=reg_names),
            _Insn(0x1002, "push", [_Operand(imm=0x2222, size=2)], reg_names=reg_names),
            _Insn(0x1004, "call", [_Operand(imm=0x2000)], reg_names=reg_names),
            _Insn(0x1007, "push", [_Operand(reg=3, size=2)], reg_names=reg_names),
            _Insn(0x1008, "push", [_Operand(reg=2, size=2)], reg_names=reg_names),
            _Insn(0x1009, "push", [_Operand(imm=0x17D, size=2)], reg_names=reg_names),
            _Insn(
                0x100B,
                "lea",
                [_Operand(reg=2), _Operand(mem=SimpleNamespace(base=5, index=0, disp=-80), size=2)],
                reg_names=reg_names,
            ),
            _Insn(0x100E, "push", [_Operand(reg=2, size=2)], reg_names=reg_names),
            _Insn(0x100F, "call", [_Operand(imm=0x3000)], reg_names=reg_names),
            _Insn(0x1012, "add", [_Operand(reg=1), _Operand(imm=8)], reg_names=reg_names),
        ]
    )
    monkeypatch.setattr(
        "inertia.semantics.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [
            CallTargetSeed(0x1004, 0x2000, 0x1007, "direct_near"),
            CallTargetSeed(0x100F, 0x3000, 0x1012, "direct_near"),
        ],
    )

    summary = summarize_x86_16_callsite(function, 0x100F)
    source_summary = summarize_x86_16_callsite(function, 0x1004)

    assert source_summary.return_shape == "dx_ax"
    assert source_summary.return_used is True
    assert summary.arg_count == 4
    assert summary.arg_widths == (2, 2, 2, 2)
    assert summary.push_arg_sources == (
        ("ret_reg", 0x1004, "dx"),
        ("ret_reg", 0x1004, "ax"),
        ("imm", 0x17D),
        ("bp_addr", -80),
    )


def test_callsite_summary_resolves_return_carrier_through_dominating_stack_store(monkeypatch):
    reg_names = {1: "sp", 2: "ax", 5: "bp"}
    insns = [
        _Insn(0x1000, "call", [_Operand(imm=0x2000)], reg_names=reg_names, size=3),
        _Insn(0x1003, "add", [_Operand(reg=1), _Operand(imm=6)], reg_names=reg_names),
        _Insn(
            0x1006,
            "mov",
            [_Operand(mem=SimpleNamespace(base=5, index=0, segment=0, disp=-2), size=2), _Operand(reg=2, size=2)],
            reg_names=reg_names,
        ),
        _Insn(0x1009, "cmp", [_Operand(imm=0x7010), _Operand(imm=0)], reg_names=reg_names),
        _Insn(0x100C, "je", [_Operand(imm=0x1020)], reg_names=reg_names),
        _Insn(0x100E, "push", [_Operand(reg=2, size=2)], reg_names=reg_names),
        _Insn(0x100F, "push", [_Operand(mem=SimpleNamespace(base=5, index=0, disp=4), size=2)], reg_names=reg_names),
        _Insn(0x1012, "push", [_Operand(imm=0x7012, size=2)], reg_names=reg_names),
        _Insn(0x1015, "call", [_Operand(imm=0x3000)], reg_names=reg_names, size=3),
        _Insn(0x1018, "add", [_Operand(reg=1), _Operand(imm=6)], reg_names=reg_names),
    ]
    function = _function_with_block(insns)
    function.addr = 0x1000
    function.block_addrs_set = {0x1000, 0x1003, 0x100E, 0x1020}
    function.graph = networkx.DiGraph([(0x1000, 0x1003), (0x1003, 0x100E), (0x1003, 0x1020)])
    monkeypatch.setattr(
        "inertia.semantics.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [
            CallTargetSeed(0x1000, 0x2000, 0x1003, "direct_near"),
            CallTargetSeed(0x1015, 0x3000, 0x1018, "direct_near"),
        ],
    )

    summary = summarize_x86_16_callsite(function, 0x1015)

    assert summary.push_arg_sources == (("bp", -2, 2), ("bp", 4, 2), ("imm", 0x7012))


def test_callsite_summary_refuses_return_carrier_when_cfg_path_bypasses_producer(monkeypatch):
    reg_names = {1: "sp", 2: "ax", 5: "bp"}
    insns = [
        _Insn(0x1000, "call", [_Operand(imm=0x2000)], reg_names=reg_names, size=3),
        _Insn(0x1003, "add", [_Operand(reg=1), _Operand(imm=6)], reg_names=reg_names),
        _Insn(
            0x1006,
            "mov",
            [_Operand(mem=SimpleNamespace(base=5, index=0, segment=0, disp=-2), size=2), _Operand(reg=2, size=2)],
            reg_names=reg_names,
        ),
        _Insn(0x1009, "je", [_Operand(imm=0x100E)], reg_names=reg_names),
        _Insn(0x100E, "push", [_Operand(reg=2, size=2)], reg_names=reg_names),
        _Insn(0x100F, "call", [_Operand(imm=0x3000)], reg_names=reg_names, size=3),
        _Insn(0x1012, "add", [_Operand(reg=1), _Operand(imm=2)], reg_names=reg_names),
    ]
    function = _function_with_block(insns)
    function.addr = 0x0FF0
    function.block_addrs_set = {0x0FF0, 0x1000, 0x1003, 0x100E}
    function.graph = networkx.DiGraph(
        [(0x0FF0, 0x1000), (0x0FF0, 0x100E), (0x1000, 0x1003), (0x1003, 0x100E)]
    )
    monkeypatch.setattr(
        "inertia.semantics.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [
            CallTargetSeed(0x1000, 0x2000, 0x1003, "direct_near"),
            CallTargetSeed(0x100F, 0x3000, 0x1012, "direct_near"),
        ],
    )

    summary = summarize_x86_16_callsite(function, 0x100F)

    assert summary.push_arg_sources == (None,)


def test_callsite_summary_records_live_callee_saved_register_argument(monkeypatch):
    """An exact PUSH DI remains representable when no earlier definition is local."""
    reg_names = {1: "sp", 4: "di"}
    function = _function_with_block(
        [
            _Insn(0x1000, "push", [_Operand(reg=4, size=2)], reg_names=reg_names),
            _Insn(0x1001, "call", [_Operand(imm=0x3000)], reg_names=reg_names, size=3),
            _Insn(0x1004, "add", [_Operand(reg=1), _Operand(imm=2)], reg_names=reg_names),
        ]
    )
    monkeypatch.setattr(
        "inertia.semantics.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x1001, 0x3000, 0x1004, "direct_near")],
    )

    summary = summarize_x86_16_callsite(function, 0x1001)

    assert summary.push_arg_sources == (("reg", "di"),)
    assert summary.push_arg_instruction_addrs == (0x1000,)


@pytest.mark.parametrize(
    ("callee_ret_operands", "helper_name"),
    [((_Operand(imm=8),), None), ((), "aNldiv")],
)
def test_callsite_summary_keeps_outer_pushes_across_exact_nested_call(
    monkeypatch,
    callee_ret_operands,
    helper_name,
):
    reg_names = {1: "sp", 2: "ax", 3: "dx", 5: "bp"}
    insns = [
        _Insn(0x1000, "push", [_Operand(imm=0x1111, size=2)], reg_names=reg_names),
        _Insn(0x1002, "push", [_Operand(imm=0x2222, size=2)], reg_names=reg_names),
        _Insn(0x1004, "mov", [_Operand(reg=2), _Operand(imm=0x03E8)], reg_names=reg_names),
        _Insn(0x1007, "mov", [_Operand(reg=3), _Operand(imm=0)], reg_names=reg_names),
        _Insn(0x100A, "push", [_Operand(reg=3, size=2)], reg_names=reg_names),
        _Insn(0x100B, "push", [_Operand(reg=2, size=2)], reg_names=reg_names),
        _Insn(0x100C, "mov", [_Operand(reg=2), _Operand(imm=0x3333)], reg_names=reg_names),
        _Insn(0x100F, "mov", [_Operand(reg=3), _Operand(imm=0x4444)], reg_names=reg_names),
        _Insn(
            0x1010,
            "sub",
            [_Operand(reg=2), _Operand(mem=SimpleNamespace(base=0, index=0, disp=0x10))],
            reg_names=reg_names,
        ),
        _Insn(
            0x1011,
            "sbb",
            [_Operand(reg=3), _Operand(mem=SimpleNamespace(base=0, index=0, disp=0x12))],
            reg_names=reg_names,
        ),
        _Insn(0x1012, "push", [_Operand(reg=3, size=2)], reg_names=reg_names),
        _Insn(0x1013, "push", [_Operand(reg=2, size=2)], reg_names=reg_names),
        _Insn(0x1014, "call", [_Operand(imm=0x2000)], reg_names=reg_names),
        _Insn(0x1017, "push", [_Operand(reg=3, size=2)], reg_names=reg_names),
        _Insn(0x1018, "push", [_Operand(reg=2, size=2)], reg_names=reg_names),
        _Insn(0x1019, "push", [_Operand(imm=0x17D, size=2)], reg_names=reg_names),
        _Insn(
            0x101B,
            "lea",
            [_Operand(reg=2), _Operand(mem=SimpleNamespace(base=5, index=0, disp=-80), size=2)],
            reg_names=reg_names,
        ),
        _Insn(0x101E, "push", [_Operand(reg=2, size=2)], reg_names=reg_names),
        _Insn(0x101F, "call", [_Operand(imm=0x3000)], reg_names=reg_names),
        _Insn(0x1022, "add", [_Operand(reg=1), _Operand(imm=12)], reg_names=reg_names),
    ]
    main_block = SimpleNamespace(capstone=SimpleNamespace(insns=tuple(insns)))
    callee_block = SimpleNamespace(
        capstone=SimpleNamespace(insns=(_Insn(0x2000, "ret", list(callee_ret_operands), reg_names=reg_names),))
    )
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        factory=SimpleNamespace(block=lambda addr, **_kwargs: callee_block if addr == 0x2000 else main_block),
    )
    function = SimpleNamespace(project=project, addr=0x5000, block_addrs_set={0x1000})
    monkeypatch.setattr(
        "inertia.semantics.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x101F, 0x3000, 0x1022, "direct_near")],
    )
    if helper_name is not None:
        monkeypatch.setattr(
            "inertia.semantics.callsite_summary._lookup_target_name_8616",
            lambda _function, _target_addr: helper_name,
        )

    summary = summarize_x86_16_callsite(function, 0x101F)

    assert summary.arg_count == 6
    assert summary.arg_widths == (2, 2, 2, 2, 2, 2)
    assert summary.stack_cleanup == 12
    assert summary.push_arg_sources == (
        ("imm", 0x1111),
        ("imm", 0x2222),
        ("ret_reg", 0x1014, "dx"),
        ("ret_reg", 0x1014, "ax"),
        ("imm", 0x17D),
        ("bp_addr", -80),
    )
    assert summary.push_arg_instruction_addrs == (
        0x1000,
        0x1002,
        0x1017,
        0x1018,
        0x1019,
        0x101E,
    )


@pytest.mark.parametrize(
    ("callee_ret_operands", "helper_name", "expected_cleanup"),
    [((_Operand(imm=8),), None, 8), ((), "aNldiv", 0)],
)
def test_callsite_summary_bounds_inner_helper_from_callee_or_known_abi(
    monkeypatch,
    callee_ret_operands,
    helper_name,
    expected_cleanup,
):
    reg_names = {1: "sp", 2: "ax", 3: "dx"}
    insns = [
        _Insn(0x1000, "push", [_Operand(imm=0x1111, size=2)], reg_names=reg_names),
        _Insn(0x1002, "push", [_Operand(imm=0x2222, size=2)], reg_names=reg_names),
        _Insn(0x1004, "mov", [_Operand(reg=2), _Operand(imm=0x03E8)], reg_names=reg_names),
        _Insn(0x1007, "mov", [_Operand(reg=3), _Operand(imm=0)], reg_names=reg_names),
        _Insn(0x100A, "push", [_Operand(reg=3, size=2)], reg_names=reg_names),
        _Insn(0x100B, "push", [_Operand(reg=2, size=2)], reg_names=reg_names),
        _Insn(0x100C, "mov", [_Operand(reg=2), _Operand(imm=0x3333)], reg_names=reg_names),
        _Insn(0x100F, "mov", [_Operand(reg=3), _Operand(imm=0x4444)], reg_names=reg_names),
        _Insn(0x1012, "push", [_Operand(reg=3, size=2)], reg_names=reg_names),
        _Insn(0x1013, "push", [_Operand(reg=2, size=2)], reg_names=reg_names),
        _Insn(0x1014, "call", [_Operand(imm=0x2000)], reg_names=reg_names),
        _Insn(0x1017, "push", [_Operand(reg=3, size=2)], reg_names=reg_names),
        _Insn(0x1018, "push", [_Operand(reg=2, size=2)], reg_names=reg_names),
    ]
    main_block = SimpleNamespace(capstone=SimpleNamespace(insns=tuple(insns)))
    callee_block = SimpleNamespace(
        capstone=SimpleNamespace(insns=(_Insn(0x2000, "ret", list(callee_ret_operands), reg_names=reg_names),))
    )
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        factory=SimpleNamespace(block=lambda addr, **_kwargs: callee_block if addr == 0x2000 else main_block),
    )
    function = SimpleNamespace(project=project, addr=0x5000, block_addrs_set={0x1000})
    monkeypatch.setattr(
        "inertia.semantics.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x1014, 0x2000, 0x1017, "direct_near")],
    )
    if helper_name is not None:
        monkeypatch.setattr(
            "inertia.semantics.callsite_summary._lookup_target_name_8616",
            lambda _function, _target_addr: helper_name,
        )

    summary = summarize_x86_16_callsite(function, 0x1014)

    assert summary.arg_count == 4
    assert summary.arg_widths == (2, 2, 2, 2)
    assert summary.stack_cleanup == expected_cleanup
    assert summary.logical_arg_widths == ((4, 4) if helper_name is not None else ())
    assert ("imm", 0x1111) not in summary.push_arg_sources
    assert ("imm", 0x2222) not in summary.push_arg_sources


def test_callsite_summary_records_sbb_memory_source_for_32bit_global_sub(monkeypatch):
    reg_names = {1: "sp", 2: "ax", 3: "dx"}
    insns = [
        _Insn(0x1000, "mov", [_Operand(reg=2), _Operand(imm=0x03E8)], reg_names=reg_names),
        _Insn(0x1003, "mov", [_Operand(reg=3), _Operand(imm=0)], reg_names=reg_names),
        _Insn(0x1006, "push", [_Operand(reg=3, size=2)], reg_names=reg_names),
        _Insn(0x1007, "push", [_Operand(reg=2, size=2)], reg_names=reg_names),
        _Insn(
            0x1008,
            "mov",
            [_Operand(reg=2), _Operand(mem=SimpleNamespace(base=0, index=0, disp=0x0B48), size=2)],
            reg_names=reg_names,
        ),
        _Insn(
            0x100B,
            "mov",
            [_Operand(reg=3), _Operand(mem=SimpleNamespace(base=0, index=0, disp=0x0B4A), size=2)],
            reg_names=reg_names,
        ),
        _Insn(
            0x100E,
            "sub",
            [_Operand(reg=2), _Operand(mem=SimpleNamespace(base=0, index=0, disp=0x0BA6), size=2)],
            reg_names=reg_names,
        ),
        _Insn(
            0x1011,
            "sbb",
            [_Operand(reg=3), _Operand(mem=SimpleNamespace(base=0, index=0, disp=0x0BA8), size=2)],
            reg_names=reg_names,
        ),
        _Insn(0x1014, "push", [_Operand(reg=3, size=2)], reg_names=reg_names),
        _Insn(0x1015, "push", [_Operand(reg=2, size=2)], reg_names=reg_names),
        _Insn(0x1016, "call", [_Operand(imm=0x2000)], reg_names=reg_names),
    ]
    main_block = SimpleNamespace(capstone=SimpleNamespace(insns=tuple(insns)))
    callee_block = SimpleNamespace(
        capstone=SimpleNamespace(insns=(_Insn(0x2000, "ret", [_Operand(imm=8)], reg_names=reg_names),))
    )
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        factory=SimpleNamespace(block=lambda addr, **_kwargs: callee_block if addr == 0x2000 else main_block),
    )
    function = SimpleNamespace(project=project, addr=0x5000, block_addrs_set={0x1000})
    monkeypatch.setattr(
        "inertia.semantics.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x1016, 0x2000, 0x1019, "direct_near")],
    )

    summary = summarize_x86_16_callsite(function, 0x1016)

    assert summary.stack_cleanup == 8
    assert summary.push_arg_sources == (
        ("imm", 0),
        ("imm", 0x03E8),
        (
            "expr",
            ("global", 0x0B4A, 2),
            ((CallsitePushExprOp8616.SBB_SOURCE.value, ("global", 0x0BA8, 2)),),
        ),
        (
            "expr",
            ("global", 0x0B48, 2),
            ((CallsitePushExprOp8616.SUB_SOURCE.value, ("global", 0x0BA6, 2)),),
        ),
    )


def test_callsite_summary_records_register_dec_push_expr_source(monkeypatch):
    function = _function_with_block(
        [
            _Insn(
                0x1000,
                "mov",
                [_Operand(reg=2), _Operand(mem=SimpleNamespace(base=5, index=0, disp=-2), size=2)],
                reg_names={2: "ax", 5: "bp"},
            ),
            _Insn(0x1003, "dec", [_Operand(reg=2)], reg_names={2: "ax"}),
            _Insn(0x1004, "push", [_Operand(reg=2, size=2)], reg_names={2: "ax"}),
            _Insn(0x1005, "call"),
            _Insn(0x1008, "add", [_Operand(reg=1), _Operand(imm=2)], reg_names={1: "sp"}),
        ]
    )
    monkeypatch.setattr(
        "inertia.semantics.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x1005, 0x1544, 0x1008, "direct_near")],
    )

    summary = summarize_x86_16_callsite(function, 0x1005)

    assert summary.arg_count == 1
    assert summary.push_arg_sources == (("expr", ("bp", -2, 2), (("sub", 1),)),)


def test_callsite_summary_records_signed_half_distance_push_source(monkeypatch):
    function = _function_with_block(
        [
            _Insn(
                0x1000,
                "lea",
                [_Operand(reg=2), _Operand(mem=SimpleNamespace(base=5, index=0, disp=-10), size=2)],
                reg_names={2: "ax", 5: "bp"},
            ),
            _Insn(0x1003, "push", [_Operand(reg=2, size=2)], reg_names={2: "ax"}),
            _Insn(0x1004, "mov", [_Operand(reg=2), _Operand(imm=23)], reg_names={2: "ax"}),
            _Insn(0x1007, "push", [_Operand(reg=2, size=2)], reg_names={2: "ax"}),
            _Insn(
                0x1008,
                "mov",
                [_Operand(reg=2), _Operand(mem=SimpleNamespace(base=5, index=0, disp=-14), size=2)],
                reg_names={2: "ax", 3: "dx", 5: "bp"},
            ),
            _Insn(0x100B, "cdq", reg_names={2: "ax", 3: "dx"}),
            _Insn(0x100C, "sub", [_Operand(reg=2), _Operand(reg=3)], reg_names={2: "ax", 3: "dx"}),
            _Insn(0x100E, "sar", [_Operand(reg=2), _Operand(imm=1)], reg_names={2: "ax"}),
            _Insn(0x1010, "sub", [_Operand(reg=2), _Operand(imm=160)], reg_names={2: "ax"}),
            _Insn(0x1013, "neg", [_Operand(reg=2)], reg_names={2: "ax"}),
            _Insn(0x1015, "push", [_Operand(reg=2, size=2)], reg_names={2: "ax"}),
            _Insn(
                0x1016,
                "push",
                [_Operand(mem=SimpleNamespace(base=0, index=0, disp=0x7000), size=2)],
            ),
            _Insn(0x101A, "lcall", size=5),
            _Insn(0x101F, "add", [_Operand(reg=1), _Operand(imm=8)], reg_names={1: "sp"}),
        ]
    )
    monkeypatch.setattr(
        "inertia.semantics.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x101A, 0x1544, 0x101F, "direct_far")],
    )

    summary = summarize_x86_16_callsite(function, 0x101A)

    assert summary.push_arg_sources == (
        ("bp_addr", -10),
        ("imm", 23),
        (
            "expr",
            ("bp", -14, 2),
            (
                ("sub_source", ("expr", ("bp", -14, 2), (("sign_ext_hi", 16),))),
                ("sar", 1),
                ("sub", 160),
                ("neg", 0),
            ),
        ),
        ("global", 0x7000, 2),
    )
    assert summary.push_arg_instruction_addrs == (0x1003, 0x1007, 0x1015, 0x1016)


def test_callsite_summary_does_not_replace_predecessor_merge_with_linear_path(monkeypatch):
    function = _function_with_block(
        [
            _Insn(0x1000, "push", [_Operand(imm=7, size=2)]),
            _Insn(0x1001, "call"),
            _Insn(0x1004, "add", [_Operand(reg=1), _Operand(imm=4)], reg_names={1: "sp"}),
        ]
    )
    merge = CallsitePredecessorStackMerge8616(
        widths=(2,),
        sources=(None,),
        representative_instruction_addrs=(0x0FF0,),
        alternative_instruction_addrs=((0x0FF0, 0x0FF4),),
        raw_fact_count=2,
        normalized_fact_count=2,
        classified_fact_count=1,
        materialized_count=1,
        failure_count=0,
    )
    monkeypatch.setattr(
        "inertia.semantics.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x1001, 0x1544, 0x1004, "direct_near")],
    )
    monkeypatch.setattr(
        "inertia.semantics.callsite_summary._predecessor_stack_merge_8616",
        lambda _function, _callsite_addr, **_kwargs: merge,
    )
    monkeypatch.setattr(
        "inertia.semantics.callsite_summary._linear_window_insns_for_callsite_8616",
        lambda *_args, **_kwargs: pytest.fail("linear path must not replace a predecessor merge"),
    )

    summary = summarize_x86_16_callsite(function, 0x1001)

    assert summary.push_arg_sources == (None, ("imm", 7))
    assert summary.push_arg_instruction_addrs == (0x0FF0, 0x1000)
    assert summary.predecessor_stack_merge is merge


def test_callsite_summary_records_global_add_push_expr_source(monkeypatch):
    function = _function_with_block(
        [
            _Insn(
                0x1000,
                "mov",
                [_Operand(reg=2), _Operand(mem=SimpleNamespace(base=0, index=0, disp=0x0BAC), size=2)],
                reg_names={1: "sp", 2: "ax"},
            ),
            _Insn(0x1003, "add", [_Operand(reg=2), _Operand(imm=7)], reg_names={1: "sp", 2: "ax"}),
            _Insn(0x1004, "push", [_Operand(reg=2, size=2)], reg_names={1: "sp", 2: "ax"}),
            _Insn(0x1005, "push", [_Operand(imm=59, size=2)], reg_names={1: "sp", 2: "ax"}),
            _Insn(0x1006, "call"),
            _Insn(0x1009, "add", [_Operand(reg=1), _Operand(imm=4)], reg_names={1: "sp", 2: "ax"}),
        ]
    )
    monkeypatch.setattr(
        "inertia.semantics.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x1006, 0x1544, 0x1009, "direct_near")],
    )

    summary = summarize_x86_16_callsite(function, 0x1006)

    assert summary.arg_count == 2
    assert summary.arg_widths == (2, 2)
    assert summary.push_arg_sources == (("expr", ("global", 0x0BAC, 2), (("add", 7),)), ("imm", 59))


def test_callsite_summary_records_lea_bp_push_address_source(monkeypatch):
    function = _function_with_block(
        [
            _Insn(
                0x1000,
                "lea",
                [_Operand(reg=2), _Operand(mem=SimpleNamespace(base=5, index=0, disp=-44), size=2)],
                reg_names={2: "ax", 5: "bp"},
            ),
            _Insn(0x1003, "push", [_Operand(reg=2, size=2)], reg_names={2: "ax"}),
            _Insn(0x1004, "call"),
            _Insn(0x1007, "add", [_Operand(reg=1), _Operand(imm=2)], reg_names={1: "sp"}),
        ]
    )
    monkeypatch.setattr(
        "inertia.semantics.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x1004, 0x1544, 0x1007, "direct_near")],
    )

    summary = summarize_x86_16_callsite(function, 0x1004)

    assert summary.arg_count == 1
    assert summary.push_arg_sources == (("bp_addr", -44),)


def test_callsite_summary_records_lea_bp_index_push_address_source(monkeypatch):
    function = _function_with_block(
        [
            _Insn(
                0x1000,
                "lea",
                [_Operand(reg=2), _Operand(mem=SimpleNamespace(base=5, index=6, scale=1, disp=-44), size=2)],
                reg_names={2: "ax", 5: "bp", 6: "si"},
            ),
            _Insn(0x1003, "push", [_Operand(reg=2, size=2)], reg_names={2: "ax"}),
            _Insn(0x1004, "call"),
            _Insn(0x1007, "add", [_Operand(reg=1), _Operand(imm=2)], reg_names={1: "sp"}),
        ]
    )
    monkeypatch.setattr(
        "inertia.semantics.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x1004, 0x1544, 0x1007, "direct_near")],
    )

    summary = summarize_x86_16_callsite(function, 0x1004)

    assert summary.arg_count == 1
    assert summary.push_arg_sources == (("bp_index_addr", -44, "si", 1),)


def test_callsite_summary_keeps_prior_pushes_before_indexed_lea_setup(monkeypatch):
    function = _function_with_block(
        [
            _Insn(
                0x1000, "push", [_Operand(mem=SimpleNamespace(base=5, index=0, disp=-46), size=2)], reg_names={5: "bp"}
            ),
            _Insn(0x1003, "mov", [_Operand(reg=2), _Operand(imm=32)], reg_names={2: "ax"}),
            _Insn(0x1006, "push", [_Operand(reg=2, size=2)], reg_names={2: "ax"}),
            _Insn(
                0x1007,
                    "mov",
                    [_Operand(reg=3), _Operand(mem=SimpleNamespace(base=5, index=0, disp=4), size=2)],
                    reg_names={3: "bx", 5: "bp"},
            ),
            _Insn(0x100A, "shl", [_Operand(reg=3), _Operand(imm=1)], reg_names={3: "bx"}),
            _Insn(
                0x100C,
                "mov",
                [_Operand(reg=2), _Operand(mem=SimpleNamespace(base=3, index=0, disp=0xB4C))],
                reg_names={2: "ax", 3: "bx"},
            ),
            _Insn(0x100F, "cwde", []),
            _Insn(0x1010, "mov", [_Operand(reg=6), _Operand(reg=2)], reg_names={2: "ax", 6: "si"}),
            _Insn(
                0x1012,
                "lea",
                [_Operand(reg=2), _Operand(mem=SimpleNamespace(base=5, index=6, scale=1, disp=-44), size=2)],
                reg_names={2: "ax", 5: "bp", 6: "si"},
            ),
            _Insn(0x1015, "push", [_Operand(reg=2, size=2)], reg_names={2: "ax"}),
            _Insn(0x1016, "call"),
            _Insn(0x1019, "add", [_Operand(reg=1), _Operand(imm=6)], reg_names={1: "sp"}),
        ]
    )
    monkeypatch.setattr(
        "inertia.semantics.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x1016, 0x1544, 0x1019, "direct_near")],
    )

    summary = summarize_x86_16_callsite(function, 0x1016)

    assert summary.arg_count == 3
    assert summary.arg_widths == (2, 2, 2)
    assert summary.push_arg_sources == (
        ("bp", -46, 2),
        ("imm", 32),
        ("bp_index_addr", -44, "si", 1, ("global_index", 0xB4C, 2, ("bp", 4, 2), (("shl", 1),))),
    )


def test_callsite_summary_keeps_segment_pointer_arg_before_call_return_segment(monkeypatch):
    function = _function_with_block(
        [
            _Insn(
                0x1000,
                "lea",
                [_Operand(reg=2), _Operand(mem=SimpleNamespace(base=5, index=0, disp=-44), size=2)],
                reg_names={2: "ax", 5: "bp"},
            ),
            _Insn(0x1003, "push", [_Operand(reg=8, size=2)], reg_names={8: "ss"}),
            _Insn(0x1004, "push", [_Operand(reg=2, size=2)], reg_names={2: "ax"}),
            _Insn(0x1005, "nop"),
            _Insn(0x1006, "push", [_Operand(reg=9, size=2)], reg_names={9: "cs"}),
            _Insn(0x1007, "call"),
            _Insn(0x100A, "add", [_Operand(reg=1), _Operand(imm=4)], reg_names={1: "sp"}),
        ]
    )
    monkeypatch.setattr(
        "inertia.semantics.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x1007, 0x1544, 0x100A, "direct_near")],
    )

    summary = summarize_x86_16_callsite(function, 0x1007)

    assert summary.arg_count == 2
    assert summary.arg_widths == (2, 2)
    assert summary.push_arg_sources == (("seg", "ss"), ("bp_addr", -44))


def test_callsite_summary_uses_fallthrough_cleanup_block_after_call(monkeypatch):
    call_block = SimpleNamespace(
        capstone=SimpleNamespace(
            insns=(
                _Insn(0x1009, "push", [_Operand(reg=3, size=2)], reg_names={3: "di"}),
                _Insn(0x100A, "push", [_Operand(reg=4, size=2)], reg_names={4: "si"}),
                _Insn(0x100B, "push", [_Operand(imm=4, size=2)]),
                _Insn(0x100E, "call"),
            )
        )
    )
    cleanup_block = SimpleNamespace(
        capstone=SimpleNamespace(insns=(_Insn(0x1011, "add", [_Operand(reg=1), _Operand(imm=2)], reg_names={1: "sp"}),))
    )
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        factory=SimpleNamespace(block=lambda addr, opt_level=0: call_block if addr == 0x1009 else cleanup_block),
    )
    function = SimpleNamespace(project=project, block_addrs_set={0x1009, 0x1011})
    monkeypatch.setattr(
        function,
        "get_call_sites",
        lambda: [0x100E],
        raising=False,
    )
    monkeypatch.setattr(
        "inertia.semantics.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x100E, 0x1544, 0x1011, "direct_near")],
    )

    summary = summarize_x86_16_callsite(function, 0x100E)

    assert summary == CallsiteSummary8616(
        callsite_addr=0x100E,
        target_addr=0x1544,
        return_addr=0x1011,
        kind="direct_near",
        arg_count=1,
        arg_widths=(2,),
        stack_cleanup=2,
        return_register=None,
        return_used=False,
        stack_probe_helper=False,
        stack_cleanup_instruction_addr=0x1011,
    )


def test_callsite_summary_marks_known_stack_probe_helpers(monkeypatch):
    insns = (_Insn(0x1002, "call"),)
    block = SimpleNamespace(capstone=SimpleNamespace(insns=insns))
    callee = SimpleNamespace(addr=0x1544, name="aNchkstk")
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        factory=SimpleNamespace(block=lambda addr, opt_level=0: block),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: callee if addr == 0x1544 else None)
        ),
    )
    function = SimpleNamespace(project=project)
    monkeypatch.setattr(
        "inertia.semantics.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x1002, 0x1544, 0x1005, "direct_near")],
    )

    summary = summarize_x86_16_callsite(function, 0x1002)

    assert summary is not None
    assert summary.stack_probe_helper is True
    assert summary.helper_return_state == "stack_address"
    assert summary.helper_return_space == "ss"
    assert summary.helper_return_width == 2
    assert summary.helper_return_address_kind == "stack"


def test_callsite_summary_marks_binary_signature_stack_probe_without_sidecars(monkeypatch):
    insns = (_Insn(0x1002, "call"),)
    block = SimpleNamespace(capstone=SimpleNamespace(insns=insns))

    def _load(addr: int, size: int):
        if addr != 0x1544:
            raise KeyError(addr)
        return MSC_ANCHKSTK_BYTES[:size]

    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        factory=SimpleNamespace(block=lambda addr, opt_level=0: block),
        loader=SimpleNamespace(memory=SimpleNamespace(load=_load)),
        kb=SimpleNamespace(functions=SimpleNamespace(function=lambda **_kwargs: None), labels={}),
    )
    function = SimpleNamespace(project=project)
    monkeypatch.setattr(
        "inertia.semantics.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x1002, 0x1544, 0x1005, "direct_near")],
    )

    summary = summarize_x86_16_callsite(function, 0x1002)

    assert summary is not None
    assert summary.stack_probe_helper is True
    assert summary.helper_return_width == 2
    assert summary.helper_return_address_kind == "stack"


@pytest.mark.parametrize("allocation_size", (0, 2))
def test_callsite_summary_carries_registered_fixed_stack_probe_allocation(
    monkeypatch: pytest.MonkeyPatch,
    allocation_size: int,
) -> None:
    insns = (
        _Insn(
            0x1002,
            "mov",
            [_Operand(reg=2), _Operand(imm=allocation_size)],
            reg_names={2: "ax"},
        ),
        _Insn(0x1005, "call"),
        _Insn(0x1008, "push", [_Operand(reg=3, size=2)], reg_names={3: "di"}),
    )
    block = SimpleNamespace(capstone=SimpleNamespace(insns=insns))
    project = SimpleNamespace(
        arch=SimpleNamespace(
            name="86_16",
            _inertia_stack_probe_helper_targets_8616=frozenset({0x1544}),
        ),
        factory=SimpleNamespace(block=lambda addr, opt_level=0: block),
        kb=SimpleNamespace(functions=SimpleNamespace(function=lambda **_kwargs: None), labels={}),
    )
    function = SimpleNamespace(project=project)
    monkeypatch.setattr(
        "inertia.semantics.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x1005, 0x1544, 0x1008, "direct_near")],
    )

    summary = summarize_x86_16_callsite(function, 0x1005)

    assert summary is not None
    assert summary.stack_probe_helper is True
    assert summary.stack_probe_allocation_size == allocation_size
    assert summary.return_used is False


def test_callsite_summary_helper_signature_overrides_generic_stub_name(monkeypatch):
    insns = (_Insn(0x1002, "call"),)
    block = SimpleNamespace(capstone=SimpleNamespace(insns=insns))

    def _load(addr: int, size: int):
        if addr != 0x1544:
            raise KeyError(addr)
        return MSC_ANCHKSTK_BYTES[:size]

    generic_stub = SimpleNamespace(addr=0x1544, name="sub_1544")
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        factory=SimpleNamespace(block=lambda addr, opt_level=0: block),
        loader=SimpleNamespace(memory=SimpleNamespace(load=_load)),
        kb=SimpleNamespace(functions=SimpleNamespace(function=lambda **_kwargs: generic_stub), labels={}),
    )
    function = SimpleNamespace(project=project)
    monkeypatch.setattr(
        "inertia.semantics.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x1002, 0x1544, 0x1005, "direct_near")],
    )

    summary = summarize_x86_16_callsite(function, 0x1002)

    assert summary is not None
    assert summary.stack_probe_helper is True
    assert summary.helper_return_state == "stack_address"


def test_callsite_summary_marks_rebased_exact_slice_stack_probe_helper_from_original_project(monkeypatch):
    insns = (_Insn(0x1002, "call"),)
    block = SimpleNamespace(capstone=SimpleNamespace(insns=insns))
    original_project = SimpleNamespace(
        kb=SimpleNamespace(
            functions=SimpleNamespace(
                function=lambda addr, create=False: (
                    SimpleNamespace(addr=addr, name="aNchkstk") if addr == 0x11222 else None
                )
            ),
            labels={0x11222: "aNchkstk"},
        ),
        _inertia_lst_metadata=SimpleNamespace(code_labels={0x11222: "aNchkstk"}),
    )
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        factory=SimpleNamespace(block=lambda addr, opt_level=0: block),
        _inertia_original_project=original_project,
        _inertia_original_linear_delta=0x10222,
    )
    function = SimpleNamespace(project=project)
    monkeypatch.setattr(
        "inertia.semantics.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x1002, 0x1000, 0x1005, "direct_far")],
    )

    summary = summarize_x86_16_callsite(function, 0x1002)

    assert summary is not None
    assert summary.stack_probe_helper is True
    assert summary.helper_return_width == 2
    assert summary.helper_return_address_kind == "stack"


def test_callsite_summary_marks_stack_probe_returned_stack_address_when_ax_is_consumed(monkeypatch):
    insns = (
        _Insn(0x1002, "call"),
        _Insn(0x1005, "mov", [_Operand(reg=3), _Operand(reg=2)], reg_names={2: "ax", 3: "bx"}),
    )
    block = SimpleNamespace(capstone=SimpleNamespace(insns=insns))
    callee = SimpleNamespace(addr=0x1544, name="aNchkstk")
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        factory=SimpleNamespace(block=lambda addr, opt_level=0: block),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: callee if addr == 0x1544 else None)
        ),
    )
    function = SimpleNamespace(project=project)
    monkeypatch.setattr(
        "inertia.semantics.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x1002, 0x1544, 0x1005, "direct_near")],
    )

    summary = summarize_x86_16_callsite(function, 0x1002)

    assert summary is not None
    assert summary.stack_probe_helper is True
    assert summary.return_register == "ax"
    assert summary.return_used is True
    assert summary.helper_return_state == "stack_address"
    assert summary.helper_return_space == "ss"
    assert summary.helper_return_width == 2
    assert summary.helper_return_address_kind == "stack"


def test_callsite_summary_marks_ax_return_used_after_stack_cleanup_in_next_block(monkeypatch):
    call_block = SimpleNamespace(capstone=SimpleNamespace(insns=(_Insn(0x1048, "call"),)))
    next_block = SimpleNamespace(
        capstone=SimpleNamespace(
            insns=(
                _Insn(0x104B, "add", [_Operand(reg=4), _Operand(imm=2)], reg_names={4: "sp"}),
                _Insn(0x104E, "cmp", [_Operand(reg=1), _Operand(imm=69)], reg_names={1: "ax"}),
            )
        )
    )
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        factory=SimpleNamespace(block=lambda addr, opt_level=0: call_block if addr == 0x1048 else next_block),
        kb=SimpleNamespace(functions=SimpleNamespace(function=lambda addr, create=False: None)),
    )
    function = SimpleNamespace(project=project, block_addrs_set={0x1048, 0x104B})
    monkeypatch.setattr(
        "inertia.semantics.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x1048, 0x2048, 0x104B, "direct_near")],
    )

    summary = summarize_x86_16_callsite(function, 0x1048)

    assert summary is not None
    assert summary.return_register == "ax"
    assert summary.return_used is True
    assert summary.return_use_kind == "condition"
    assert summary.return_shape == CallsiteReturnShape8616.AX.value


def test_callsite_summary_detects_dx_ax_return_shape(monkeypatch):
    bp_base = 7
    insns = (
        _Insn(0x1002, "call"),
        _Insn(
            0x1005,
            "mov",
            [
                _Operand(mem=SimpleNamespace(base=bp_base, disp=-4), size=2),
                _Operand(reg=2),
            ],
            reg_names={bp_base: "bp", 2: "ax"},
        ),
        _Insn(
            0x1007,
            "mov",
            [
                _Operand(mem=SimpleNamespace(base=bp_base, disp=-2), size=2),
                _Operand(reg=3),
            ],
            reg_names={bp_base: "bp", 3: "dx"},
        ),
    )
    block = SimpleNamespace(capstone=SimpleNamespace(insns=insns))
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        factory=SimpleNamespace(block=lambda addr, opt_level=0: block),
    )
    function = SimpleNamespace(project=project)
    monkeypatch.setattr(
        "inertia.semantics.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x1002, 0x1500, 0x1005, "direct_near")],
    )

    summary = summarize_x86_16_callsite(function, 0x1002)

    assert summary is not None
    assert summary.return_shape == CallsiteReturnShape8616.DX_AX.value


def test_callsite_summary_detects_dx_ax_return_shape_after_call_block_ends(monkeypatch):
    bp_base = 7
    call_block = SimpleNamespace(capstone=SimpleNamespace(insns=(_Insn(0x1002, "call", size=3),)))
    follow_block = SimpleNamespace(
        capstone=SimpleNamespace(
            insns=(
                _Insn(
                    0x1005,
                    "mov",
                    [
                        _Operand(mem=SimpleNamespace(base=bp_base, disp=-4), size=2),
                        _Operand(reg=2),
                    ],
                    reg_names={bp_base: "bp", 2: "ax"},
                ),
                _Insn(
                    0x1007,
                    "mov",
                    [
                        _Operand(mem=SimpleNamespace(base=bp_base, disp=-2), size=2),
                        _Operand(reg=3),
                    ],
                    reg_names={bp_base: "bp", 3: "dx"},
                ),
            )
        )
    )
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        factory=SimpleNamespace(block=lambda addr, **_kwargs: follow_block if addr == 0x1005 else call_block),
    )
    function = SimpleNamespace(project=project)
    monkeypatch.setattr(
        "inertia.semantics.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x1002, 0x1500, 0x1005, "direct_near")],
    )

    summary = summarize_x86_16_callsite(function, 0x1002)

    assert summary is not None
    assert summary.return_shape == CallsiteReturnShape8616.DX_AX.value


def test_callsite_summary_detects_dx_ax_return_shape_from_direct_global_store(monkeypatch):
    call_block = SimpleNamespace(capstone=SimpleNamespace(insns=(_Insn(0x1002, "call", size=3),)))
    follow_block = SimpleNamespace(
        capstone=SimpleNamespace(
            insns=(
                _Insn(
                    0x1005,
                    "mov",
                    [
                        _Operand(mem=SimpleNamespace(base=None, disp=0xB48), size=2),
                        _Operand(reg=2),
                    ],
                    reg_names={2: "ax"},
                ),
                _Insn(
                    0x1008,
                    "mov",
                    [
                        _Operand(mem=SimpleNamespace(base=None, disp=0xB4A), size=2),
                        _Operand(reg=3),
                    ],
                    reg_names={3: "dx"},
                ),
            )
        )
    )
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        factory=SimpleNamespace(block=lambda addr, **_kwargs: follow_block if addr == 0x1005 else call_block),
    )
    function = SimpleNamespace(project=project)
    monkeypatch.setattr(
        "inertia.semantics.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x1002, 0x1500, 0x1005, "direct_near")],
    )

    summary = summarize_x86_16_callsite(function, 0x1002)

    assert summary is not None
    assert summary.return_shape == CallsiteReturnShape8616.DX_AX.value
    assert summary.return_store_destination == ("global", 0xB48)
    assert summary.return_store_width == 4


def test_callsite_summary_keeps_ax_global_store_width_when_dx_store_is_not_adjacent(monkeypatch):
    call_block = SimpleNamespace(capstone=SimpleNamespace(insns=(_Insn(0x1002, "call", size=3),)))
    follow_block = SimpleNamespace(
        capstone=SimpleNamespace(
            insns=(
                _Insn(
                    0x1005,
                    "mov",
                    [
                        _Operand(mem=SimpleNamespace(base=None, disp=0xB48), size=2),
                        _Operand(reg=2),
                    ],
                    reg_names={2: "ax"},
                ),
                _Insn(0x1008, "call"),
                _Insn(
                    0x100B,
                    "mov",
                    [
                        _Operand(mem=SimpleNamespace(base=None, disp=0xB4A), size=2),
                        _Operand(reg=3),
                    ],
                    reg_names={3: "dx"},
                ),
            )
        )
    )
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        factory=SimpleNamespace(block=lambda addr, **_kwargs: follow_block if addr == 0x1005 else call_block),
    )
    function = SimpleNamespace(project=project)
    monkeypatch.setattr(
        "inertia.semantics.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x1002, 0x1500, 0x1005, "direct_near")],
    )

    summary = summarize_x86_16_callsite(function, 0x1002)

    assert summary is not None
    assert summary.return_store_destination == ("global", 0xB48)
    assert summary.return_store_width == 2


def test_callsite_summary_records_byte_stack_return_store(monkeypatch):
    bp_base = 5
    call_block = SimpleNamespace(capstone=SimpleNamespace(insns=(_Insn(0x1002, "call", size=3),)))
    follow_block = SimpleNamespace(
        capstone=SimpleNamespace(
            insns=(
                _Insn(
                    0x1005,
                    "mov",
                    [
                        _Operand(mem=SimpleNamespace(base=bp_base, disp=-2), size=1),
                        _Operand(reg=2, size=1),
                    ],
                    reg_names={bp_base: "bp", 2: "al"},
                ),
            )
        )
    )
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        factory=SimpleNamespace(block=lambda addr, **_kwargs: follow_block if addr == 0x1005 else call_block),
    )
    function = SimpleNamespace(project=project)
    monkeypatch.setattr(
        "inertia.semantics.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x1002, 0x1500, 0x1005, "direct_near")],
    )

    summary = summarize_x86_16_callsite(function, 0x1002)

    assert summary is not None
    assert summary.return_shape == CallsiteReturnShape8616.AX.value
    assert (
        summary.return_store_destination,
        summary.return_store_width,
        summary.return_store_instruction_addr,
    ) == (("bp", -2), 1, 0x1005)


def test_callsite_summary_does_not_look_past_intervening_call_for_return_store(monkeypatch):
    bp_base = 5
    insns = (
        _Insn(0x1002, "call", size=3),
        _Insn(0x1005, "add", [_Operand(reg=1), _Operand(imm=2)], reg_names={1: "sp"}),
        _Insn(0x1008, "call", size=3),
        _Insn(
            0x100B,
            "mov",
            [
                _Operand(mem=SimpleNamespace(base=bp_base, disp=-2), size=1),
                _Operand(reg=2, size=1),
            ],
            reg_names={bp_base: "bp", 2: "al"},
        ),
    )
    function = _function_with_block(insns)
    monkeypatch.setattr(
        "inertia.semantics.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x1002, 0x1500, 0x1005, "direct_near")],
    )

    summary = summarize_x86_16_callsite(function, 0x1002)

    assert summary is not None
    assert summary.return_store_destination is None
    assert summary.return_store_width is None


def test_callsite_summary_return_use_follows_direct_jump_before_fallthrough():
    reg_names = {1: "sp", 2: "ax"}
    insns = (
        _Insn(0x1002, "call", size=3),
        _Insn(0x1005, "add", [_Operand(reg=1), _Operand(imm=2)], reg_names=reg_names),
        _Insn(0x1008, "jmp", [_Operand(imm=0x1100)], reg_names=reg_names),
        _Insn(0x100B, "mov", [_Operand(reg=2), _Operand(imm=0)], reg_names=reg_names),
    )
    target_block = SimpleNamespace(
        capstone=SimpleNamespace(
            insns=(
                _Insn(0x1100, "cmp", [_Operand(reg=2), _Operand(imm=0x45)], reg_names=reg_names),
                _Insn(0x1103, "jne", [_Operand(imm=0x1110)], reg_names=reg_names),
            )
        )
    )
    empty_block = SimpleNamespace(capstone=SimpleNamespace(insns=()))
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        factory=SimpleNamespace(block=lambda addr, **_kwargs: target_block if addr == 0x1100 else empty_block),
    )
    function = SimpleNamespace(project=project)

    return_register, return_used, return_use_kind = _return_use_after_call(function, insns, 0, 0x1002)

    assert return_register == "ax"
    assert return_used is True
    assert return_use_kind == "condition"


def test_callsite_summary_does_not_pass_callee_ax_through_explicit_void_return():
    reg_names = {1: "sp"}
    insns = (
        _Insn(0x1002, "call", size=3),
        _Insn(0x1005, "add", [_Operand(reg=1), _Operand(imm=4)], reg_names=reg_names),
        _Insn(0x1008, "ret"),
    )
    function = _function_with_block(insns)
    function.prototype = SimTypeFunction(
        [],
        SimTypeBottom(label="void"),
    )

    return_register, return_used, return_use_kind = _return_use_after_call(
        function,
        insns,
        0,
        0x1002,
    )

    assert return_register is None
    assert return_used is False
    assert return_use_kind is None


def test_callsite_summary_keeps_callee_ax_pass_through_for_scalar_return():
    insns = (
        _Insn(0x1002, "call", size=3),
        _Insn(0x1005, "ret"),
    )
    function = _function_with_block(insns)
    function.prototype = SimTypeFunction([], SimTypeLong(False))

    return_register, return_used, return_use_kind = _return_use_after_call(
        function,
        insns,
        0,
        0x1002,
    )

    assert return_register == "ax"
    assert return_used is True
    assert return_use_kind == "function_return"


def test_callsite_summary_marks_guarded_dx_ax_compare_as_wide_return_condition():
    reg_names = {2: "ax", 3: "dx", 4: "bp"}
    insns = (
        _Insn(0x1002, "call", size=3),
        _Insn(0x1005, "cmp", [_Operand(reg=3), _Operand(mem=SimpleNamespace(base=4, disp=-2))], reg_names=reg_names),
        _Insn(0x1008, "jle", [_Operand(imm=0x100D)], reg_names=reg_names),
        _Insn(0x100A, "jmp", [_Operand(imm=0x1018)], reg_names=reg_names),
        _Insn(0x100D, "jge", [_Operand(imm=0x1012)], reg_names=reg_names),
        _Insn(0x100F, "jmp", [_Operand(imm=0x1015)], reg_names=reg_names),
        _Insn(0x1012, "cmp", [_Operand(reg=2), _Operand(mem=SimpleNamespace(base=4, disp=-4))], reg_names=reg_names),
        _Insn(0x1015, "jbe", [_Operand(imm=0x1002)], reg_names=reg_names),
    )
    exit_block = SimpleNamespace(capstone=SimpleNamespace(insns=(_Insn(0x1018, "pop"), _Insn(0x1019, "ret"))))
    function = SimpleNamespace(
        project=SimpleNamespace(factory=SimpleNamespace(block=lambda _addr, **_kwargs: exit_block))
    )

    return_register, return_used, return_use_kind = _return_use_after_call(function, insns, 0, 0x1002)
    return_shape = _return_shape_after_call(function, insns, 0, 0x1002)

    assert return_register == "ax"
    assert return_used is True
    assert return_use_kind == "condition"
    assert return_shape is CallsiteReturnShape8616.DX_AX


def test_callsite_summary_refuses_unpaired_dx_compare_as_wide_return_condition():
    reg_names = {2: "ax", 3: "dx", 4: "bp"}
    insns = (
        _Insn(0x1002, "call", size=3),
        _Insn(0x1005, "cmp", [_Operand(reg=3), _Operand(mem=SimpleNamespace(base=4, disp=-2))], reg_names=reg_names),
        _Insn(0x1008, "jne", [_Operand(imm=0x1010)], reg_names=reg_names),
        _Insn(0x100A, "mov", [_Operand(reg=2), _Operand(imm=0)], reg_names=reg_names),
    )
    function = SimpleNamespace()

    return_register, return_used, return_use_kind = _return_use_after_call(function, insns, 0, 0x1002)

    assert return_register is None
    assert return_used is False
    assert return_use_kind is None


def test_callsite_summary_treats_post_call_ax_reload_as_clobber_not_value_use():
    reg_names = {1: "sp", 2: "ax", 3: "bp"}
    insns = (
        _Insn(0x1002, "call", size=3),
        _Insn(0x1005, "add", [_Operand(reg=1), _Operand(imm=4)], reg_names=reg_names),
        _Insn(0x1008, "mov", [_Operand(reg=2), _Operand(mem=SimpleNamespace(base=3, disp=-6))], reg_names=reg_names),
        _Insn(0x100B, "dec", [_Operand(reg=2)], reg_names=reg_names),
        _Insn(0x100C, "push", [_Operand(reg=2)], reg_names=reg_names),
    )
    function = SimpleNamespace()

    return_register, return_used, return_use_kind = _return_use_after_call(function, insns, 0, 0x1002)

    assert return_register == "ax"
    assert return_used is False
    assert return_use_kind == "clobbered"


def test_callsite_summary_treats_post_call_push_ax_as_value_forwarding():
    reg_names = {1: "sp", 2: "ax"}
    insns = (
        _Insn(0x1002, "call", size=3),
        _Insn(0x1005, "add", [_Operand(reg=1), _Operand(imm=2)], reg_names=reg_names),
        _Insn(0x1008, "push", [_Operand(reg=2)], reg_names=reg_names),
        _Insn(0x1009, "call", size=3),
    )

    return_register, return_used, return_use_kind = _return_use_after_call(
        SimpleNamespace(),
        insns,
        0,
        0x1002,
    )

    assert return_register == "ax"
    assert return_used is True
    assert return_use_kind == "value"


def test_callsite_summary_tracks_ax_return_through_divisor_setup_to_cwd():
    reg_names = {2: "ax", 3: "cx", 4: "bp"}
    insns = (
        _Insn(0x1002, "call", size=3),
        _Insn(
            0x1005,
            "mov",
            [_Operand(reg=3), _Operand(mem=SimpleNamespace(base=4, disp=-4))],
            reg_names=reg_names,
        ),
        _Insn(0x1008, "inc", [_Operand(reg=3)], reg_names=reg_names),
        _Insn(0x1009, "cwd", reg_names=reg_names),
        _Insn(0x100A, "idiv", [_Operand(reg=3)], reg_names=reg_names),
    )

    return_register, return_used, return_use_kind = _return_use_after_call(
        SimpleNamespace(),
        insns,
        0,
        0x1002,
    )

    assert return_register == "ax"
    assert return_used is True
    assert return_use_kind == "value"


def test_callsite_summary_uses_ax_shape_without_paired_dx_ax_stores(monkeypatch):
    insns = (
        _Insn(0x1002, "call"),
        _Insn(
            0x1005,
            "cmp",
            [_Operand(reg=2), _Operand(reg=3)],
            reg_names={2: "ax", 3: "dx"},
        ),
    )
    function = SimpleNamespace()

    shape = _return_shape_after_call(function, insns, 0, 0x1002)

    assert shape == CallsiteReturnShape8616.AX


def test_callsite_summary_does_not_claim_stack_address_when_probe_return_is_not_consumed(monkeypatch):
    insns = (
        _Insn(0x1002, "call"),
        _Insn(0x1005, "push", [_Operand(reg=3, size=2)], reg_names={3: "di"}),
        _Insn(0x1006, "push", [_Operand(reg=4, size=2)], reg_names={4: "si"}),
    )
    block = SimpleNamespace(capstone=SimpleNamespace(insns=insns))
    callee = SimpleNamespace(addr=0x1544, name="aNchkstk")
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        factory=SimpleNamespace(block=lambda addr, opt_level=0: block),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: callee if addr == 0x1544 else None)
        ),
    )
    function = SimpleNamespace(project=project)
    monkeypatch.setattr(
        "inertia.semantics.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x1002, 0x1544, 0x1005, "direct_near")],
    )

    summary = summarize_x86_16_callsite(function, 0x1002)

    assert summary is not None
    assert summary.stack_probe_helper is True
    assert summary.return_register is None
    assert summary.return_used is False
    assert summary.helper_return_state == "none"
    assert summary.helper_return_space is None
    assert summary.helper_return_width is None
    assert summary.helper_return_address_kind == "none"


def test_collect_caller_return_use_evidence_proves_all_direct_call_results_unused():
    # Two calls to 0x1020, each followed by caller stack cleanup and a non-AX instruction.
    code = bytes.fromhex("e81d0083c40290e8160083c40290")
    project = SimpleNamespace(
        arch=Arch86_16(),
        loader=SimpleNamespace(memory=_Memory({0x1000: code})),
    )

    evidence = collect_caller_return_use_evidence_8616(project, 0x1020, ((0x1000, 0x100E),))

    assert evidence.verdict is CallerReturnUseVerdict8616.UNUSED
    assert evidence.raw_fact_count == 2
    assert evidence.normalized_fact_count == 2
    assert evidence.classified_fact_count == 2
    assert evidence.materialized_count == 2
    assert evidence.failure_count == 0
    assert evidence.used_callsite_count == 0
    assert evidence.unused_callsite_count == 2
    assert evidence.callsite_addrs == (0x1000, 0x1007)


def test_collect_caller_return_use_evidence_reports_any_ax_consumer():
    # call 0x1020; add sp, 2; test ax, ax
    code = bytes.fromhex("e81d0083c40285c0")
    project = SimpleNamespace(
        arch=Arch86_16(),
        loader=SimpleNamespace(memory=_Memory({0x1000: code})),
    )

    evidence = collect_caller_return_use_evidence_8616(project, 0x1020, ((0x1000, 0x1008),))

    assert evidence.verdict is CallerReturnUseVerdict8616.USED
    assert evidence.raw_fact_count == 1
    assert evidence.classified_fact_count == 1
    assert evidence.used_callsite_count == 1
    assert evidence.unused_callsite_count == 0


def test_collect_caller_return_use_evidence_does_not_treat_memory_compare_as_ax_use():
    # call 0x1020; add sp, 4; cmp byte ptr [bp-10], 3
    code = bytes.fromhex("e81d0083c404807ef603")
    project = SimpleNamespace(
        arch=Arch86_16(),
        loader=SimpleNamespace(memory=_Memory({0x1000: code})),
    )

    evidence = collect_caller_return_use_evidence_8616(project, 0x1020, ((0x1000, 0x100A),))

    assert evidence.verdict is CallerReturnUseVerdict8616.UNUSED
    assert evidence.raw_fact_count == 1
    assert evidence.classified_fact_count == 1
    assert evidence.used_callsite_count == 0
    assert evidence.unused_callsite_count == 1
    assert evidence.failure_count == 0


def test_collect_caller_return_use_evidence_ignores_recursive_return_passthrough():
    # call self; ret. The recursive pass-through cannot prove its own return contract.
    code = bytes.fromhex("90 90 e8 fb ff c3")
    project = SimpleNamespace(
        arch=Arch86_16(),
        loader=SimpleNamespace(memory=_Memory({0x1000: code})),
    )

    evidence = collect_caller_return_use_evidence_8616(project, 0x1000, ((0x1000, 0x1006),))

    assert evidence.verdict is CallerReturnUseVerdict8616.UNKNOWN
    assert evidence.raw_fact_count == 1
    assert evidence.classified_fact_count == 0
    assert evidence.used_callsite_count == 0
    assert evidence.unused_callsite_count == 0
    assert evidence.excluded_callsite_count == 1
    assert evidence.failure_count == 0


def test_collect_caller_return_use_evidence_keeps_recursive_value_use():
    recursive_consumer = bytes.fromhex("e8 fd ff 05 01 00 c3")
    independent_caller = bytes.fromhex("e8 dd ff b8 00 00")
    project = SimpleNamespace(
        arch=Arch86_16(),
        loader=SimpleNamespace(
            memory=_Memory({0x1000: recursive_consumer, 0x1020: independent_caller})
        ),
    )

    evidence = collect_caller_return_use_evidence_8616(
        project,
        0x1000,
        ((0x1000, 0x1007), (0x1020, 0x1026)),
        target_aliases=(0x1000,),
    )

    assert evidence.verdict is CallerReturnUseVerdict8616.USED
    assert evidence.raw_fact_count == 2
    assert evidence.classified_fact_count == 2
    assert evidence.used_callsite_count == 1
    assert evidence.unused_callsite_count == 1
    assert evidence.excluded_callsite_count == 0
    assert evidence.failure_count == 0


def test_collect_caller_return_use_evidence_censuses_all_entry_aliases():
    unused_alias_caller = bytes.fromhex("e8 dd ff b8 00 00")
    used_alias_caller = bytes.fromhex("e8 dd ff 05 01 00")
    project = SimpleNamespace(
        arch=Arch86_16(),
        loader=SimpleNamespace(
            memory=_Memory({0x1020: unused_alias_caller, 0x1030: used_alias_caller})
        ),
    )

    evidence = collect_caller_return_use_evidence_8616(
        project,
        0x1000,
        ((0x1020, 0x1026), (0x1030, 0x1036)),
        target_aliases=(0x1000, 0x1010),
    )

    assert evidence.verdict is CallerReturnUseVerdict8616.USED
    assert evidence.raw_fact_count == 2
    assert evidence.classified_fact_count == 2
    assert evidence.used_callsite_count == 1
    assert evidence.unused_callsite_count == 1
    assert evidence.failure_count == 0


def test_collect_caller_return_use_evidence_uses_independent_callers_across_recursive_wrapper():
    # target <- wrapper <- recursive wrapper; an independent caller discards
    # the recursive wrapper's return, so the cycle adds no observation.
    wrapper = bytes.fromhex("e8 1d 00 c3")
    recursive_wrapper = bytes.fromhex("e8 ed ff c3 e8 f9 ff c3")
    observer = bytes.fromhex("e8 dd ff b8 00 00")
    project = SimpleNamespace(
        arch=Arch86_16(),
        loader=SimpleNamespace(
            memory=_Memory(
                {
                    0x1000: wrapper,
                    0x1010: recursive_wrapper,
                    0x1030: observer,
                }
            )
        ),
    )

    evidence = collect_caller_return_use_evidence_8616(
        project,
        0x1020,
        ((0x1000, 0x1004), (0x1010, 0x1018), (0x1030, 0x1036)),
    )

    assert evidence.verdict is CallerReturnUseVerdict8616.UNUSED
    assert evidence.raw_fact_count == 1
    assert evidence.classified_fact_count == 1
    assert evidence.failure_count == 0


def test_collect_caller_return_use_evidence_keeps_observed_wrapper_return_passthrough():
    # wrapper: call 0x1020; ret. observer: call wrapper; test ax, ax.
    wrapper = bytes.fromhex("e8 1d 00 c3")
    observer = bytes.fromhex("e8 ed ff 85 c0")
    project = SimpleNamespace(
        arch=Arch86_16(),
        loader=SimpleNamespace(memory=_Memory({0x1000: wrapper, 0x1010: observer})),
    )

    evidence = collect_caller_return_use_evidence_8616(
        project,
        0x1020,
        ((0x1000, 0x1004), (0x1010, 0x1015)),
    )

    assert evidence.verdict is CallerReturnUseVerdict8616.USED
    assert evidence.used_callsite_count == 1
    assert evidence.unused_callsite_count == 0


def test_collect_caller_return_use_evidence_proves_unobserved_wrapper_return_unused():
    # wrapper: call 0x1020; ret. observer: call wrapper; overwrite ax.
    wrapper = bytes.fromhex("e8 1d 00 c3")
    observer = bytes.fromhex("e8 ed ff b8 00 00")
    project = SimpleNamespace(
        arch=Arch86_16(),
        loader=SimpleNamespace(memory=_Memory({0x1000: wrapper, 0x1010: observer})),
    )

    evidence = collect_caller_return_use_evidence_8616(
        project,
        0x1020,
        ((0x1000, 0x1004), (0x1010, 0x1016)),
    )

    assert evidence.verdict is CallerReturnUseVerdict8616.UNUSED
    assert evidence.used_callsite_count == 0
    assert evidence.unused_callsite_count == 1
