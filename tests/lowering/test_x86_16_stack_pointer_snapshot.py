from __future__ import annotations

from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CBinaryOp,
    CConstant,
    CFunctionCall,
    CIndexedVariable,
    CStatements,
    CVariable,
)
from angr.sim_type import SimTypeChar, SimTypePointer, SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
import inertia.lowering.near_pointer_argument as near_pointer_argument_module
from inertia.lowering.near_pointer_argument import (
    NearPointerArgumentFact8616,
    collect_near_pointer_argument_facts_8616,
)
from inertia.lowering.stack_pointer_snapshot import (
    StackPointerSnapshotMaterializationError8616,
    StackPointerSnapshotTracker8616,
)
from capstone.x86_const import (
    X86_INS_CMP,
    X86_INS_INC,
    X86_INS_MOV,
    X86_OP_IMM,
    X86_OP_MEM,
    X86_OP_REG,
    X86_REG_AX,
    X86_REG_BP,
    X86_REG_BX,
    X86_REG_INVALID,
    X86_REG_SI,
)


class _Codegen:
    def __init__(self) -> None:
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cstyle_null_cmp = False
        self._idx = 0

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def _reg(register: int, *, size: int = 2) -> SimpleNamespace:
    return SimpleNamespace(type=X86_OP_REG, reg=register, size=size, access=0)


def _imm(value: int, *, size: int = 1) -> SimpleNamespace:
    return SimpleNamespace(type=X86_OP_IMM, imm=value, size=size, access=0)


def _mem(
    base: int,
    *,
    index: int = X86_REG_INVALID,
    displacement: int = 0,
    size: int = 2,
    access: int = 0,
) -> SimpleNamespace:
    return SimpleNamespace(
        type=X86_OP_MEM,
        size=size,
        access=access,
        mem=SimpleNamespace(
            base=base,
            index=index,
            disp=displacement,
        ),
    )


def _instruction(address: int, instruction_id: int, *operands: SimpleNamespace) -> SimpleNamespace:
    return SimpleNamespace(
        insn=SimpleNamespace(
            address=address,
            id=instruction_id,
            operands=operands,
        )
    )


def _function(*instructions: SimpleNamespace) -> SimpleNamespace:
    return SimpleNamespace(
        blocks=(
            SimpleNamespace(
                addr=0x1000,
                capstone=SimpleNamespace(insns=instructions),
            ),
        )
    )


def _snapshot_fact() -> NearPointerArgumentFact8616:
    return NearPointerArgumentFact8616(
        stack_offset=4,
        carrier_load_ins_addr=0x100A,
        dereference_ins_addr=0x1010,
        access_width_bytes=1,
        source_version_delta=1,
        source_update_ins_addrs=(0x100D,),
    )


def _pointer_argument(codegen: _Codegen) -> CVariable:
    return CVariable(
        SimStackVariable(4, 2, base="bp", name="s"),
        variable_type=SimTypePointer(SimTypeChar(False)).with_arch(codegen.project.arch),
        codegen=codegen,
    )


def _segment(codegen: _Codegen) -> CVariable:
    return CVariable(
        SimRegisterVariable(0x24, 2, name="ds"),
        variable_type=SimTypeShort(False).with_arch(codegen.project.arch),
        codegen=codegen,
    )


def test_collect_near_pointer_fact_retains_preincrement_stack_version() -> None:
    function = _function(
        _instruction(0x100A, X86_INS_MOV, _reg(X86_REG_BX), _mem(X86_REG_BP, displacement=4)),
        _instruction(0x100D, X86_INS_INC, _mem(X86_REG_BP, displacement=4, access=3)),
        _instruction(0x1010, X86_INS_CMP, _mem(X86_REG_BX, size=1), _imm(0)),
    )

    assert collect_near_pointer_argument_facts_8616(function) == (_snapshot_fact(),)


def test_collect_near_pointer_fact_refuses_clobbered_carrier() -> None:
    function = _function(
        _instruction(0x100A, X86_INS_MOV, _reg(X86_REG_BX), _mem(X86_REG_BP, displacement=4)),
        _instruction(0x100D, X86_INS_INC, _mem(X86_REG_BP, displacement=4, access=3)),
        _instruction(0x100F, X86_INS_MOV, _reg(X86_REG_BX), _reg(X86_REG_AX)),
        _instruction(0x1010, X86_INS_CMP, _mem(X86_REG_BX, size=1), _imm(0)),
    )

    assert collect_near_pointer_argument_facts_8616(function) == ()


def test_collect_near_pointer_fact_ignores_update_to_other_stack_slot() -> None:
    function = _function(
        _instruction(0x100A, X86_INS_MOV, _reg(X86_REG_BX), _mem(X86_REG_BP, displacement=4)),
        _instruction(0x100D, X86_INS_INC, _mem(X86_REG_BP, displacement=6, access=3)),
        _instruction(0x1010, X86_INS_CMP, _mem(X86_REG_BX, size=1), _imm(0)),
    )

    facts = collect_near_pointer_argument_facts_8616(function)

    assert len(facts) == 1
    assert facts[0].source_version_delta == 0
    assert facts[0].source_update_ins_addrs == ()


def test_collect_near_pointer_fact_accepts_carrier_as_index_register() -> None:
    function = _function(
        _instruction(0x100A, X86_INS_MOV, _reg(X86_REG_SI), _mem(X86_REG_BP, displacement=4)),
        _instruction(
            0x1010,
            X86_INS_MOV,
            _mem(X86_REG_BX, index=X86_REG_SI, size=1, access=3),
            _reg(X86_REG_AX, size=1),
        ),
    )

    assert collect_near_pointer_argument_facts_8616(function) == (
        NearPointerArgumentFact8616(
            stack_offset=4,
            carrier_load_ins_addr=0x100A,
            dereference_ins_addr=0x1010,
            access_width_bytes=1,
        ),
    )


def test_collect_near_pointer_fact_refuses_two_argument_address_carriers() -> None:
    function = _function(
        _instruction(0x100A, X86_INS_MOV, _reg(X86_REG_BX), _mem(X86_REG_BP, displacement=4)),
        _instruction(0x100D, X86_INS_MOV, _reg(X86_REG_SI), _mem(X86_REG_BP, displacement=6)),
        _instruction(
            0x1010,
            X86_INS_MOV,
            _mem(X86_REG_BX, index=X86_REG_SI, size=1, access=3),
            _reg(X86_REG_AX, size=1),
        ),
    )

    assert collect_near_pointer_argument_facts_8616(function) == ()


def test_collect_near_pointer_facts_reuses_project_request_inventory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    function = _function(
        _instruction(0x100A, X86_INS_MOV, _reg(X86_REG_BX), _mem(X86_REG_BP, displacement=4)),
        _instruction(0x1010, X86_INS_CMP, _mem(X86_REG_BX, size=1), _imm(0)),
    )
    project = SimpleNamespace()
    decode_count = 0

    monkeypatch.setattr(
        near_pointer_argument_module,
        "_direct_global_update_blocks_8616",
        lambda _project, selected_function: tuple(selected_function.blocks),
    )

    def decoded_instructions(_project: object, block: SimpleNamespace) -> tuple[SimpleNamespace, ...]:
        nonlocal decode_count
        decode_count += 1
        return tuple(block.capstone.insns)

    monkeypatch.setattr(
        near_pointer_argument_module,
        "_capstone_insns_for_direct_global_update_8616",
        decoded_instructions,
    )

    first = collect_near_pointer_argument_facts_8616(function, project=project)
    second = collect_near_pointer_argument_facts_8616(function, project=project)

    assert second is first
    assert decode_count == 1

    original_block = function.blocks[0]
    function.blocks = (SimpleNamespace(addr=0x2000, capstone=original_block.capstone),)
    third = collect_near_pointer_argument_facts_8616(function, project=project)

    assert third == first
    assert decode_count == 2


def test_unique_untagged_helper_join_materializes_saved_pointer_value() -> None:
    codegen = _Codegen()
    pointer = _pointer_argument(codegen)
    helper = CFunctionCall(
        "SEG_U8",
        None,
        [_segment(codegen), pointer],
        codegen=codegen,
        tags={"inertia_x86_16_runtime_segment_helper": "SEG_U8"},
    )
    tracker = StackPointerSnapshotTracker8616((_snapshot_fact(),))
    tracker.bind_unique_untagged_helpers(CStatements([helper], codegen=codegen))

    adjusted = tracker.materialize(
        helper.args[1],
        source_instruction_addrs=frozenset(),
        provenance_node=helper,
        codegen=codegen,
    )

    assert isinstance(adjusted, CBinaryOp)
    assert adjusted.op == "Sub"
    assert adjusted.lhs is pointer
    assert isinstance(adjusted.rhs, CConstant)
    assert adjusted.rhs.value == 1
    assert tracker.stats.materialized_count == 1
    tracker.assert_closed()


def test_ambiguous_untagged_helper_join_refuses_provenance() -> None:
    codegen = _Codegen()
    pointer = _pointer_argument(codegen)
    helpers = [
        CFunctionCall(
            "SEG_U8",
            None,
            [_segment(codegen), pointer],
            codegen=codegen,
            tags={"inertia_x86_16_runtime_segment_helper": "SEG_U8"},
        )
        for _ in range(2)
    ]
    tracker = StackPointerSnapshotTracker8616((_snapshot_fact(),))

    tracker.bind_unique_untagged_helpers(CStatements(helpers, codegen=codegen))

    assert tracker.bound_facts_by_node_id == {}
    assert all("inertia_source_instruction_addrs" not in helper.tags for helper in helpers)


def test_indexed_pointer_access_uses_saved_pointer_element() -> None:
    codegen = _Codegen()
    pointer = _pointer_argument(codegen)
    access = CIndexedVariable(
        pointer,
        CConstant(0, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"inertia_source_instruction_addrs": (0x1010,)},
    )
    tracker = StackPointerSnapshotTracker8616((_snapshot_fact(),))

    adjusted = tracker.materialize_indexed_access(
        access,
        source_instruction_addrs=frozenset({0x1010}),
        codegen=codegen,
    )

    assert isinstance(adjusted, CIndexedVariable)
    assert isinstance(adjusted.index, CBinaryOp)
    assert adjusted.index.op == "Sub"
    assert isinstance(adjusted.index.rhs, CConstant)
    assert adjusted.index.rhs.value == 1
    tracker.assert_closed()


def test_classified_unmaterialized_snapshot_fails_closed() -> None:
    codegen = _Codegen()
    tracker = StackPointerSnapshotTracker8616((_snapshot_fact(),))
    unrelated = CVariable(
        SimStackVariable(6, 2, base="bp", name="other"),
        codegen=codegen,
    )

    tracker.materialize(
        unrelated,
        source_instruction_addrs=frozenset({0x1010}),
        provenance_node=None,
        codegen=codegen,
    )

    with pytest.raises(StackPointerSnapshotMaterializationError8616):
        tracker.assert_closed()
