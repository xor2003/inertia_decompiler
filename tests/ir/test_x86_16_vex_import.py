from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
import inertia.ir.direct_evidence_deadline as deadline_owner
import inertia.ir.vex_import as importer
from inertia.ir.core import (
    AddressStatus,
    IRAddress,
    IRBinaryValue,
    IRBlock,
    IRCondition,
    IRFunctionArtifact,
    IRInstr,
    IRValue,
    MemSpace,
    SegmentOrigin,
)
from inertia.ir.entry_jump_domain import (
    EntryJumpDomainApplication8616,
    EntryJumpDomainApplicationStatus8616,
)
from inertia.ir.function_ir_registry import (
    FunctionIRArtifactFailure8616,
    FunctionIRArtifactVerdict8616,
    publish_function_ir_artifact_8616,
    registered_function_ir_artifact_8616,
)
from inertia.ir.vex_import import (
    apply_x86_16_vex_ir_artifact,
    build_x86_16_ir_function_artifact,
    build_x86_16_ir_function_artifact_summary,
)
from inertia.ir.vex_terminal_jump import (
    TerminalJumpEvidence8616,
    TerminalJumpEvidenceStats8616,
    TerminalJumpRefusalReason8616,
)

from inertia.frontend.x86_16.relative_control_edge import DecodedRelativeEdge, decode_relative_edge


def _const(value: int):
    return SimpleNamespace(tag="Iex_Const", con=SimpleNamespace(value=value))


def _get(offset: int):
    return SimpleNamespace(tag="Iex_Get", offset=offset)


_ARCH = Arch86_16()


def _get_register(name: str):
    return _get(_ARCH.registers[name][0])


def _rdtmp(tmp: int):
    return SimpleNamespace(tag="Iex_RdTmp", tmp=tmp)


def _binop(op: str, *args):
    return SimpleNamespace(tag="Iex_Binop", op=op, args=args)


def _unop(op: str, arg, *, size: int = 2):
    """Provide the byte-valued result width of this synthetic VEX boundary."""
    return SimpleNamespace(tag="Iex_Unop", op=op, args=(arg,), result_size=size)


def _wrtmp(tmp: int, data):
    return SimpleNamespace(tag="Ist_WrTmp", tmp=tmp, data=data)


def _store(addr, data):
    return SimpleNamespace(tag="Ist_Store", addr=addr, data=data)


def _exit(guard, dst):
    return SimpleNamespace(tag="Ist_Exit", guard=guard, dst=dst)


def _ite(cond, iftrue, iffalse):
    return SimpleNamespace(tag="Iex_ITE", cond=cond, iftrue=iftrue, iffalse=iffalse)


def _flag_test(mask: int, *, is_set: bool):
    return _binop(
        "Iop_CmpNE8" if is_set else "Iop_CmpEQ8",
        _binop("Iop_And16", _get_register("flags"), _const(mask)),
        _const(0),
    )


def _flags_equal(mask_a: int, mask_b: int):
    return _binop("Iop_CmpEQ8", _flag_test(mask_a, is_set=True), _flag_test(mask_b, is_set=True))


def _flags_not_equal(mask_a: int, mask_b: int):
    return _binop("Iop_CmpNE8", _flag_test(mask_a, is_set=True), _flag_test(mask_b, is_set=True))


def _insn(mnemonic: str, op_str: str = ""):
    return SimpleNamespace(mnemonic=mnemonic, op_str=op_str)


def _imark(addr: int, delta: int = 0):
    return SimpleNamespace(tag="Ist_IMark", addr=addr, delta=delta)


def _block(addr: int, *stmts, next_expr=None, insns=()):
    return SimpleNamespace(
        addr=addr,
        size=1,
        vex=SimpleNamespace(statements=stmts, next=next_expr),
        capstone=SimpleNamespace(insns=tuple(insns)),
    )


class _FakeFactory:
    def __init__(self, blocks):
        self._blocks = blocks

    def block(self, addr, opt_level=0, collect_data_refs=False):
        assert opt_level == 0
        assert collect_data_refs is True
        return self._blocks[addr]


def _project(blocks, function):
    return SimpleNamespace(
        factory=_FakeFactory(blocks),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: function if addr == function.addr else None)
        ),
    )


def test_ir_summary_traverses_binary_value_operands() -> None:
    artifact = IRFunctionArtifact(
        function_addr=0x1000,
        blocks=(
            IRBlock(
                addr=0x1000,
                instrs=(
                    IRInstr(
                        op="ASSIGN",
                        dst=IRValue(space=MemSpace.TMP, name="t0", size=2),
                        args=(
                            IRBinaryValue(
                                op="add",
                                lhs=IRValue(space=MemSpace.REG, name="ax", size=2),
                                rhs=IRValue(space=MemSpace.CONST, const=1, size=2),
                                size=2,
                            ),
                        ),
                        size=2,
                    ),
                ),
            ),
        ),
    )

    summary = build_x86_16_ir_function_artifact_summary(artifact)

    assert summary["space_counts"] == {
        "const": 1,
        "ds": 0,
        "es": 0,
        "reg": 1,
        "ss": 0,
        "tmp": 1,
        "unknown": 0,
    }
    assert summary["aliasable_value_count"] == 1


def test_vex_import_maps_si_based_store_to_typed_provisional_ds_address() -> None:
    function = SimpleNamespace(addr=0x1000, block_addrs_set={0x1000}, info={})
    project = _project(
        {
            0x1000: _block(
                0x1000,
                _imark(0x0FFE, 2),
                _wrtmp(0, _get_register("si")),
                _wrtmp(1, _const(4)),
                _wrtmp(2, _binop("Iop_Add16", _rdtmp(0), _rdtmp(1))),
                _wrtmp(3, SimpleNamespace(tag="Iex_Const", con=SimpleNamespace(value=0x55), ty="Ity_I8")),
                _store(_rdtmp(2), _rdtmp(3)),
            )
        },
        function,
    )

    artifact = build_x86_16_ir_function_artifact(project, function)
    store = artifact.blocks[0].instrs[-1]
    addr = store.args[0]

    assert store.op == "STORE"
    assert store.dst is None
    assert isinstance(addr, IRAddress)
    assert addr.space == MemSpace.DS
    assert addr.base == ("si",)
    assert addr.offset == 4
    assert addr.size == store.size == 1
    assert addr.status == AddressStatus.PROVISIONAL
    assert addr.segment_origin == SegmentOrigin.DEFAULTED
    assert all(instruction.addr == 0x1000 for instruction in artifact.blocks[0].instrs)
    assert all(refusal.kind != "unsupported_stmt" for refusal in artifact.blocks[0].refusals)


def test_vex_import_keeps_load_arguments_typed_as_address() -> None:
    function = SimpleNamespace(addr=0x1000, block_addrs_set={0x1000}, info={})
    project = _project(
        {
            0x1000: _block(
                0x1000,
                _wrtmp(0, _get_register("si")),
                _wrtmp(1, SimpleNamespace(tag="Iex_Load", addr=_rdtmp(0), result_size=2)),
            )
        },
        function,
    )

    artifact = build_x86_16_ir_function_artifact(project, function)
    load = artifact.blocks[0].instrs[-1]

    assert load.op == "LOAD"
    assert isinstance(load.args[0], IRAddress)
    assert load.args[0].base == ("si",)


def test_vex_import_uses_vex_type_token_for_byte_load_width() -> None:
    function = SimpleNamespace(addr=0x1000, block_addrs_set={0x1000}, info={})
    project = _project(
        {
            0x1000: _block(
                0x1000,
                _wrtmp(0, _get_register("bp")),
                _wrtmp(1, _binop("Iop_Add16", _rdtmp(0), _const(7))),
                _wrtmp(
                    2,
                    SimpleNamespace(
                        tag="Iex_Load",
                        addr=_rdtmp(1),
                        result_size=lambda _tyenv: 8,
                        ty="Ity_I8",
                    ),
                ),
            )
        },
        function,
    )

    artifact = build_x86_16_ir_function_artifact(project, function)
    load = artifact.blocks[0].instrs[-1]

    assert load.op == "LOAD"
    assert load.size == 1
    assert isinstance(load.args[0], IRAddress)
    assert load.args[0].offset == 7
    assert load.args[0].size == 1


def test_vex_import_maps_bp_sub_offset_to_proven_ss_frame_slot() -> None:
    function = SimpleNamespace(addr=0x1000, block_addrs_set={0x1000}, info={})
    project = _project(
        {
            0x1000: _block(
                0x1000,
                _wrtmp(0, _get_register("bp")),
                _wrtmp(1, _const(6)),
                _wrtmp(2, _binop("Iop_Sub16", _rdtmp(0), _rdtmp(1))),
                _store(_rdtmp(2), _const(1)),
            )
        },
        function,
    )

    artifact = build_x86_16_ir_function_artifact(project, function)
    store = artifact.blocks[0].instrs[-1]
    addr = store.args[0]

    assert isinstance(addr, IRAddress)
    assert addr.space == MemSpace.SS
    assert addr.base == ("bp",)
    assert addr.offset == -6
    assert addr.status == AddressStatus.STABLE
    assert addr.segment_origin == SegmentOrigin.PROVEN
    assert artifact.summary["frame_slot_count"] == 1
    assert artifact.summary["address_status_counts"]["stable"] >= 1
    assert artifact.summary["segment_origin_counts"]["proven"] >= 1


def test_vex_import_recovers_explicit_ss_linearized_bp_offset_as_segmented_frame_slot() -> None:
    function = SimpleNamespace(addr=0x1000, block_addrs_set={0x1000}, info={})
    project = _project(
        {
            0x1000: _block(
                0x1000,
                _wrtmp(0, _get_register("bp")),
                _wrtmp(1, _binop("Iop_Add16", _rdtmp(0), _const(0xFFFE))),
                _wrtmp(2, _get_register("ss")),
                _wrtmp(3, _unop("Iop_16Uto32", _rdtmp(2), size=4)),
                _wrtmp(4, _binop("Iop_Shl32", _rdtmp(3), _const(4))),
                _wrtmp(5, _unop("Iop_16Uto32", _rdtmp(1), size=4)),
                _wrtmp(6, _binop("Iop_Add32", _rdtmp(4), _rdtmp(5))),
                _store(_rdtmp(6), _const(1)),
            )
        },
        function,
    )

    artifact = build_x86_16_ir_function_artifact(project, function)
    addr = artifact.blocks[0].instrs[-1].args[0]

    assert isinstance(addr, IRAddress)
    assert addr.space is MemSpace.SS
    assert addr.base == ("bp",)
    assert addr.offset == -2
    assert addr.status is AddressStatus.STABLE
    assert addr.segment_origin is SegmentOrigin.PROVEN
    assert artifact.summary["frame_slot_count"] == 1


def test_vex_import_keeps_register_pair_address_tuple_for_alias() -> None:
    function = SimpleNamespace(addr=0x1000, block_addrs_set={0x1000}, info={})
    project = _project(
        {
            0x1000: _block(
                0x1000,
                _wrtmp(0, _get_register("bx")),
                _wrtmp(1, _get_register("si")),
                _wrtmp(2, _binop("Iop_Add16", _rdtmp(0), _rdtmp(1))),
                _store(_rdtmp(2), _const(0x33)),
            )
        },
        function,
    )

    artifact = build_x86_16_ir_function_artifact(project, function)
    addr = artifact.blocks[0].instrs[-1].args[0]

    assert isinstance(addr, IRAddress)
    assert addr.base == ("bx", "si")
    assert addr.space == MemSpace.DS
    assert addr.segment_origin == SegmentOrigin.DEFAULTED


def test_vex_import_marks_string_destination_di_as_proven_es() -> None:
    function = SimpleNamespace(addr=0x1000, block_addrs_set={0x1000}, info={})
    project = _project(
        {
            0x1000: _block(
                0x1000,
                _wrtmp(0, _get_register("di")),
                _store(_rdtmp(0), _const(0x33)),
                insns=(_insn("rep movsb"),),
            )
        },
        function,
    )

    artifact = build_x86_16_ir_function_artifact(project, function)
    addr = artifact.blocks[0].instrs[-1].args[0]

    assert isinstance(addr, IRAddress)
    assert addr.base == ("di",)
    assert addr.space == MemSpace.ES
    assert addr.status == AddressStatus.STABLE
    assert addr.segment_origin == SegmentOrigin.PROVEN


def test_vex_import_lifts_comparison_exit_to_typed_condition() -> None:
    function = SimpleNamespace(addr=0x1000, block_addrs_set={0x1000}, info={})
    project = _project(
        {
            0x1000: _block(
                0x1000,
                _wrtmp(0, _get_register("ax")),
                _wrtmp(1, _get_register("bx")),
                _wrtmp(2, _binop("Iop_CmpEQ16", _rdtmp(0), _rdtmp(1))),
                _exit(_rdtmp(2), _const(0x1010)),
            )
        },
        function,
    )

    artifact = build_x86_16_ir_function_artifact(project, function)
    cjmp = artifact.blocks[0].instrs[-1]
    cond = cjmp.args[0]

    assert cjmp.op == "CJMP"
    assert isinstance(cond, IRCondition)
    assert cond.op == "eq"
    assert [value.name for value in cond.args] == ["ax", "bx"]
    assert artifact.summary["condition_counts"] == {"eq": 1}


def test_vex_import_folds_compare_with_zero_to_nonzero_condition() -> None:
    function = SimpleNamespace(addr=0x1000, block_addrs_set={0x1000}, info={})
    project = _project(
        {
            0x1000: _block(
                0x1000,
                _wrtmp(0, _get_register("si")),
                _wrtmp(1, _binop("Iop_CmpNE16", _rdtmp(0), _const(0))),
                _exit(_rdtmp(1), _const(0x1010)),
            )
        },
        function,
    )

    artifact = build_x86_16_ir_function_artifact(project, function)
    cond = artifact.blocks[0].instrs[-1].args[0]

    assert isinstance(cond, IRCondition)
    assert cond.op == "nonzero"
    assert [value.name for value in cond.args] == ["si"]


def test_vex_import_lifts_unsigned_compare_condition() -> None:
    function = SimpleNamespace(addr=0x1000, block_addrs_set={0x1000}, info={})
    project = _project(
        {
            0x1000: _block(
                0x1000,
                _wrtmp(0, _get_register("ax")),
                _wrtmp(1, _get_register("bx")),
                _wrtmp(2, _binop("Iop_CmpLT16U", _rdtmp(0), _rdtmp(1))),
                _exit(_rdtmp(2), _const(0x1010)),
            )
        },
        function,
    )

    artifact = build_x86_16_ir_function_artifact(project, function)
    cond = artifact.blocks[0].instrs[-1].args[0]

    assert isinstance(cond, IRCondition)
    assert cond.op == "ult"
    assert [value.name for value in cond.args] == ["ax", "bx"]


def test_vex_import_lifts_masked_nonzero_exit_to_typed_condition() -> None:
    function = SimpleNamespace(addr=0x1000, block_addrs_set={0x1000}, info={})
    project = _project(
        {
            0x1000: _block(
                0x1000,
                _wrtmp(0, _get_register("si")),
                _wrtmp(1, _const(1)),
                _wrtmp(2, _binop("Iop_And16", _rdtmp(0), _rdtmp(1))),
                _exit(_rdtmp(2), _const(0x1010)),
            )
        },
        function,
    )

    artifact = build_x86_16_ir_function_artifact(project, function)
    cjmp = artifact.blocks[0].instrs[-1]
    cond = cjmp.args[0]

    assert cjmp.op == "CJMP"
    assert isinstance(cond, IRCondition)
    assert cond.op == "masked_nonzero"
    assert [value.name for value in cond.args] == ["si", None]
    assert artifact.summary["condition_counts"] == {"masked_nonzero": 1}


def test_vex_import_preserves_ite_wrapped_condition_temp_for_exit() -> None:
    function = SimpleNamespace(addr=0x1000, block_addrs_set={0x1000}, info={})
    project = _project(
        {
            0x1000: _block(
                0x1000,
                _wrtmp(0, _get_register("si")),
                _wrtmp(1, _const(0)),
                _wrtmp(2, _binop("Iop_CmpNE16", _rdtmp(0), _rdtmp(1))),
                _wrtmp(3, _ite(_rdtmp(2), _const(0), _const(1))),
                _exit(_rdtmp(3), _const(0x1010)),
            )
        },
        function,
    )

    artifact = build_x86_16_ir_function_artifact(project, function)
    cond = artifact.blocks[0].instrs[-1].args[0]

    assert isinstance(cond, IRCondition)
    assert cond.op == "zero"
    assert [value.name for value in cond.args] == ["si"]


@pytest.mark.parametrize(
    ("guard_expr", "expected_op"),
    [
        (_flag_test(0x0040, is_set=True), "eq"),
        (_flag_test(0x0040, is_set=False), "ne"),
        (_flag_test(0x0001, is_set=True), "ult"),
        (_flag_test(0x0001, is_set=False), "uge"),
        (_binop("Iop_Or8", _flag_test(0x0001, is_set=True), _flag_test(0x0040, is_set=True)), "ule"),
        (_binop("Iop_And8", _flag_test(0x0001, is_set=False), _flag_test(0x0040, is_set=False)), "ugt"),
        (_flags_not_equal(0x0080, 0x0800), "slt"),
        (_flags_equal(0x0080, 0x0800), "sge"),
        (_binop("Iop_Or8", _flag_test(0x0040, is_set=True), _flags_not_equal(0x0080, 0x0800)), "sle"),
        (_binop("Iop_And8", _flag_test(0x0040, is_set=False), _flags_equal(0x0080, 0x0800)), "sgt"),
    ],
)
def test_vex_import_lifts_flag_formula_jcc_variants_to_typed_compare(guard_expr, expected_op) -> None:
    function = SimpleNamespace(addr=0x1000, block_addrs_set={0x1000}, info={})
    project = _project(
        {
            0x1000: _block(
                0x1000,
                _wrtmp(0, _get_register("ax")),
                _wrtmp(1, _get_register("bx")),
                _wrtmp(2, _binop("Iop_CmpEQ16", _rdtmp(0), _rdtmp(1))),
                _wrtmp(3, guard_expr),
                _exit(_rdtmp(3), _const(0x1010)),
            )
        },
        function,
    )

    artifact = build_x86_16_ir_function_artifact(project, function)
    cond = artifact.blocks[0].instrs[-1].args[0]

    assert isinstance(cond, IRCondition)
    assert cond.op == expected_op
    assert [value.name for value in cond.args] == ["ax", "bx"]


def test_vex_import_inverts_ite_wrapped_flag_formula_to_complement_compare() -> None:
    function = SimpleNamespace(addr=0x1000, block_addrs_set={0x1000}, info={})
    sgt_formula = _binop("Iop_And8", _flag_test(0x0040, is_set=False), _flags_equal(0x0080, 0x0800))
    project = _project(
        {
            0x1000: _block(
                0x1000,
                _wrtmp(0, _get_register("ax")),
                _wrtmp(1, _get_register("bx")),
                _wrtmp(2, _binop("Iop_CmpEQ16", _rdtmp(0), _rdtmp(1))),
                _wrtmp(3, _ite(sgt_formula, _const(0), _const(1))),
                _exit(_rdtmp(3), _const(0x1010)),
            )
        },
        function,
    )

    artifact = build_x86_16_ir_function_artifact(project, function)
    cond = artifact.blocks[0].instrs[-1].args[0]

    assert isinstance(cond, IRCondition)
    assert cond.op == "sle"
    assert [value.name for value in cond.args] == ["ax", "bx"]


def test_vex_import_records_successor_addrs_and_function_ssa() -> None:
    function = SimpleNamespace(addr=0x1000, block_addrs_set={0x1000, 0x1010, 0x1020}, info={})
    project = _project(
        {
            0x1000: _block(0x1000, _wrtmp(0, _get_register("ax")), next_expr=_const(0x1010)),
            0x1010: _block(0x1010, _wrtmp(0, _get_register("ax")), next_expr=_const(0x1020)),
            0x1020: _block(0x1020, _wrtmp(0, _get_register("ax"))),
        },
        function,
    )
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=0x1000))

    changed = apply_x86_16_vex_ir_artifact(project, codegen)

    assert changed is False
    assert codegen._inertia_vex_ir_artifact.blocks[0].successor_addrs == (0x1010,)
    assert codegen._inertia_vex_ir_function_ssa.summary["block_count"] == 3
    assert function.info["x86_16_vex_ir_function_ssa"]["summary"]["block_count"] == 3


def test_vex_import_reuses_coherent_artifacts_for_same_codegen_function() -> None:
    function = SimpleNamespace(addr=0x1000, block_addrs_set={0x1000}, info={})
    project = _project(
        {0x1000: _block(0x1000, _wrtmp(0, _get_register("ax")))},
        function,
    )
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=0x1000))

    apply_x86_16_vex_ir_artifact(project, codegen)
    first_artifact = codegen._inertia_vex_ir_artifact
    first_frame = codegen._inertia_vex_ir_frame
    first_ssa = codegen._inertia_vex_ir_function_ssa

    apply_x86_16_vex_ir_artifact(project, codegen)

    assert codegen._inertia_vex_ir_artifact is first_artifact
    assert codegen._inertia_vex_ir_frame is first_frame
    assert codegen._inertia_vex_ir_function_ssa is first_ssa


def test_vex_import_prefers_exact_function_graph_edges_over_low16_vex_successors() -> None:
    entry_node = SimpleNamespace(addr=0x11000)
    body_node = SimpleNamespace(addr=0x11010)
    function = SimpleNamespace(
        addr=0x11000,
        block_addrs_set={0x11000, 0x11010},
        graph=SimpleNamespace(edges=((entry_node, body_node), (body_node, entry_node))),
        info={},
    )
    project = _project(
        {
            0x11000: _block(0x11000, _wrtmp(0, _get_register("ax")), next_expr=_const(0x0010)),
            0x11010: _block(0x11010, _wrtmp(0, _get_register("ax")), next_expr=_const(0x0000)),
        },
        function,
    )
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=0x11000))

    apply_x86_16_vex_ir_artifact(project, codegen)

    blocks = codegen._inertia_vex_ir_artifact.blocks
    assert blocks[0].successor_addrs == (0x11010,)
    assert blocks[1].successor_addrs == (0x11000,)
    assert codegen._inertia_vex_ir_function_ssa.predecessor_map == {
        0x11000: (0x11010,),
        0x11010: (0x11000,),
    }


def test_apply_vex_ir_artifact_attaches_summary_to_codegen_and_function_info() -> None:
    function = SimpleNamespace(addr=0x1000, block_addrs_set={0x1000}, info={})
    project = _project(
        {0x1000: _block(0x1000, _wrtmp(0, _get_register("di")), _store(_rdtmp(0), _const(2)))},
        function,
    )
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=0x1000))

    changed = apply_x86_16_vex_ir_artifact(project, codegen)

    assert changed is False
    assert codegen._inertia_vex_ir_summary["instruction_count"] == 2
    assert function.info["x86_16_vex_ir_summary"]["instruction_count"] == 2
    assert "x86_16_vex_ir_function_ssa" in function.info


@pytest.mark.parametrize("expiry_phase", ["import", "collection", "boundary", "proof", "application"])
def test_import_deadline_refuses_without_starting_later_work(monkeypatch, expiry_phase: str) -> None:
    clock = [10.0]
    monkeypatch.setattr(deadline_owner.time, "monotonic", lambda: clock[0])
    function = SimpleNamespace(addr=0x1000, block_addrs_set={0x1000}, info={})
    project = _project(
        {0x1000: _block(0x1000, _wrtmp(0, _get_register("ax")), SimpleNamespace(tag="Ist_Dirty"))},
        function,
    )
    original_import = importer._import_x86_16_function_surface_8616
    original_refusals = []
    called = []

    def expire_at(phase):
        clock[0] = {expiry_phase: 21.0}.get(phase, clock[0])

    def imported_surface(project, function):
        surface = original_import(project, function)
        original_refusals.extend(surface.refusals)
        if expiry_phase == "import":
            clock[0] = 21.0
            return surface
        decoded = decode_relative_edge(0x1000, b"\xeb\x00")
        assert isinstance(decoded, DecodedRelativeEdge)
        pending = TerminalJumpEvidence8616(
            retain=True,
            proven_target=None,
            refusals=(),
            failure=TerminalJumpRefusalReason8616.SELECTOR_WINDOW_UNPROVED,
            stats=TerminalJumpEvidenceStats8616(1, 1, 1, 0, 1),
            decoded=decoded,
        )
        return replace(surface, terminal_evidence={0x1000: pending})

    def collect(*args, **kwargs):
        called.append("collection")
        expire_at("collection")
        return ()

    def boundary(*args, **kwargs):
        called.append("boundary")
        expire_at("boundary")
        return None

    def prove(*args, **kwargs):
        called.append("proof")
        expire_at("proof")
        return SimpleNamespace()

    def apply(artifact, proof):
        called.append("application")
        clock[0] = 21.0
        return EntryJumpDomainApplication8616(
            EntryJumpDomainApplicationStatus8616.EMPTY, artifact.blocks, (), (),
        )

    def forbid(*args, **kwargs):
        pytest.fail("expired import started finalization")

    monkeypatch.setattr(importer, "_import_x86_16_function_surface_8616", imported_surface)
    monkeypatch.setattr(importer, "_entry_domain_call_preservations_8616", collect)
    monkeypatch.setattr(importer, "entry_domain_caller_boundary_8616", boundary)
    monkeypatch.setattr(importer, "prove_entry_jump_domains_8616", prove)
    monkeypatch.setattr(importer, "apply_entry_jump_domain_8616", apply)
    monkeypatch.setattr(importer, "_finalize_x86_16_ir_artifact_8616", forbid)
    with deadline_owner.direct_evidence_deadline_scope_8616(project, 20.0):
        artifact = build_x86_16_ir_function_artifact(project, function)
    assert project._inertia_direct_evidence_deadline_8616 is None
    assert [instr.op for instr in artifact.blocks[0].instrs] == ["MOV"]
    assert artifact.refusals[:-1] == tuple(original_refusals)
    assert artifact.blocks[0].refusals == tuple(original_refusals)
    assert artifact.refusals[-1].kind == importer.IRImportRefusalReason8616.DIRECT_EVIDENCE_DEADLINE_EXPIRED.value
    assert artifact.logical_memory is None and artifact.condition_evidence is None
    assert artifact.summary == {}
    assert called == {
        "import": [],
        "collection": ["collection"],
        "boundary": ["collection", "boundary"],
        "proof": ["collection", "boundary", "proof"],
        "application": ["collection", "boundary", "proof", "application"],
    }[expiry_phase]
    publication = publish_function_ir_artifact_8616(project, artifact)
    assert publication.verdict is FunctionIRArtifactVerdict8616.UNKNOWN_REFUSE
    assert publication.failure is FunctionIRArtifactFailure8616.ARTIFACT_REFUSED
    assert publication.artifact is None
    assert registered_function_ir_artifact_8616(project, function.addr).artifact is None


@pytest.mark.parametrize("deadline", [None, 20.0])
def test_import_unexpired_deadline_keeps_normalization_and_restores_slot(monkeypatch, deadline: float | None) -> None:
    monkeypatch.setattr(deadline_owner.time, "monotonic", lambda: 10.0)
    function = SimpleNamespace(addr=0x1000, block_addrs_set={0x1000}, info={})
    project = _project({0x1000: _block(0x1000, _wrtmp(0, _get_register("ax")))}, function)
    with deadline_owner.direct_evidence_deadline_scope_8616(project, deadline):
        artifact = build_x86_16_ir_function_artifact(project, function)
    assert artifact.logical_memory is not None
    assert artifact.summary["instruction_count"] == 1
    assert not artifact.refusals
    if deadline is not None:
        assert project._inertia_direct_evidence_deadline_8616 is None
    else:
        assert not hasattr(project, "_inertia_direct_evidence_deadline_8616")


def test_attached_expired_ir_is_rebuilt_after_deadline_scope_exits(monkeypatch) -> None:
    monkeypatch.setattr(deadline_owner.time, "monotonic", lambda: 10.0)
    function = SimpleNamespace(addr=0x1000, block_addrs_set={0x1000}, info={})
    project = _project({0x1000: _block(0x1000, _wrtmp(0, _get_register("ax")))}, function)
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=0x1000))
    with deadline_owner.direct_evidence_deadline_scope_8616(project, 9.0):
        apply_x86_16_vex_ir_artifact(project, codegen)
    partial = codegen._inertia_vex_ir_artifact
    assert partial.refusals[-1].kind == importer.IRImportRefusalReason8616.DIRECT_EVIDENCE_DEADLINE_EXPIRED.value
    assert registered_function_ir_artifact_8616(project, function.addr).artifact is None

    apply_x86_16_vex_ir_artifact(project, codegen)
    assert codegen._inertia_vex_ir_artifact is not partial
    assert codegen._inertia_vex_ir_artifact.logical_memory is not None
    assert not codegen._inertia_vex_ir_artifact.refusals
    assert registered_function_ir_artifact_8616(project, function.addr).artifact is codegen._inertia_vex_ir_artifact


def test_attached_non_deadline_refusal_is_reused_without_relift(monkeypatch) -> None:
    function = SimpleNamespace(addr=0x1000, block_addrs_set={0x1000}, info={})
    project = _project(
        {0x1000: _block(0x1000, _wrtmp(0, _get_register("ax")), SimpleNamespace(tag="Ist_Dirty"))},
        function,
    )
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=0x1000))
    original_block = project.factory.block
    calls = []

    def tracked_block(*args, **kwargs):
        calls.append(args[0])
        return original_block(*args, **kwargs)

    monkeypatch.setattr(project.factory, "block", tracked_block)
    apply_x86_16_vex_ir_artifact(project, codegen)
    refused = codegen._inertia_vex_ir_artifact
    assert refused.refusals
    assert all(
        refusal.kind != importer.IRImportRefusalReason8616.DIRECT_EVIDENCE_DEADLINE_EXPIRED.value
        for refusal in refused.refusals
    )
    assert refused.logical_memory is not None

    apply_x86_16_vex_ir_artifact(project, codegen)
    assert codegen._inertia_vex_ir_artifact is refused
    assert calls == [0x1000]
    assert registered_function_ir_artifact_8616(project, function.addr).artifact is None


def test_import_uses_earliest_active_session_deadline_and_restores_outer_slot(monkeypatch) -> None:
    monkeypatch.setattr(deadline_owner.time, "monotonic", lambda: 10.0)
    function = SimpleNamespace(addr=0x1000, block_addrs_set={0x1000}, info={})
    project = _project({0x1000: _block(0x1000, _wrtmp(0, _get_register("ax")))}, function)
    project._inertia_direct_evidence_deadline_8616 = 30.0
    project._inertia_entry_domain_call_resolution_8616 = SimpleNamespace(deadline=9.0)
    project._inertia_entry_domain_premise_resolution_8616 = SimpleNamespace(deadline=25.0)
    with deadline_owner.direct_evidence_deadline_scope_8616(project, 20.0):
        assert project._inertia_direct_evidence_deadline_8616 == 9.0
        artifact = build_x86_16_ir_function_artifact(project, function)
    assert project._inertia_direct_evidence_deadline_8616 == 30.0
    assert artifact.refusals[-1].kind == importer.IRImportRefusalReason8616.DIRECT_EVIDENCE_DEADLINE_EXPIRED.value
    assert artifact.blocks[0].instrs
