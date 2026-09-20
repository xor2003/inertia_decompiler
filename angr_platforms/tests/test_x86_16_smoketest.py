import io
from types import SimpleNamespace

import angr
import keystone as ks
import pyvex
from angr import options as o
from angr.analyses.decompiler.structured_codegen.c import CVariable
from angr.sim_type import (
    SimTypeChar,
    SimTypeFunction,
    SimTypeInt,
    SimTypeLong,
    SimTypePointer,
    SimTypeShort,
)
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16.annotations import apply_x86_16_metadata_annotations, decompile_function
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.lift_86_16 import Lifter86_16  # noqa: F401
from angr_platforms.X86_16.simos_86_16 import SimCC8616MSCsmall  # noqa: F401
from pyvex.expr import Const as VexConst
from pyvex.stmt import Exit as VexExit

from decompile import _resolve_stack_cvar_at_offset


def _project_from_bytes(code: bytes):
    return angr.Project(
        io.BytesIO(code),
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": 0x1000,
            "entry_point": 0x1000,
        },
    )


def _project_from_asm(asm: str):
    ks_ = ks.Ks(ks.KS_ARCH_X86, ks.KS_MODE_16)
    code, _ = ks_.asm(asm, as_bytes=True)
    return _project_from_bytes(bytes(code))


def _assert_word_signature(func, arg_count: int):
    assert func.prototype is not None
    assert len(func.prototype.args) == arg_count
    assert all(isinstance(arg, SimTypeInt) and arg.size == 16 for arg in func.prototype.args)
    assert isinstance(func.prototype.returnty, SimTypeInt)
    assert func.prototype.returnty.size == 16


def _assert_long_signature(func, arg_count: int):
    assert func.prototype is not None
    assert len(func.prototype.args) == arg_count
    assert all(isinstance(arg, SimTypeLong) and arg.size == 32 for arg in func.prototype.args)
    assert isinstance(func.prototype.returnty, SimTypeLong)
    assert func.prototype.returnty.size == 32


def test_mov_add_ret_smoke():
    code = b"\xb8\x01\x00\x05\x02\x00\xc3"  # mov ax,1; add ax,2; ret
    project = _project_from_bytes(code)

    block = project.factory.block(0x1000, len(code))
    irsb = block.vex

    assert irsb.jumpkind == "Ijk_Ret"
    assert any(stmt.__class__.__name__ == "Put" for stmt in irsb.statements)
    assert "Add16" in irsb._pp_str()

    cfg = project.analyses.CFGFast(normalize=True)
    dec = project.analyses.Decompiler(cfg.functions[0x1000], cfg=cfg)
    assert dec.codegen is not None
    assert "return 3;" in dec.codegen.text


def test_reg_reg_arithmetic_smoke():
    project = _project_from_asm("mov ax,1; mov bx,2; add ax,bx; ret")

    cfg = project.analyses.CFGFast(normalize=True)
    dec = project.analyses.Decompiler(cfg.functions[0x1000], cfg=cfg)
    assert dec.codegen is not None
    assert "return 3;" in dec.codegen.text


def test_cmp_je_lifts():
    project = _project_from_asm("mov ax,1; cmp ax,1; je done; mov ax,9; done: ret")
    code = project.loader.memory.load(0x1000, project.loader.main_object.max_addr - 0x1000 + 1)

    irsb = project.factory.block(0x1000, len(code)).vex
    assert irsb.jumpkind == "Ijk_Boring"
    assert "CmpEQ16" in irsb._pp_str()


def test_simple_je_short_targets_branch_destination():
    project = _project_from_bytes(bytes.fromhex("74 02 b8 01 00 c3"))  # je +2; mov ax,1; ret

    block = project.factory.block(0x1000, opt_level=0)
    assert block.vex.jumpkind == "Ijk_Boring"
    assert isinstance(block.vex.next, VexConst)
    assert block.vex.next.con.value == 0x1004
    assert [statement.dst.value for statement in block.vex.statements if isinstance(statement, VexExit)] == [0x1002]


def test_simple_je_near_targets_branch_destination():
    project = _project_from_bytes(bytes.fromhex("0f840200b80100c3"))  # je +2; mov ax,1; ret

    block = project.factory.block(0x1000, opt_level=0)
    assert block.vex.jumpkind == "Ijk_Boring"
    assert isinstance(block.vex.next, VexConst)
    assert block.vex.next.con.value == 0x1006
    assert [statement.dst.value for statement in block.vex.statements if isinstance(statement, VexExit)] == [0x1004]


def test_loop_uses_direct_linear_backedge_above_first_64k():
    """LOOP must expose its static DOS-image backedge without a runtime IP read."""
    irsb = pyvex.lift(bytes.fromhex("e2fd"), 0x1107C, Arch86_16(), max_inst=1, opt_level=0)

    assert isinstance(irsb.next, VexConst)
    assert irsb.next.con.value == 0x1107B
    assert "GET:I16(ip)" not in irsb._pp_str()


def test_bound_16bit_addressing_lifts():
    code = b"\x67\x62\x07"  # bound ax, [bx]
    project = angr.load_shellcode(
        code,
        arch=Arch86_16(),
        start_offset=0x100,
        load_address=0x100,
        selfmodifying_code=False,
        rebase_granularity=0x1000,
    )

    block = project.factory.block(0x100, size=len(code), opt_level=0)
    assert block.vex is not None
    assert block.vex.jumpkind == "Ijk_Call"
    assert block.capstone.insns[0].mnemonic == "bound"


def test_enter_local_stack_smoke():
    project = _project_from_asm("enter 2, 0; mov word ptr [bp-2], 1; mov ax, [bp-2]; leave; ret")

    cfg = project.analyses.CFGFast(normalize=True)
    dec = project.analyses.Decompiler(cfg.functions[0x1000], cfg=cfg)
    assert dec.codegen is not None
    assert " = 1;" in dec.codegen.text
    assert "return 1;" in dec.codegen.text
    assert "return Load(" not in dec.codegen.text
    assert "*((char **)(ir_0 * 16 + (unsigned int)&s_2)) = &s_0;" not in dec.codegen.text


def test_resolve_stack_cvar_at_offset_prefers_exact_stack_slots():
    class _DummyCodegen:
        def __init__(self):
            self.cfunc = SimpleNamespace(variables_in_use={})
            self._idx = 0

        def next_idx(self, _kind):
            self._idx += 1
            return self._idx
        def next_node_idx(self) -> int:
            return self.next_idx("")
        def next_ident(self, name: str) -> str:
            return name

    codegen = _DummyCodegen()
    frame = SimStackVariable(0, 2, base="bp", name="frame", region=0x1000)
    arg = SimStackVariable(4, 2, base="bp", name="arg", region=0x1000)
    alias = SimStackVariable(4, 2, base="bp", name="s_3", region=0x1000)
    frame_cvar = CVariable(frame, codegen=codegen)
    arg_cvar = CVariable(arg, codegen=codegen)
    alias_cvar = CVariable(alias, codegen=codegen)
    codegen.cfunc.variables_in_use = {frame: frame_cvar, alias: alias_cvar, arg: arg_cvar}

    assert _resolve_stack_cvar_at_offset(codegen, 4) is arg_cvar
    assert _resolve_stack_cvar_at_offset(codegen, 5) is arg_cvar


def test_resolve_stack_cvar_at_offset_prefers_arg_list_candidates():
    class _DummyCodegen:
        def __init__(self):
            self.cfunc = SimpleNamespace(variables_in_use={})
            self._idx = 0

        def next_idx(self, _kind):
            self._idx += 1
            return self._idx
        def next_node_idx(self) -> int:
            return self.next_idx("")
        def next_ident(self, name: str) -> str:
            return name

    codegen = _DummyCodegen()
    arg = SimStackVariable(4, 2, base="bp", name="arg", region=0x1000)
    alias = SimStackVariable(4, 2, base="bp", name="s_3", region=0x1000)
    arg_cvar = CVariable(arg, codegen=codegen)
    alias_cvar = CVariable(alias, codegen=codegen)
    codegen.cfunc.arg_list = [arg_cvar]
    codegen.cfunc.variables_in_use = {alias: alias_cvar}

    assert _resolve_stack_cvar_at_offset(codegen, 4) is arg_cvar


def test_near_call_smoke():
    code = bytes.fromhex("e80100c3b80300c3")  # call 0x1004; ret; mov ax,3; ret
    project = _project_from_bytes(code)

    cfg = project.analyses.CFGFast(normalize=True)
    assert 0x1004 in cfg.functions

    caller = project.analyses.Decompiler(cfg.functions[0x1000], cfg=cfg)
    callee = project.analyses.Decompiler(cfg.functions[0x1004], cfg=cfg)

    assert caller.codegen is not None
    assert callee.codegen is not None
    assert "sub_1004()" in caller.codegen.text
    assert "return 3;" in callee.codegen.text


def test_indirect_near_call_lifts_as_call_edge():
    code = bytes.fromhex("b80510ffd0c3")  # mov ax,0x1005; call ax; ret
    project = _project_from_bytes(code)

    block = project.factory.block(0x1000, opt_level=0)
    asm = "\n".join(f"{insn.mnemonic} {insn.op_str}".strip() for insn in block.capstone.insns).lower()

    assert block.vex.jumpkind == "Ijk_Call"
    assert "PUT(sp)" in block.vex._pp_str()
    assert "call ax" in asm
    assert "ret" not in asm


def test_short_jmp_lifts_as_boring_jump():
    code = bytes.fromhex("eb02b80100c3")  # jmp short +2; mov ax,1; ret
    project = _project_from_bytes(code)

    block = project.factory.block(0x1000, opt_level=0)
    asm = "\n".join(f"{insn.mnemonic} {insn.op_str}".strip() for insn in block.capstone.insns).lower()

    assert block.vex.jumpkind == "Ijk_Boring"
    assert "jmp 0x1004" in asm
    assert "mov" not in asm


def test_jcxz_lifts_as_a_boring_conditional_jump():
    code = bytes.fromhex("e302b80100c3")  # jcxz +2; mov ax,1; ret
    project = _project_from_bytes(code)

    block = project.factory.block(0x1000, opt_level=0)
    vex_text = block.vex._pp_str()

    assert block.vex.jumpkind == "Ijk_Boring"
    assert block.capstone.insns[0].mnemonic == "jcxz"
    assert "if (" in vex_text
    assert "PUT(ip) = 0x1002" in vex_text


def test_indirect_near_jump_lifts_as_boring_jump():
    code = bytes.fromhex("b80510ffe0c3")  # mov ax,0x1005; jmp ax; ret
    project = _project_from_bytes(code)

    block = project.factory.block(0x1000, opt_level=0)
    asm = "\n".join(f"{insn.mnemonic} {insn.op_str}".strip() for insn in block.capstone.insns).lower()

    assert block.vex.jumpkind == "Ijk_Boring"
    assert "jmp ax" in asm
    assert "ret" not in asm


def test_immediate_far_call_lifts_as_call_edge():
    code = bytes.fromhex("9a08003412c3")  # call far 1234:0008; retf
    project = _project_from_bytes(code)

    block = project.factory.block(0x1000, opt_level=0)

    assert block.vex.jumpkind == "Ijk_Call"
    assert "PUT(cs)" in block.vex._pp_str()
    assert "PUT(d)" not in block.vex._pp_str()
    assert "lcall" in "\n".join(f"{insn.mnemonic} {insn.op_str}".strip().lower() for insn in block.capstone.insns)


def test_immediate_far_jump_lifts_as_boring_jump():
    code = bytes.fromhex("ea08003412")  # jmp far 1234:0008
    project = _project_from_bytes(code)

    block = project.factory.block(0x1000, opt_level=0)

    assert block.vex.jumpkind == "Ijk_Boring"
    assert "ljmp" in "\n".join(f"{insn.mnemonic} {insn.op_str}".strip().lower() for insn in block.capstone.insns)


def test_retf_imm16_lifts_and_adjusts_stack():
    code = bytes.fromhex("ca0400")  # retf 4
    project = _project_from_bytes(code)

    block = project.factory.block(0x1000, opt_level=0)
    vex_text = block.vex._pp_str()

    assert block.vex.jumpkind == "Ijk_Ret"
    assert "PUT(sp)" in vex_text
    assert "PUT(cs)" in vex_text


def test_retf_lifts_as_return():
    code = bytes.fromhex("cb")  # retf
    project = _project_from_bytes(code)

    block = project.factory.block(0x1000, opt_level=0)
    vex_text = block.vex._pp_str()

    assert block.vex.jumpkind == "Ijk_Ret"
    assert "PUT(cs)" in vex_text


def test_retn_imm16_lifts_and_adjusts_stack():
    code = bytes.fromhex("c20400")  # ret 4 / retn 4
    project = _project_from_bytes(code)

    block = project.factory.block(0x1000, opt_level=0)
    vex_text = block.vex._pp_str()

    assert block.vex.jumpkind == "Ijk_Ret"
    assert "PUT(sp)" in vex_text


def test_xlat_lifts_as_table_lookup():
    project = _project_from_bytes(bytes.fromhex("d7"))

    block = project.factory.block(0x1000, opt_level=0)
    vex_text = block.vex._pp_str()

    assert block.vex.jumpkind == "Ijk_Boring"
    assert "LDle:I8" in vex_text
    assert "PUT(al)" in vex_text
    assert "PUT(ax)" not in vex_text


def test_esc_memory_form_lifts_as_a_harmless_fpu_escape():
    project = _project_from_bytes(bytes.fromhex("d800"))

    block = project.factory.block(0x1000, opt_level=0)
    vex_text = block.vex._pp_str()

    assert block.vex.jumpkind == "Ijk_Boring"
    assert block.capstone.insns[0].mnemonic == "fadd"
    assert "LDle:I8" in vex_text


def test_msvc_emulated_x87_interrupt_consumes_modrm_operand():
    # MS C can encode `fwait; fld dword ptr [bp+8]` as `int 35h` plus the
    # original D9 ModR/M payload. The frontend must consume the operand bytes
    # as one non-control-flow instruction, not decode them as integer opcodes.
    project = _project_from_bytes(bytes.fromhex("cd354608c3"))

    block = project.factory.block(0x1000, opt_level=0)
    vex_text = block.vex._pp_str()

    assert block.vex.jumpkind == "Ijk_Ret"
    assert block.vex.size == 5
    assert "Ijk_Call" not in vex_text
    assert "LDle:I8" in vex_text


def test_msvc_emulated_x87_wait_is_not_an_interrupt_call():
    project = _project_from_bytes(bytes.fromhex("cd3dc3"))

    block = project.factory.block(0x1000, opt_level=0)
    vex_text = block.vex._pp_str()

    assert block.vex.jumpkind == "Ijk_Ret"
    assert block.vex.size == 3
    assert "Ijk_Call" not in vex_text


def test_rep_movsb_decompiles_to_typed_string_intrinsic_without_double_negation():
    project = _project_from_bytes(bytes.fromhex("b90200f3a4c3"))  # mov cx,2; rep movsb; ret

    cfg = project.analyses.CFGFast(normalize=True)
    dec = project.analyses.Decompiler(cfg.functions[0x1000], cfg=cfg)
    assert dec.codegen is not None
    text = dec.codegen.text
    assert "void __x86_16_movs(unsigned short width);" in text
    assert "__x86_16_movs(1);" in text
    assert "memcpy_class" not in text
    assert "goto " not in text
    assert "!(!(" not in text


def test_rep_movsw_decompiles_to_typed_string_intrinsic():
    project = _project_from_bytes(bytes.fromhex("b90200f3a5c3"))  # mov cx,2; rep movsw; ret

    cfg = project.analyses.CFGFast(normalize=True)
    dec = project.analyses.Decompiler(cfg.functions[0x1000], cfg=cfg)
    assert dec.codegen is not None
    text = dec.codegen.text
    assert "void __x86_16_movs(unsigned short width);" in text
    assert "__x86_16_movs(2);" in text
    assert "memcpy_class" not in text
    assert "goto " not in text


def test_movsb_lifts_and_updates_indices():
    project = _project_from_bytes(bytes.fromhex("a4"))

    block = project.factory.block(0x1000, opt_level=0)
    vex_text = block.vex._pp_str()

    assert block.vex.jumpkind == "Ijk_Boring"
    assert "LDle:I8" in vex_text
    assert "STle" in vex_text
    assert "PUT(si)" in vex_text
    assert "PUT(di)" in vex_text


def test_direct_absolute_memory_add_executes_as_bytes_with_one_semantic_write():
    from angr_platforms.X86_16.ir.logical_memory_capture import (
        collect_accesses_for_block,
        collect_accesses_for_function,
    )
    from angr_platforms.X86_16.ir.logical_memory_contracts import IRMemoryAccessKind8616

    project = _project_from_bytes(bytes.fromhex("8306480002"))  # add word ptr [0x48],2

    with collect_accesses_for_function(0x1000) as capture, collect_accesses_for_block(0x1000):
        block = project.factory.block(0x1000, num_inst=1, opt_level=0, collect_data_refs=True)
    store_count = sum(1 for stmt in block.vex.statements if stmt.tag == "Ist_Store")
    writes = tuple(access for access in capture.accesses if access.kind is IRMemoryAccessKind8616.WRITE)

    assert store_count == 2
    assert tuple((write.block_addr, write.insn_addr, write.address_bits, write.address.size) for write in writes) == (
        (0x1000, 0x1000, 16, 2),
    )
    assert "0x0048" in block.vex._pp_str()


def test_wait_lifts_as_a_boring_noop():
    project = _project_from_bytes(bytes.fromhex("9b"))

    block = project.factory.block(0x1000, opt_level=0)
    assert block.vex.jumpkind == "Ijk_Boring"
    assert isinstance(block.vex.next, VexConst)
    assert block.vex.next.con.value == 0x1001
    assert block.capstone.insns[0].mnemonic == "wait"


def test_hlt_lifts_as_a_boring_stop_instruction():
    project = _project_from_bytes(bytes.fromhex("f4"))

    block = project.factory.block(0x1000, opt_level=0)
    assert block.vex.jumpkind == "Ijk_Boring"
    assert isinstance(block.vex.next, VexConst)
    assert block.vex.next.con.value == 0x1001
    assert block.capstone.insns[0].mnemonic == "hlt"


def test_flag_control_instructions_smoke():
    cases = (
        (bytes.fromhex("fa"), 9, 0),  # cli
        (bytes.fromhex("fb"), 9, 1),  # sti
        (bytes.fromhex("fc"), 10, 0),  # cld
        (bytes.fromhex("fd"), 10, 1),  # std
    )

    for code, bit, expected in cases:
        project = _project_from_bytes(code)
        state = project.factory.blank_state(
            add_options={o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS}
        )
        state.regs.flags = 0xFFFF

        simgr = project.factory.simgr(state)
        simgr.step(num_inst=1, insn_bytes=code)
        assert len(simgr.active) == 1

        result = simgr.active[0]
        assert result.solver.eval(result.regs.flags[bit]) == expected


def test_lock_prefix_add_executes_like_unlocked_add():
    unlocked = _project_from_bytes(bytes.fromhex("0107"))
    locked = _project_from_bytes(bytes.fromhex("f00107"))

    def _run(project, code: bytes):
        state = project.factory.blank_state(
            add_options={o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS}
        )
        state.regs.ax = 0x1234
        state.regs.bx = 0x0200
        state.regs.ds = 0
        state.memory.store(0x0200, b"\x78\x56")

        simgr = project.factory.simgr(state)
        simgr.step(num_inst=1, insn_bytes=code)
        assert len(simgr.active) == 1
        return simgr.active[0]

    unlocked_state = _run(unlocked, bytes.fromhex("0107"))
    locked_state = _run(locked, bytes.fromhex("f00107"))

    assert locked.factory.block(0x1000, opt_level=0).capstone.insns[0].mnemonic == "lock add"
    assert (
        unlocked_state.solver.eval(unlocked_state.memory.load(0x0200, 2, endness=unlocked_state.arch.memory_endness))
        == 0x68AC
    )
    assert (
        locked_state.solver.eval(locked_state.memory.load(0x0200, 2, endness=locked_state.arch.memory_endness))
        == 0x68AC
    )
    assert unlocked_state.solver.eval(unlocked_state.regs.ax) == locked_state.solver.eval(locked_state.regs.ax)
    for bit in (0, 2, 6, 7, 11):
        assert unlocked_state.solver.eval(unlocked_state.regs.flags[bit]) == locked_state.solver.eval(
            locked_state.regs.flags[bit]
        )


def test_into_lifts_as_conditional_interrupt_call():
    project = _project_from_bytes(bytes.fromhex("ce"))

    block = project.factory.block(0x1000, opt_level=0)
    vex_text = block.vex._pp_str()

    assert block.vex.jumpkind == "Ijk_Call"
    assert block.vex.next.con.value == 0xFF004
    assert "if (" in vex_text


def test_insb_lifts_with_io_helper_and_di_update():
    project = _project_from_bytes(bytes.fromhex("6c"))

    block = project.factory.block(0x1000, opt_level=0)
    vex_text = block.vex._pp_str()

    assert block.vex.jumpkind == "Ijk_Boring"
    assert "x86g_dirtyhelper_IN" in vex_text
    assert "PUT(di)" in vex_text


def test_outsw_lifts_with_io_helper_and_si_update():
    project = _project_from_bytes(bytes.fromhex("6f"))

    block = project.factory.block(0x1000, opt_level=0)
    vex_text = block.vex._pp_str()

    assert block.vex.jumpkind == "Ijk_Boring"
    assert "x86g_dirtyhelper_OUT" in vex_text
    assert "PUT(si)" in vex_text


def test_indirect_far_call_lifts_as_call_edge():
    code = bytes.fromhex("ff1e0610c3c308003412")  # call far [0x1006]
    project = _project_from_bytes(code)

    block = project.factory.block(0x1000, opt_level=0)

    assert block.vex.jumpkind == "Ijk_Call"
    assert "PUT(cs)" in block.vex._pp_str()
    assert "lcall" in "\n".join(f"{insn.mnemonic} {insn.op_str}".strip().lower() for insn in block.capstone.insns)


def test_indirect_far_jump_lifts_as_boring_jump():
    code = bytes.fromhex("ff2e0610c3c308003412")  # jmp far [0x1006]
    project = _project_from_bytes(code)

    block = project.factory.block(0x1000, opt_level=0)

    assert block.vex.jumpkind == "Ijk_Boring"
    assert "ljmp" in "\n".join(f"{insn.mnemonic} {insn.op_str}".strip().lower() for insn in block.capstone.insns)


def test_stack_arg_prototype_inference():
    project = _project_from_asm(
        "push bp; mov bp, sp; mov ax, [bp+4]; mov dx, [bp+6]; add ax, dx; pop bp; ret",
    )

    cfg = project.analyses.CFGFast(normalize=True)
    func = cfg.functions[0x1000]
    dec = project.analyses.Decompiler(func, cfg=cfg)

    assert dec.codegen is not None
    _assert_word_signature(func, 2)
    arg_names = [argument.variable.name for argument in dec.codegen.cfunc.arg_list]
    assert all(isinstance(name, str) for name in arg_names)
    assert f"return {arg_names[0]} + {arg_names[1]};" in dec.codegen.text


def test_single_word_arg_signature_and_return_type():
    project = _project_from_asm("push bp; mov bp, sp; mov ax, [bp+4]; add ax, 1; pop bp; ret")

    cfg = project.analyses.CFGFast(normalize=True)
    func = cfg.functions[0x1000]
    dec = project.analyses.Decompiler(func, cfg=cfg)

    assert dec.codegen is not None
    _assert_word_signature(func, 1)
    assert "return arg + 1;" in dec.codegen.text
    assert "return (Load(" not in dec.codegen.text


def test_no_arg_frame_function_does_not_gain_phantom_arg():
    project = _project_from_asm("push bp; mov bp, sp; mov ax, 7; pop bp; ret")

    cfg = project.analyses.CFGFast(normalize=True)
    func = cfg.functions[0x1000]
    dec = project.analyses.Decompiler(func, cfg=cfg)

    assert dec.codegen is not None
    _assert_word_signature(func, 0)
    assert "return 7;" in dec.codegen.text


def test_three_word_args_signature():
    project = _project_from_asm("push bp; mov bp, sp; mov ax, [bp+4]; add ax, [bp+6]; add ax, [bp+8]; pop bp; ret")

    cfg = project.analyses.CFGFast(normalize=True)
    func = cfg.functions[0x1000]
    dec = project.analyses.Decompiler(func, cfg=cfg)

    assert dec.codegen is not None
    _assert_word_signature(func, 3)
    assert "return" in dec.codegen.text


def test_compiler_conditional_decomp_simplifies_bool_ite():
    project = _project_from_asm(
        "push bp; mov bp, sp; mov ax, [bp+4]; cmp ax, 2; jle base; mov ax, 0; jmp done; "
        "base: mov ax, 1; done: pop bp; ret"
    )

    cfg = project.analyses.CFGFast(normalize=True)
    dec = project.analyses.Decompiler(cfg.functions[0x1000], cfg=cfg)

    assert dec.codegen is not None
    assert "? 0 : 1" not in dec.codegen.text
    assert "if ((short)arg > 2)\n        return 0;\n    return 1;" in dec.codegen.text
    assert dec.codegen.text.count("return 0;") == 1
    assert dec.codegen.text.count("return 1;") == 1
    assert "return 0;" in dec.codegen.text
    assert "return 1;" in dec.codegen.text


def test_conditional_two_word_args_signature():
    project = _project_from_asm(
        "push bp; mov bp, sp; mov ax, [bp+4]; cmp ax, [bp+6]; jle base; mov ax, 0; pop bp; ret; "
        "base: mov ax, 1; pop bp; ret"
    )

    cfg = project.analyses.CFGFast(normalize=True)
    func = cfg.functions[0x1000]
    dec = project.analyses.Decompiler(func, cfg=cfg)

    assert dec.codegen is not None
    _assert_word_signature(func, 2)
    assert "? 0 : 1" not in dec.codegen.text


def test_wide_return_inference():
    project = _project_from_asm("mov ax, 0x5678; mov dx, 0x1234; ret")

    cfg = project.analyses.CFGFast(normalize=True)
    func = cfg.functions[0x1000]
    dec = project.analyses.Decompiler(func, cfg=cfg)

    assert dec.codegen is not None
    _assert_long_signature(func, 0)
    assert "return" in dec.codegen.text


def test_wide_arg_and_return_inference():
    project = _project_from_asm("push bp; mov bp, sp; mov ax, [bp+4]; mov dx, [bp+6]; pop bp; ret")

    cfg = project.analyses.CFGFast(normalize=True)
    func = cfg.functions[0x1000]
    dec = project.analyses.Decompiler(func, cfg=cfg)

    assert dec.codegen is not None
    _assert_long_signature(func, 1)
    assert "return" in dec.codegen.text


def test_explicit_wide_return_codegen():
    project = _project_from_asm("mov ax, 0x5678; mov dx, 0x1234; ret")

    cfg = project.analyses.CFGFast(normalize=True)
    func = cfg.functions[0x1000]
    func.prototype = SimTypeFunction([], SimTypeLong()).with_arch(project.arch)
    func.is_prototype_guessed = False
    dec = project.analyses.Decompiler(func, cfg=cfg)

    assert dec.codegen is not None
    _assert_long_signature(func, 0)
    assert "return 305419896;" in dec.codegen.text


def test_explicit_near_pointer_prototype():
    project = _project_from_asm("push bp; mov bp, sp; mov ax, [bp+4]; pop bp; ret")

    cfg = project.analyses.CFGFast(normalize=True)
    func = cfg.functions[0x1000]
    func.prototype = SimTypeFunction([SimTypePointer(SimTypeChar())], SimTypePointer(SimTypeChar())).with_arch(
        project.arch
    )
    func.is_prototype_guessed = False
    dec = project.analyses.Decompiler(func, cfg=cfg)

    assert dec.codegen is not None
    arg_name = dec.codegen.cfunc.arg_list[0].variable.name
    assert isinstance(arg_name, str)
    assert f"char * _start(char *{arg_name})" in dec.codegen.text
    assert f"return {arg_name};" in dec.codegen.text


def test_explicit_far_pointer_like_prototype():
    project = _project_from_asm("push bp; mov bp, sp; mov ax, [bp+4]; mov dx, [bp+6]; pop bp; ret")

    cfg = project.analyses.CFGFast(normalize=True)
    func = cfg.functions[0x1000]
    func.prototype = SimTypeFunction([SimTypeLong(label="far_ptr")], SimTypeLong(label="far_ptr")).with_arch(
        project.arch
    )
    func.is_prototype_guessed = False
    dec = project.analyses.Decompiler(func, cfg=cfg)

    assert dec.codegen is not None
    assert "long _start" in dec.codegen.text
    arg_name = dec.codegen.cfunc.arg_list[0].variable.name
    assert isinstance(arg_name, str)
    assert f"return {arg_name};" in dec.codegen.text


def test_c_decl_annotation_applies_function_and_argument_names():
    project = _project_from_asm("push bp; mov bp, sp; mov ax, [bp+4]; add ax, [bp+6]; pop bp; ret")

    dec = decompile_function(project, 0x1000, c_decl="int add_words(int lhs, int rhs);")

    assert dec.codegen is not None
    assert "int add_words(int lhs, int rhs)" in dec.codegen.text
    assert "return lhs + rhs;" in dec.codegen.text or "return (unsigned short)lhs + rhs;" in dec.codegen.text


def test_stack_variable_annotation_applies_local_name():
    project = _project_from_asm(
        "push bp; mov bp, sp; sub sp, 2; mov ax, [bp+4]; add ax, [bp+6]; "
        "mov [bp-2], ax; mov ax, [bp-2]; mov sp, bp; pop bp; ret"
    )

    dec = decompile_function(
        project,
        0x1000,
        c_decl="int add_store(int lhs, int rhs);",
        stack_vars={-4: "total"},
    )

    assert dec.codegen is not None
    assert "int add_store(int lhs, int rhs)" in dec.codegen.text
    assert "unsigned short total;" in dec.codegen.text
    assert "unsigned char total;" not in dec.codegen.text
    assert "unsigned int total;" not in dec.codegen.text
    assert "unsigned int rhs;" not in dec.codegen.text
    assert "total = lhs + rhs;" in dec.codegen.text


def test_stack_variable_annotation_preserves_explicit_type():
    project = _project_from_asm(
        "push bp; mov bp, sp; sub sp, 2; mov ax, [bp+4]; add ax, [bp+6]; "
        "mov [bp-2], ax; mov ax, [bp-2]; mov sp, bp; pop bp; ret"
    )

    dec = decompile_function(
        project,
        0x1000,
        c_decl="int add_store_bp(int lhs, int rhs);",
        bp_stack_vars={-2: {"name": "sum_local", "type": SimTypeShort(False)}},
    )

    assert dec.codegen is not None
    assert "unsigned short sum_local;" in dec.codegen.text
    assert "unsigned char sum_local;" not in dec.codegen.text
    assert "unsigned int sum_local;" not in dec.codegen.text
    assert "sum_local = lhs + rhs;" in dec.codegen.text
    annotations = project.kb.functions[0x1000].info["x86_16_annotations"]["stack_vars"]
    assert annotations[-4]["name"] == "sum_local"
    assert annotations[-4]["type"] == SimTypeShort(False)


def test_bp_relative_stack_annotation_uses_assembly_displacement():
    project = _project_from_asm(
        "push bp; mov bp, sp; sub sp, 2; mov ax, [bp+4]; add ax, [bp+6]; "
        "mov [bp-2], ax; mov ax, [bp-2]; mov sp, bp; pop bp; ret"
    )

    dec = decompile_function(
        project,
        0x1000,
        c_decl="int add_store_bp(int lhs, int rhs);",
        bp_stack_vars={-2: "sum_local"},
    )

    assert dec.codegen is not None
    assert "unsigned short sum_local;" in dec.codegen.text
    assert "unsigned char sum_local;" not in dec.codegen.text
    assert "unsigned int sum_local;" not in dec.codegen.text
    assert "sum_local = lhs + rhs;" in dec.codegen.text


def test_global_variable_annotation_applies_global_names():
    project = _project_from_asm("mov ax, [0x1234]; add ax, [0x1236]; mov [0x1238], ax; ret")

    dec = decompile_function(
        project,
        0x1000,
        global_vars={
            0x1234: {"name": "left_word", "type": SimTypeShort(False)},
            0x1236: {"name": "right_word", "type": SimTypeShort(False)},
            0x1238: {"name": "sum_word", "type": SimTypeShort(False)},
        },
    )

    assert dec.codegen is not None
    assert "left_word" in dec.codegen.text
    assert "right_word" in dec.codegen.text
    assert "sum_word" in dec.codegen.text
    assert "field_" not in dec.codegen.text
    annotations = project.kb.functions[0x1000].info["x86_16_annotations"]["global_vars"]
    assert annotations[0x1234]["name"] == "left_word"
    assert annotations[0x1234]["type"] == SimTypeShort(False)


def test_metadata_annotations_apply_before_decompilation():
    project = _project_from_asm("ret")
    cfg = project.analyses.CFGFast(normalize=True)
    func = cfg.functions[0x1000]

    changed = apply_x86_16_metadata_annotations(
        project,
        func_addr=func.addr,
        cod_metadata=SimpleNamespace(
            call_names=("joyOrKey",),
            stack_aliases={4: "lhs", 6: "rhs"},
        ),
        lst_metadata=SimpleNamespace(
            data_labels={0x1234: "data_label"},
            code_labels={0x1000: "entry_label"},
        ),
        synthetic_globals={0x2000: ("rin", 14)},
    )

    assert changed is True
    assert project.kb.labels[0x1234] == "data_label"
    assert project.kb.labels[0x2000] == "rin"
    assert project.kb.functions[0x1000].name == "entry_label"
    annotations = project.kb.functions[0x1000].info.get("x86_16_annotations", {})
    assert not annotations.get("stack_vars")
    assert not annotations.get("global_vars")


def test_cod_call_names_do_not_apply_helper_signatures_before_decompilation():
    project = _project_from_asm("ret")
    helper = project.kb.functions.function(addr=0x2000, create=True)
    helper.name = "joyOrKey"
    changed = apply_x86_16_metadata_annotations(
        project,
        func_addr=0x2000,
        cod_metadata=SimpleNamespace(call_names=("joyOrKey",)),
    )

    assert changed is False
    assert project.kb.functions.function(addr=0x2000, create=False).prototype is None


def test_cod_source_decl_is_not_recorded_as_recovered_prototype_evidence():
    project = _project_from_asm("ret")
    func = project.kb.functions.function(addr=0x1000, create=True)
    func.name = "Demo"
    func.prototype = SimTypeFunction([SimTypeShort(False)], SimTypeShort(False), arg_names=("value",)).with_arch(
        project.arch
    )
    original_prototype = func.prototype
    original_cc = func.calling_convention
    changed = apply_x86_16_metadata_annotations(
        project,
        func_addr=0x1000,
        cod_metadata=SimpleNamespace(
            call_names=(),
            source_lines=(
                "void Demo(short value)",
                "{",
                "}",
            ),
            stack_aliases={},
        ),
    )

    assert changed is False
    updated_func = project.kb.functions.function(addr=0x1000, create=False)
    updated = updated_func.prototype
    updated_cc = project.kb.functions.function(addr=0x1000, create=False).calling_convention
    assert updated is original_prototype
    assert updated_cc is original_cc
    assert isinstance(updated.returnty, SimTypeShort)
    assert len(updated.args) == 1
    assert isinstance(updated.args[0], SimTypeShort)
    assert not updated_func.info.get("x86_16_annotations", {}).get("source_lines")


def test_synthetic_global_annotation_preserves_name_only():
    project = _project_from_asm("mov ax, [0x1234]; ret")

    dec = decompile_function(
        project,
        0x1000,
        synthetic_globals={0x1234: ("rin", 14)},
    )

    assert dec.codegen is not None
    assert project.kb.labels[0x1234] == "rin"
    annotations = project.kb.functions[0x1000].info.get("x86_16_annotations", {})
    assert not annotations.get("global_vars")


def test_c_decl_annotation_applies_pointer_signature():
    project = _project_from_asm("push bp; mov bp, sp; mov ax, [bp+4]; pop bp; ret")

    dec = decompile_function(project, 0x1000, c_decl="char *identity(char *src);")

    assert dec.codegen is not None
    assert "identity(char *src)" in dec.codegen.text or "identity(char *v2)" in dec.codegen.text
    assert "return src;" in dec.codegen.text or "return v2;" in dec.codegen.text
