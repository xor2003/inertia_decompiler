"""VEX integers carry width-bounded bit patterns, not Python signed values."""

import io

import angr
import pytest
import pyvex
from angr.analyses.stack_pointer_tracker import OffsetVal, Register
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.processor import Processor
from angr_platforms.X86_16.regs import reg16_t, reg32_t
from pyvex.const import get_type_size, is_int_ty
from pyvex.lifting.util.syntax_wrapper import VexValue
from pyvex.lifting.util.vex_helper import IRSBCustomizer, Type


@pytest.mark.parametrize("bits", [1, 8, 16, 32, 64])
@pytest.mark.parametrize("case", ["minus_one", "minus_two", "overflow"])
def test_lifted_integer_constant_preserves_exact_bit_pattern(bits: int, case: str) -> None:
    processor = Processor()
    processor.set_lifter_instruction(IRSBCustomizer(pyvex.IRSB.empty_block(Arch86_16(), 0x1000)))
    value = {"minus_one": -1, "minus_two": -2, "overflow": (1 << bits) + 3}[case]
    result = processor.constant(value, f"Ity_I{bits}")
    assert isinstance(result, VexValue)
    assert result.value == value & ((1 << bits) - 1)
    assert result.width == bits


def test_constant_keeps_concrete_signed_arithmetic_and_float_values() -> None:
    processor = Processor()
    assert processor.constant(-2, Type.int_16) == -2
    processor.set_lifter_instruction(IRSBCustomizer(pyvex.IRSB.empty_block(Arch86_16(), 0x1000)))
    result = processor.constant(-2, Type.ieee_float_64)
    assert isinstance(result, VexValue)
    assert result.value == -2


@pytest.mark.parametrize("encoded", ["1e", "0e", "ff 36 32 01", "66 1e", "66 50", "9c"])
def test_push_lifting_never_emits_out_of_width_integer_constants(encoded: str) -> None:
    block = pyvex.lift(bytes.fromhex(encoded), 0x1000, Arch86_16(), opt_level=0)
    assert block.size == len(bytes.fromhex(encoded))
    constants = [constant for constant in block.all_constants if is_int_ty(constant.type)]
    assert constants
    assert all(0 <= constant.value < 1 << get_type_size(constant.type) for constant in constants)


@pytest.mark.parametrize("register,bits", [(reg16_t.SP, 16), (reg32_t.ESP, 32)])
@pytest.mark.parametrize("delta", [-4, -2, 2, 65536])
def test_register_update_preserves_signed_delta_before_bit_encoding(
    register: reg16_t | reg32_t, bits: int, delta: int,
) -> None:
    processor = Processor()
    arch = Arch86_16()
    processor.vex_offsets = {name: offset for name, (offset, _size) in arch.registers.items()}
    block = pyvex.IRSB.empty_block(arch, 0x1000)
    processor.set_lifter_instruction(IRSBCustomizer(block))
    processor.update_gpreg(register, delta)
    updates = [stmt.data for stmt in block.statements if isinstance(stmt, pyvex.stmt.WrTmp)
               and isinstance(stmt.data, pyvex.expr.Binop)]
    operation = f"Iop_{'Sub' if delta < 0 else 'Add'}{bits}"
    assert any(expr.op == operation and isinstance(expr.args[1], pyvex.expr.Const)
               and expr.args[1].con.value == abs(delta) & ((1 << bits) - 1)
               for expr in updates)


def test_mixed_push_paths_preserve_decrement_in_wide_native_tracking_domain() -> None:
    project = angr.Project(
        io.BytesIO(bytes.fromhex("55 0e 1e 50 c3")), auto_load_libs=False,
        main_opts={"backend": "blob", "arch": Arch86_16(), "base_addr": 0x1000, "entry_point": 0x1000},
    )
    project.arch.bits = 32
    block = project.factory.block(0x1000)
    sp = project.arch.sp_offset
    tracker = project.analyses.StackPointerTracker(
        None, {sp}, block=block, cross_insn_opt=False,
        initial_reg_values={sp: OffsetVal(Register(sp, 32), 0)},
    )
    assert [tracker.offset_after(0x1000 + i, sp) for i in range(4)] == [
        (-2 * (i + 1)) & 0xFFFFFFFF for i in range(4)
    ]


@pytest.mark.parametrize("initial", [0xABCD0000, 0xABCD0001, 0xABCDFFFF])
@pytest.mark.parametrize("delta", [-4, -2, 2])
def test_concrete_word_update_wraps_without_changing_upper_esp(initial: int, delta: int) -> None:
    processor = Processor()
    processor.set_gpreg(reg32_t.ESP, initial)
    processor.update_gpreg(reg16_t.SP, delta)
    assert processor.get_gpreg(reg32_t.ESP) == (initial & 0xFFFF0000) | ((initial + delta) & 0xFFFF)


@pytest.mark.parametrize("initial", [0xABCD0000, 0xABCD0001, 0xABCDFFFF])
@pytest.mark.parametrize("encoded,size", [("0e", 2), ("66 0e", 4)])
def test_lifted_push_keeps_upper_esp_and_wrapped_stack_bytes(initial: int, encoded: str, size: int) -> None:
    project = angr.Project(
        io.BytesIO(bytes.fromhex(encoded)), auto_load_libs=False,
        main_opts={"backend": "blob", "arch": Arch86_16(), "base_addr": 0x1000, "entry_point": 0x1000},
    )
    state = project.factory.blank_state(addr=0x1000)
    state.regs.esp = initial
    state.regs.ss = 0
    state.regs.cs = 0
    successors = project.factory.successors(state, num_inst=1).flat_successors
    assert len(successors) == 1
    result = successors[0]
    sp = (initial - size) & 0xFFFF
    assert result.solver.eval(result.regs.esp) == (initial & 0xFFFF0000) | sp
    assert all(result.solver.eval(result.memory.load((sp + i) & 0xFFFF, 1)) == 0 for i in range(size))
