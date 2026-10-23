"""Independent execution checks for bounded flat32 REP memory semantics."""
import pytest
import z3
from unicorn import UC_ARCH_X86, UC_MODE_32, Uc
from unicorn.x86_const import (
    UC_X86_REG_EAX,
    UC_X86_REG_ECX,
    UC_X86_REG_EDI,
    UC_X86_REG_EFLAGS,
    UC_X86_REG_ESI,
)

from tools.dosunit.ssa.z3_repeat_memory import exact_repeat_memory

pytestmark = pytest.mark.ssa_z3


def _arguments(memory, count, source, destination, direction, *, move, size):
    prefix = [memory, z3.BitVecVal(count, 32)]
    if move:
        prefix += [z3.BitVecVal(source, 32), z3.BitVecVal(destination, 32),
                   z3.BitVecVal(0, 16), z3.BitVecVal(0, 16)]
    else:
        prefix += [z3.BitVecVal(destination, 32), z3.BitVecVal(0x89abcdef, size * 8), z3.BitVecVal(0, 16)]
    return [*prefix, *[z3.BitVecVal(0, 32) for _ in range(4)], z3.BitVecVal(direction, 32)]


@pytest.mark.parametrize("move,size,opcode", ((True, 1, "f3a4"), (True, 4, "f3a5"),
                                             (False, 1, "f3aa"), (False, 4, "f3ab"),
                                             (True, 2, "66f3a5"), (False, 2, "f366ab")))
@pytest.mark.parametrize("direction", (1, -1))
@pytest.mark.parametrize("displacement", (-3, 1, 64))
def test_bounded_repeat_memory_matches_unicorn(move, size, opcode, direction, displacement):
    """Read-before-write element ordering agrees even with partial word overlap."""
    guest = Uc(UC_ARCH_X86, UC_MODE_32)
    guest.mem_map(0x100000, 0x1000)
    code = bytes.fromhex(opcode)
    guest.mem_write(0x100000, code)
    source = 0x100400
    start = source - 80
    payload = bytes((i * 37 + 11) & 255 for i in range(256))
    memory = z3.K(z3.BitVecSort(32), z3.BitVecVal(0, 8))
    for index, value in enumerate(payload):
        memory = z3.Store(memory, z3.BitVecVal(start + index, 32), z3.BitVecVal(value, 8))
    operation = "summary_rep_" + ("movs" if move else "stos") + str(size * 8) + "_memory"
    for count in (0, 1, 3, 16):
        guest.mem_write(start, payload)
        for register, value in ((UC_X86_REG_ECX, count), (UC_X86_REG_ESI, source),
                                (UC_X86_REG_EDI, source + displacement), (UC_X86_REG_EAX, 0x89abcdef),
                                (UC_X86_REG_EFLAGS, 2 | (0x400 if direction == -1 else 0))):
            guest.reg_write(register, value)
        guest.emu_start(0x100000, 0x100000 + len(code), count=count + 2)
        args = _arguments(memory, count, source, source + displacement, direction, move=move, size=size)
        result = exact_repeat_memory(operation, 0, args, z3)
        assert result is not None
        result = z3.simplify(result)
        actual = bytes(z3.simplify(z3.Select(result, start + i)).as_long() for i in range(256))
        assert actual == bytes(guest.mem_read(start, 256))


@pytest.mark.parametrize("count", (17, 0xffffffff))
def test_large_repeat_retains_existing_abstract_memory(count):
    """An expansion limit is not permission to truncate the copy."""
    memory = z3.Array("initial_memory", z3.BitVecSort(32), z3.BitVecSort(8))
    args = _arguments(memory, count, 0, 0, 1, move=True, size=1)
    assert exact_repeat_memory("summary_rep_movs8_memory", 0, args, z3) is None


def test_symbolic_count_and_nonflat_shapes_are_not_expanded():
    """Unknown iteration counts and 16-bit pointer models remain distinct."""
    memory = z3.Array("initial_memory", z3.BitVecSort(32), z3.BitVecSort(8))
    args = _arguments(memory, 3, 0, 0, 1, move=True, size=1)
    args[1] = z3.BitVec("unknown_count", 32)
    assert exact_repeat_memory("summary_rep_movs8_memory", 0, args, z3) is None
    args[1] = z3.BitVecVal(3, 16)
    assert exact_repeat_memory("summary_rep_movs8_memory", 0, args, z3) is None
