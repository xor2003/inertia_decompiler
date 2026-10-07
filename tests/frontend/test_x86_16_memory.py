from __future__ import annotations

from bitstring import ConstBitStream

from inertia.frontend.x86_16.memory import DEFAULT_MEMORY_SIZE, Memory


def test_memory_initializes_default_concrete_store() -> None:
    memory = Memory()

    assert memory.mem_size == DEFAULT_MEMORY_SIZE
    assert len(memory.memory) == DEFAULT_MEMORY_SIZE
    assert memory.is_ena_a20gate() is False


def test_memory_relies_on_gc_without_timeout_interruptible_finalizer() -> None:
    assert "__del__" not in Memory.__dict__


def test_memory_read_write_data_respects_bounds() -> None:
    memory = Memory(8)

    assert memory.write_data(2, bytearray([0xAA, 0xBB])) is True
    assert memory.read_data(2, 2) == bytearray([0xAA, 0xBB])
    assert memory.write_data(7, bytearray([1, 2])) is False
    assert memory.read_data(7, 2) is None


def test_memory_a20_gate_and_bitstream_are_explicit_state() -> None:
    memory = Memory(4)
    bitstream = ConstBitStream(bytes=b"\x01\x02")

    memory.set_a20gate(True)
    memory.set_bitstream(bitstream)

    assert memory.is_ena_a20gate() is True
    assert memory.bitstream is bitstream


def test_dump_mem_prints_aligned_little_endian_rows(capsys) -> None:
    memory = Memory(32)
    memory.write_data(0, bytearray(range(16)))

    memory.dump_mem(3, 16)

    captured = capsys.readouterr()
    assert captured.out == "0x00000000: 03020100 07060504 0b0a0908 0f0e0d0c \n"
