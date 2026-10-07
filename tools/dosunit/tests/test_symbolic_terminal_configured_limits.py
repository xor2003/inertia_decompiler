"""Native terminal budget controls across actual MZ and PE32 images.

Layer: tests.
Responsibility: keep configured finite intake and receipt-verification limits coherent.
"""
from __future__ import annotations

import pytest
from tools.dosunit.tests.test_symbolic_terminal import dos_environment, exit_code, mz, pe32_bytes, pe_environment

import tools.dosunit.compare.symbolic_terminal as ST


@pytest.mark.parametrize("flat32", [False, True], ids=["mz", "pe32"])
def test_explicit_nine_block_budget_verifies_its_own_trace(flat32: bool) -> None:
    """A caller-authorized ninth block cannot become stale under a hidden default."""
    prefix = bytes.fromhex("eb0190") * 8
    environment = pe_environment() if flat32 else dos_environment()
    image = pe32_bytes(exit_code(prefix=prefix)) if flat32 else mz(prefix + bytes.fromhex("b8074ccd21"))
    result = ST.compare_symbolic_terminals(
        image, environment, image, environment, limits=ST.TerminalLimits(max_blocks=9),
    )
    assert result.status is ST.TerminalComparisonStatus.EQUIVALENT, result.detail
    for lane in (result.oracle, result.candidate):
        assert lane.trace is not None
        assert len(lane.trace.blocks) == 9
        assert ST.verify_terminal_trace(lane.trace) is None


@pytest.mark.parametrize("flat32", [False, True], ids=["mz", "pe32"])
def test_default_eight_block_budget_still_refuses_ninth(flat32: bool) -> None:
    """Supporting an explicit larger request must not enlarge default work."""
    prefix = bytes.fromhex("eb0190") * 8
    environment = pe_environment() if flat32 else dos_environment()
    image = pe32_bytes(exit_code(prefix=prefix)) if flat32 else mz(prefix + bytes.fromhex("b8074ccd21"))
    result = ST.compare_symbolic_terminals(image, environment, image, environment)
    assert result.status is ST.TerminalComparisonStatus.REFUSED
    assert result.oracle.refusal is not None
    assert result.oracle.refusal.kind is ST.TerminalRefusalKind.BLOCK_LIMIT


@pytest.mark.parametrize("flat32", [False, True], ids=["mz", "pe32"])
def test_smaller_budget_still_refuses_second_block(flat32: bool) -> None:
    """Caller-supplied limits below the defaults are equally authoritative."""
    prefix = bytes.fromhex("eb0190")
    environment = pe_environment() if flat32 else dos_environment()
    image = pe32_bytes(exit_code(prefix=prefix)) if flat32 else mz(prefix + bytes.fromhex("b8074ccd21"))
    result = ST.compare_symbolic_terminals(
        image, environment, image, environment, limits=ST.TerminalLimits(max_blocks=1),
    )
    assert result.status is ST.TerminalComparisonStatus.REFUSED
    assert result.oracle.refusal is not None
    assert result.oracle.refusal.kind is ST.TerminalRefusalKind.BLOCK_LIMIT


@pytest.mark.parametrize("size", [257, 4097], ids=["instructions", "bytes"])
def test_decoder_uses_explicit_limits_without_raising_defaults(size: int) -> None:
    """Shared decoding honors explicit byte/instruction budgets, including refusal."""
    import capstone

    from tools.dosunit.architectures.terminal_native_decode import NativeDecodeLimits, decode_terminal_block

    code = b"\x90" * size
    with pytest.raises(ST.TerminalRefusal) as error:
        decode_terminal_block(code, 0, mode=capstone.CS_MODE_32)
    assert error.value.kind is ST.TerminalRefusalKind.DECODE
    limits = NativeDecodeLimits(max_block_bytes=size, max_instructions=size)
    assert len(decode_terminal_block(code, 0, mode=capstone.CS_MODE_32, limits=limits)) == size
    with pytest.raises(ST.TerminalRefusal) as error:
        decode_terminal_block(
            code, 0, mode=capstone.CS_MODE_32,
            limits=NativeDecodeLimits(max_block_bytes=size, max_instructions=size - 1),
        )
    assert error.value.kind is ST.TerminalRefusalKind.DECODE
