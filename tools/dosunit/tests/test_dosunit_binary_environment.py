"""External binary events cannot disappear through return-value liveness."""

from types import SimpleNamespace

import archinfo
import pytest
import pyvex

from tools.dosunit.contracts.binary_environment import (
    EnvironmentEffect,
    decoded_port_effects,
    external_effects,
    requires_environment_contract,
    scan_lowered_parts,
)


def test_unused_port_read_still_requires_an_environment_contract() -> None:
    """IN AL,DX is observable even when XOR immediately discards its result."""
    pure = pyvex.IRSB(bytes.fromhex('31c0c3'), 0x401000, archinfo.ArchX86(), opt_level=0)
    port_read = pyvex.IRSB(bytes.fromhex('ec31c0c3'), 0x401000, archinfo.ArchX86(), opt_level=0)
    assert not requires_environment_contract(pure)
    assert requires_environment_contract(port_read)


def test_structured_input_and_output_events_remain_visible() -> None:
    """Port effects are collected from IR assignments as well as final outputs."""
    assert external_effects({'assignments': [{'op': 'summary_io_in'}],
                             'outputs': {'io': {'op': 'summary_io_out'}}}) == {
        EnvironmentEffect.PORT_READ, EnvironmentEffect.PORT_WRITE,
    }


@pytest.mark.parametrize("mode_bits", [16, 32])
@pytest.mark.parametrize("code,effect", [
    ("e440", EnvironmentEffect.PORT_READ), ("e540", EnvironmentEffect.PORT_READ),
    ("ec", EnvironmentEffect.PORT_READ), ("ed", EnvironmentEffect.PORT_READ),
    ("6c", EnvironmentEffect.PORT_READ), ("666d", EnvironmentEffect.PORT_READ),
    ("f36d", EnvironmentEffect.PORT_READ),
    ("e640", EnvironmentEffect.PORT_WRITE), ("e740", EnvironmentEffect.PORT_WRITE),
    ("ee", EnvironmentEffect.PORT_WRITE), ("ef", EnvironmentEffect.PORT_WRITE),
    ("6e", EnvironmentEffect.PORT_WRITE), ("666f", EnvironmentEffect.PORT_WRITE),
    ("f36f", EnvironmentEffect.PORT_WRITE),
])
def test_decoded_port_events_include_immediate_register_and_string_forms(mode_bits, code, effect):
    """Instruction IDs retain events across operand width and repeat prefixes."""
    assert decoded_port_effects(bytes.fromhex(code), 0x1200, mode_bits=mode_bits) == {effect}


@pytest.mark.parametrize("mode_bits", [16, 32])
def test_port_opcode_bytes_inside_immediates_are_not_events(mode_bits):
    """MOV immediate data must never be mistaken for IN/OUT opcodes."""
    assert decoded_port_effects(bytes.fromhex("b0e4b0e6c3"), 0x1200, mode_bits=mode_bits) == frozenset()
    assert decoded_port_effects(bytes.fromhex("66"), 0x1200, mode_bits=mode_bits) is None
    assert decoded_port_effects(b"", 0x1200, mode_bits=mode_bits) is None


@pytest.mark.parametrize("code", [None, b"\xe4", b"\xc3"])
def test_missing_or_truncated_block_bytes_cannot_prove_environment_absence(code):
    """A valid IR block cannot substitute for missing exact binary coverage."""
    irsb = pyvex.IRSB(b"\xc3", 0x401000, archinfo.ArchX86(), opt_level=0)
    block = SimpleNamespace(vex=irsb, bytes=code)
    project = SimpleNamespace(arch=archinfo.ArchX86(), factory=SimpleNamespace(block=lambda *args, **kwargs: block))
    scan = scan_lowered_parts(project, [{"entry": {"linear": "0x401000"}, "source": {"machine_code_size": 3}}])
    assert not scan.complete
    assert not scan.requires_contract
