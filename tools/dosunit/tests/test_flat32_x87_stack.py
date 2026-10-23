"""Native x87 register-stack instruction tests.

Covers the conversion-free stack family (FLD ST(i)/m80/constants, FST(P)
ST(i), FSTP m80, FXCH, FFREE/FFREEP, FINCSTP/FDECSTP, FCHS/FABS): decode admission,
TOP/tag/80-bit register transitions and stack-fault masked/unmasked
responses evaluated against concrete Z3 inputs, the narrow Unicorn
differential (TOP and double-convertible register values only — Unicorn's
FPTAG collapses tag classes and FPST is 64-bit, so it is not a tag or ext80
oracle), and end-to-end comparison outcomes.
"""
from __future__ import annotations

import pytest
import z3

from tools.dosunit.architectures.flat32 import flat32_register_architecture
from tools.dosunit.architectures.flat32_control_word import (
    decode_native_x87,
    native_x87_body,
    unmodeled_x87_status_write,
)
from tools.dosunit.architectures.flat32_x87_stack import (
    StackConstant,
    StackExchange,
    StackFree,
    StackLoad,
    StackLoadMemory80,
    StackSignOp,
    StackStore,
    StackStoreMemory80,
    StackTopStep,
)
from tools.dosunit.ssa.translation import TranslationContext
from tools.dosunit.tests.test_flat32_comparator_lane import BASE, _compare_calls, _driver_lane

pytestmark = pytest.mark.ssa_z3

REGS = dict(flat32_register_architecture().registers)
CW = 0x37F  # all exceptions masked


def _run(raw: bytes, concrete: dict[str, object]) -> dict[str, object]:
    """Evaluate one native body's outputs under concrete inputs."""
    instruction = decode_native_x87(raw)
    assert instruction is not None, raw.hex()
    body = native_x87_body(instruction, continuation=0x1000, registers=REGS, address=0x800)
    inputs = {}
    for item in body["inputs"]:
        name = item["name"] if isinstance(item, dict) else item
        width = item.get("width", 32) if isinstance(item, dict) else 32
        if name == "mem":
            memory = z3.K(z3.BitVecSort(32), z3.BitVecVal(0, 8))
            for addr, value in concrete.get("mem", {}).items():
                memory = z3.Store(memory, z3.BitVecVal(addr, 32), z3.BitVecVal(value, 8))
            inputs[name] = (memory, 8)
        else:
            inputs[name] = (z3.BitVecVal(concrete.get(name, 0), width), width)
    context = TranslationContext(body, inputs, {i["id"]: i for i in body["assignments"]},
                                 {}, z3, lambda value, **_kwargs: value)
    outputs = {}
    for name, term in body["outputs"].items():
        value = z3.simplify(context.term(term))
        outputs[name] = value.as_long() if z3.is_bv_value(value) else value
    return outputs


def _state(**overrides):
    """Concrete all-empty stack state used across the evaluation cases."""
    base = {"x87_status_word": 0, "x87_control_word": CW, "x87_tag_word": 0xFFFF}
    base.update(overrides)
    return base


@pytest.mark.parametrize("raw,kind", [
    ("d9c2", StackLoad), ("d9c9", StackExchange), ("d9f6", StackTopStep),
    ("d9f7", StackTopStep), ("ddc3", StackFree), ("ddd1", StackStore),
    ("ddda", StackStore), ("dfc1", StackFree), ("d9e0", StackSignOp), ("d9e1", StackSignOp),
    ("d9e8", StackConstant), ("d9eb", StackConstant), ("d9ee", StackConstant),
    ("db28", StackLoadMemory80), ("db38", StackStoreMemory80),
    ("d9d9", StackStore),
])
def test_stack_decode_admits(raw, kind):
    assert isinstance(decode_native_x87(bytes.fromhex(raw)), kind)


@pytest.mark.parametrize("raw", [
    "dbe4", "dfc8", "dd", "d9",
])
def test_stack_decode_still_refuses_unmodeled(raw):
    assert decode_native_x87(bytes.fromhex(raw)) is None
    assert unmodeled_x87_status_write(bytes.fromhex(raw)) is True


def test_fldz_pushes_zero_at_top_minus_one():
    out = _run(bytes.fromhex("d9ee"), _state())
    assert out["x87_status_word"] == 0x3800  # TOP 0 -> 7
    assert out["x87_tag_word"] == 0x7FFF     # tag[7] = 01 (zero)
    assert out["x87_st7"] == 0


def test_fld_sti_copies_value_and_tag():
    out = _run(bytes.fromhex("d9c1"), _state(
        x87_tag_word=0xFFFB, x87_st1=0x3FFF8000000000000000))
    assert out["x87_status_word"] == 0x3800
    assert out["x87_tag_word"] == 0x3FFB     # tag[7] = 00 (valid)
    assert out["x87_st7"] == 0x3FFF8000000000000000


def test_fld_overflow_matches_host_vector():
    # Parent host control (host_stack_overflow.c): FNINIT + 8x FLD1 leaves a
    # full stack (all tags valid, TOP=0); FLDZ then reports SW 0x3A41 and
    # stores ffffc000000000000000. Masked-overflow-audit receipt.
    out = _run(bytes.fromhex("d9ee"), _state(x87_tag_word=0x0000))
    assert out["x87_status_word"] == 0x3A41
    assert out["x87_st7"] == 0xFFFFC000000000000000
    assert out["x87_tag_word"] == 0x8000  # tag[7] = special(10)


def test_fld_overflow_masked_pushes_indefinite():
    # Real hardware (host_stack_overflow.c): masked overflow completes the
    # push with the negative QNaN indefinite — SW 0x3A41, tag[7]=special.
    out = _run(bytes.fromhex("d9ee"), _state(x87_tag_word=0x3FFF))
    assert out["x87_status_word"] == 0x3A41
    assert out["x87_tag_word"] == 0xBFFF
    assert out["x87_st7"] == 0xFFFFC000000000000000


def test_fld_overflow_unmasked_aborts_push():
    # Unmasked IE: the fault sets IE+SF+C1 and ES/B, TOP and tags unchanged.
    out = _run(bytes.fromhex("d9ee"), _state(
        x87_tag_word=0x3FFF, x87_control_word=0x37E))
    status = out["x87_status_word"]
    assert status & 0x3800 == 0
    assert status == 0x82C1                    # IE+SF+C1 with ES+B
    assert out["x87_st7"] == 0


def test_fld_overflow_underflow_precedence():
    # Source empty AND destination full, masked: overflow wins (C1 set),
    # and the indefinite is still pushed.
    out = _run(bytes.fromhex("d9c1"), _state(x87_tag_word=0x3FFF))
    assert out["x87_status_word"] & 0x027F == 0x0241
    assert out["x87_st7"] == 0xFFFFC000000000000000


def test_fld_sti_underflow_masked_pushes_default_nan():
    out = _run(bytes.fromhex("d9c1"), _state())
    assert out["x87_status_word"] & 0x7F == 0x41      # IE+SF
    assert out["x87_status_word"] & 0x3800 == 0x3800  # pushed anyway
    assert out["x87_st7"] == 0xFFFFC000000000000000


def test_fld_sti_underflow_unmasked_aborts_push():
    out = _run(bytes.fromhex("d9c1"), _state(x87_control_word=0x37E))
    status = out["x87_status_word"]
    assert status & 0x7F == 0x41            # IE+SF
    assert status & 0x8080 == 0x8080        # ES+B recomputed for the unmasked fault
    assert status & 0x3800 == 0             # no TOP move
    assert out["x87_st7"] == 0


def test_fstp_st0_pops_and_empties_tag():
    out = _run(bytes.fromhex("ddd8"), _state(
        x87_tag_word=0xFFFE, x87_st0=0x4000C90FDAA22168C235))
    assert out["x87_status_word"] == 0x0800  # TOP 0 -> 1
    assert out["x87_tag_word"] == 0xFFFF


def test_fstpnce_stores_without_popping():
    """FSTPNCE ST(i) (D9 D8+i): store ST(0) into ST(i), no pop (host probe
    host_fstpnce.c: TOP unchanged, empty destination gets the masked-
    invalid indefinite)."""
    out = _run(bytes.fromhex("d9d9"), _state(
        x87_tag_word=0xFFF8, x87_st0=0x3FFF8000000000000000,
        x87_st1=0x00000000000000000000))
    assert out["x87_status_word"] & 0x3800 == 0        # TOP unchanged
    assert out["x87_st1"] == 0x3FFF8000000000000000    # ST0 copied into ST1
    assert out["x87_st0"] == 0x3FFF8000000000000000    # source preserved


def test_fstpnce_empty_destination_masked_indefinite():
    # Host: fstpnce st(1) on an empty ST(1) writes the masked-invalid
    # indefinite into the DESTINATION, still without a pop.
    out = _run(bytes.fromhex("d9d9"), _state())
    assert out["x87_status_word"] & 0x7F == 0x41       # IE+SF
    assert out["x87_st1"] == 0xFFFFC000000000000000
    assert out["x87_status_word"] & 0x3800 == 0        # no pop


def test_fst_sti_underflow_masked_writes_nan():
    out = _run(bytes.fromhex("ddd0"), _state())
    assert out["x87_status_word"] & 0x7F == 0x41
    assert out["x87_st0"] == 0xFFFFC000000000000000


def test_fst_sti_underflow_unmasked_writes_nothing():
    out = _run(bytes.fromhex("ddd0"), _state(
        x87_control_word=0x37E, x87_st0=0x3FFF8000000000000000))
    status = out["x87_status_word"]
    assert status & 0x7F == 0x41            # IE+SF
    assert status & 0x8080 == 0x8080        # ES+B for the unmasked fault
    assert out["x87_st0"] == 0x3FFF8000000000000000


def test_fxch_swaps_values_and_tags():
    out = _run(bytes.fromhex("d9c9"), _state(
        x87_tag_word=0xFFF8, x87_st0=0x3FFF8000000000000000,
        x87_st1=0x40008000000000000000))
    assert out["x87_st0"] == 0x40008000000000000000
    assert out["x87_st1"] == 0x3FFF8000000000000000
    # Tags follow the swapped values through FPU_tagof: both become valid(00).
    assert out["x87_tag_word"] == 0xFFF0


def test_ffree_marks_physical_register_empty():
    # TOP=1 -> logical ST(2) is physical 3; tag[3] 00 -> 11.
    out = _run(bytes.fromhex("ddc2"), _state(
        x87_status_word=0x0800, x87_tag_word=0xFF00))
    assert out["x87_tag_word"] == 0xFFC0


def test_ffreep_frees_then_pops():
    # DF C0+i is the undocumented-but-real FFREEP: tag ST(i) empty, TOP+1.
    # TOP=0, i=1 -> phys1 freed; the pop also empties old ST(0)'s tag.
    out = _run(bytes.fromhex("dfc1"), _state(
        x87_status_word=0, x87_tag_word=0xFFF0))
    assert out["x87_tag_word"] == 0xFFFC
    assert out["x87_status_word"] == 0x0800


@pytest.mark.parametrize("raw,top", [("d9f7", 0x0800), ("d9f6", 0x3800)])
def test_top_step(raw, top):
    out = _run(bytes.fromhex(raw), _state())
    assert out["x87_status_word"] == top


def test_fchs_flips_sign_only():
    out = _run(bytes.fromhex("d9e0"), _state(
        x87_tag_word=0xFFFE, x87_st0=0x3FFF8000000000000000))
    assert out["x87_st0"] == 0xBFFF8000000000000000


def test_fabs_clears_sign_only():
    out = _run(bytes.fromhex("d9e1"), _state(
        x87_tag_word=0xFFFE, x87_st0=0xBFFF8000000000000000))
    assert out["x87_st0"] == 0x3FFF8000000000000000


def test_fld_m80_loads_raw_ext80_and_env():
    image = bytes.fromhex("35c26821a2da0fc90040")  # ext80 PI, little-endian
    out = _run(bytes.fromhex("db28"), _state(
        eax=0x2000, ds=0x23, mem={0x2000 + i: b for i, b in enumerate(image)}))
    assert out["x87_status_word"] == 0x3800
    assert out["x87_st7"] == 0x4000C90FDAA22168C235
    assert out["x87_tag_word"] == 0x3FFF
    assert out["x87_fdp"] == 0x2000
    assert out["x87_fds"] == 0x23
    assert out["x87_fip"] == 0x800


def test_fstp_m80_stores_raw_ext80_and_pops():
    out = _run(bytes.fromhex("db38"), _state(
        eax=0x2000, x87_tag_word=0xFFFE, x87_st0=0x7FFFC000000000000000))
    assert out["x87_status_word"] == 0x0800
    memory = out["memory"]
    stored = bytes(z3.simplify(z3.Select(memory, z3.BitVecVal(0x2000 + i, 32))).as_long()
                   for i in range(10))
    assert stored == bytes.fromhex("00000000000000c0ff7f")


def test_unicorn_top_and_value_differential():
    # Unicorn executes the family but its FPTAG collapses tag classes and
    # FPST is 64-bit: it is only a TOP/status and value oracle.
    from unicorn import UC_ARCH_X86, UC_MODE_32, Uc
    from unicorn.x86_const import UC_X86_REG_FPCW, UC_X86_REG_FPSW, UC_X86_REG_FPTAG
    machine = Uc(UC_ARCH_X86, UC_MODE_32)
    machine.mem_map(0x1000, 0x1000)
    machine.mem_write(0x1000, bytes.fromhex("d9eed9e8d9c9"))  # fldz; fld1; fxch st1
    machine.reg_write(UC_X86_REG_FPCW, CW)
    machine.reg_write(UC_X86_REG_FPSW, 0)
    machine.reg_write(UC_X86_REG_FPTAG, 0)
    machine.emu_start(0x1000, 0x1006)
    out = _run(bytes.fromhex("d9ee"), _state())
    out = _run(bytes.fromhex("d9e8"), _state(
        x87_status_word=out["x87_status_word"], x87_tag_word=out["x87_tag_word"]))
    out = _run(bytes.fromhex("d9c9"), _state(
        x87_status_word=out["x87_status_word"], x87_tag_word=out["x87_tag_word"],
        x87_st6=out["x87_st6"], x87_st7=out["x87_st7"]))
    assert out["x87_status_word"] & 0x3800 == machine.reg_read(UC_X86_REG_FPSW) & 0x3800
    assert out["x87_st6"] == 0                       # ST0 = 0.0 after swap
    assert out["x87_st7"] == 0x3FFF8000000000000000  # ST1 = 1.0


@pytest.mark.parametrize("original,candidate", [
    ("d9e8d9eec3", "d9e8d9eec3"),          # identical: conditional (checking)
    ("d9e8c3", "d9eec3"),                  # 1.0 vs 0.0
    ("d9f7c3", "c3"),                      # dropped FINCSTP moves TOP
    ("d9e8d9c9c3", "d9e8d9e8c3"),          # FXCH vs second FLD1
])
def test_stack_comparison_outcomes(original, candidate):
    with _driver_lane("msc8") as lane:
        result = _compare_calls(lane, original, candidate,
            oracle_functions={BASE: len(bytes.fromhex(original))},
            candidate_functions={BASE: len(bytes.fromhex(candidate))},
            outputs=("x87_status_word", "x87_st6", "x87_st7"))
    expected = "conditional" if original == candidate else "failed"
    assert result["status"] == expected, result


@pytest.mark.parametrize("raw,values", [
    ("d9e8", (0x3FFF8000000000000000,) * 4),
    ("d9e9", (0x4000D49A784BCD1B8AFE, 0x4000D49A784BCD1B8AFE,
              0x4000D49A784BCD1B8AFF, 0x4000D49A784BCD1B8AFE)),
    ("d9ea", (0x3FFFB8AA3B295C17F0BC, 0x3FFFB8AA3B295C17F0BB,
              0x3FFFB8AA3B295C17F0BC, 0x3FFFB8AA3B295C17F0BB)),
    ("d9eb", (0x4000C90FDAA22168C235, 0x4000C90FDAA22168C234,
              0x4000C90FDAA22168C235, 0x4000C90FDAA22168C234)),
    ("d9ec", (0x3FFD9A209A84FBCFF799, 0x3FFD9A209A84FBCFF798,
              0x3FFD9A209A84FBCFF799, 0x3FFD9A209A84FBCFF798)),
    ("d9ed", (0x3FFEB17217F7D1CF79AC, 0x3FFEB17217F7D1CF79AB,
              0x3FFEB17217F7D1CF79AC, 0x3FFEB17217F7D1CF79AB)),
    ("d9ee", (0,) * 4),
])
@pytest.mark.parametrize("precision", [0x000, 0x200, 0x300])
def test_constant_rounding_hardware_vectors(raw, values, precision):
    """Host FXSAVE vectors for each RC; PC must not truncate FLD constants."""
    for rc, expected in enumerate(values):
        cw = 0x7F | precision | (rc << 10)
        out = _run(bytes.fromhex(raw), _state(x87_control_word=cw))
        assert out["x87_st7"] == expected
        assert out["x87_status_word"] == 0x3800
        assert out["x87_control_word"] == cw


@pytest.mark.parametrize("raw,expected", [
    ("db6d00", 0x2B),  # FLD m80 [EBP] uses SS
    ("db2c24", 0x2B),  # FLD m80 [ESP] uses SS
    ("db6800", 0x23),  # FLD m80 [EAX] uses DS
    ("db6c2800", 0x23),  # EBP as index does not select SS
    ("db7d00", 0x2B),  # FSTP m80 [EBP] uses SS
])
def test_memory_environment_records_effective_default_segment(raw, expected):
    # Bochs FPU_update_last_instruction records sregs[i->seg()], not a
    # hard-coded DS. Base EBP/ESP selects SS; an EBP index still uses DS.
    out = _run(bytes.fromhex(raw), _state(ds=0x23, ss=0x2B))
    assert out["x87_fds"] == expected
