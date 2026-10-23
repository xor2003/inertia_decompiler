"""Native control-word stores must preserve precision and memory effects."""
import pytest
import z3
from unicorn import UC_ARCH_X86, UC_MODE_32, Uc
from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_EBP, UC_X86_REG_FPCW, UC_X86_REG_FPSW

from tools.dosunit.architectures.flat32_control_word import (
    control_word_store_body,
    decode_control_word_store,
    decode_native_x87_word,
    native_x87_word_body,
)
from tools.dosunit.ssa.translation import TranslationContext
from tools.dosunit.tests.test_flat32_comparator_lane import BASE, _compare_calls, _compare_loops, _driver_lane

pytestmark = pytest.mark.ssa_z3


@pytest.mark.parametrize("status", [0, 1, 0x40, 0x80, 0x4700, 0x3800, 0x8000, 0xffff])
@pytest.mark.parametrize("raw", ["dfe0", "dd7dfc"])
def test_status_word_matches_instruction_execution(status, raw):
    machine = Uc(UC_ARCH_X86, UC_MODE_32)
    machine.mem_map(0x1000, 0x1000)
    machine.mem_map(0x3000, 0x1000)
    machine.mem_write(0x1000, bytes.fromhex(raw))
    machine.mem_write(0x3000, bytes([0xaa]) * 32)
    machine.reg_write(UC_X86_REG_EBP, 0x3010)
    machine.reg_write(UC_X86_REG_EAX, 0xabcd1234)
    machine.reg_write(UC_X86_REG_FPSW, status)
    assert machine.reg_read(UC_X86_REG_FPSW) == status
    machine.emu_start(0x1000, 0x1000 + len(bytes.fromhex(raw)))
    instruction = decode_native_x87_word(bytes.fromhex(raw))
    assert instruction is not None
    body = native_x87_word_body(instruction, continuation=0x1000 + len(bytes.fromhex(raw)),
                               registers={"eax": 32, "x87_status_word": 16})
    inputs = {"mem": (z3.K(z3.BitVecSort(32), z3.BitVecVal(0xaa, 8)), 0),
              "ebp": (z3.BitVecVal(0x3010, 32), 32),
              "eax": (z3.BitVecVal(0xabcd1234, 32), 32),
              "x87_status_word": (z3.BitVecVal(status, 16), 16)}
    context = TranslationContext(body, inputs, {item["id"]: item for item in body["assignments"]},
                                 {}, z3, lambda value, **_kwargs: value)
    assert z3.simplify(context.term(body["outputs"]["eax"])).as_long() == machine.reg_read(UC_X86_REG_EAX)
    assert z3.simplify(context.term(body["outputs"]["x87_status_word"])).as_long() == machine.reg_read(UC_X86_REG_FPSW)
    memory = context.term(body["outputs"]["memory"])
    modeled = bytes(z3.simplify(z3.Select(memory, z3.BitVecVal(0x3000 + i, 32))).as_long() for i in range(32))
    assert modeled == bytes(machine.mem_read(0x3000, 32))


@pytest.mark.parametrize("raw", ["9bdfe0", "66dfe0", "67dd3f", "64dd3f", "dfe0c3", "dd", "dde0"])
def test_status_word_unadmitted_forms(raw):
    assert decode_native_x87_word(bytes.fromhex(raw)) is None


@pytest.mark.parametrize("writer", ["66dbe2", "dbe4", "d9d8"])
@pytest.mark.parametrize("cfg", [False, True])
def test_status_word_unsupported_writer_is_not_erased(writer, cfg):
    original = writer + "dfe0c3"
    candidate = "dfe0c3"
    with _driver_lane("msc8") as lane:
        if cfg:
            result = _compare_loops(lane, original, candidate, outputs=("eax",))
        else:
            result = _compare_calls(lane, original, candidate,
                oracle_functions={BASE: len(bytes.fromhex(original))},
                candidate_functions={BASE: len(bytes.fromhex(candidate))}, outputs=("eax",))
    assert result["status"] == "refused", result


@pytest.mark.parametrize("writer", ["dbe2", "dbe3"])
def test_modeled_status_writer_is_observable(writer):
    # FNCLEX/FNINIT are now native: dropping one changes FNSTSW observably.
    original = writer + "dfe0c3"
    candidate = "dfe0c3"
    with _driver_lane("msc8") as lane:
        result = _compare_calls(lane, original, candidate,
            oracle_functions={BASE: len(bytes.fromhex(original))},
            candidate_functions={BASE: len(bytes.fromhex(candidate))}, outputs=("eax",))
    assert result["status"] == "failed", result


@pytest.mark.parametrize("driver", ["msc8", "bc5"])
@pytest.mark.parametrize("cfg", [False, True])
def test_status_word_ax_matches_memory(driver, cfg):
    # Both store SW. AX form must preserve the high half of arbitrary EAX.
    original = "dd3fdfe0c3"
    candidate = "dd3f668b07c3"
    with _driver_lane(driver) as lane:
        if cfg:
            result = _compare_loops(lane, original, candidate, outputs=("eax", "memory", "eip"))
        else:
            result = _compare_calls(lane, original, candidate,
                oracle_functions={BASE: len(bytes.fromhex(original))},
                candidate_functions={BASE: len(bytes.fromhex(candidate))}, outputs=("eax", "memory"))
    assert result["status"] == "passed", result


@pytest.mark.parametrize("mutation", ["6683f801", "6683f001", "0fb7c0"])
def test_status_word_corruption_is_observable(mutation):
    # CMP AX,1 changes flags only; XOR changes SW; MOVZX destroys EAX high bits.
    original = "dfe0c3"
    candidate = "dfe0" + mutation + "c3"
    with _driver_lane("msc8") as lane:
        result = _compare_calls(lane, original, candidate,
            oracle_functions={BASE: len(bytes.fromhex(original))},
            candidate_functions={BASE: len(bytes.fromhex(candidate))}, outputs=("eax",))
    assert result["status"] == ("passed" if mutation == "6683f801" else "failed"), result


@pytest.mark.parametrize("driver", ["msc8", "bc5"])
@pytest.mark.parametrize("corrupt", [False, True])
def test_cfg_control_word_store(driver, corrupt):
    original = "d93f0fb707c3"
    candidate = "d93fd93f0fb707" + ("3500010000" if corrupt else "") + "c3"
    with _driver_lane(driver) as lane:
        result = _compare_loops(lane, original, candidate, outputs=("eax", "memory", "eip"))
    if not corrupt:
        assert result["status"] == "passed", result
    else:
        # CFG induction reports failure of a relation, not automatically a
        # reachable whole-function counterexample. The SSA mismatch is exact.
        assert result["status"] == "refused", result
        assert result["reason"] == "reblocked_cfg_induction", result
        assert any(row["status"] == "failed" and any(item.get("reg") == "eax"
                   for item in row.get("mismatches", []))
                   for row in result["block_compare"]["results"]), result


def test_cfg_wait_retains_pending_exception_obligation():
    with _driver_lane("msc8") as lane:
        result = _compare_loops(lane, "9bd93fc3", "9bd93fc3")
    # The pending-exception premise is a typed conditional contract, not a
    # silent normal continuation or a refusal.
    assert result["status"] == "conditional", result
    assert result["reason"] == "declared_x87_premises", result


@pytest.mark.parametrize("raw", ["67d93f", "64d93f", "d93fc3", "d9", "d92f"])
def test_unadmitted_control_word_forms(raw):
    assert decode_control_word_store(bytes.fromhex(raw)) is None


def test_indexed_control_word_address():
    decoded = decode_control_word_store(bytes.fromhex("d97c8dfc"))
    assert decoded is not None
    assert (decoded.base, decoded.index, decoded.scale, decoded.displacement) == ("ebp", "ecx", 4, -4)


@pytest.mark.parametrize("driver", ["msc8", "bc5"])
def test_native_fnstcw_read_rewrite(driver):
    # FNSTCW [EDI]; MOVZX EAX,word [EDI]; RET.
    # A second identical store is idempotent and must not need a helper premise.
    original = "d93f0fb707c3"
    candidate = "d93fd93f0fb707c3"
    with _driver_lane(driver) as lane:
        result = _compare_calls(lane, original, candidate,
            oracle_functions={BASE: len(bytes.fromhex(original))},
            candidate_functions={BASE: len(bytes.fromhex(candidate))}, outputs=("eax",))
    assert result["status"] == "passed", result


def test_native_fnstcw_precision_difference_is_visible():
    original = "d93f0fb707c3"
    candidate = "d93f0fb7073500010000c3"  # Flip precision bit8 in returned value.
    with _driver_lane("msc8") as lane:
        result = _compare_calls(lane, original, candidate,
            oracle_functions={BASE: len(bytes.fromhex(original))},
            candidate_functions={BASE: len(bytes.fromhex(candidate))}, outputs=("eax",))
    assert result["status"] == "failed", result
    assert any(item.get("reg") == "eax" for item in result.get("mismatches", [])), result


def test_waiting_control_word_store_keeps_exception_obligation():
    code = "9bd93fc3"
    with _driver_lane("msc8") as lane:
        result = _compare_calls(lane, code, code,
            oracle_functions={BASE: 4}, candidate_functions={BASE: 4}, outputs=("eax",))
    assert result["status"] == "conditional", result
    assert result["reason"] == "declared_x87_premises", result


@pytest.mark.parametrize("precision", [0, 2, 3])
@pytest.mark.parametrize("rounding", range(4))
def test_control_word_memory_matches_native(precision, rounding):
    control = 0x7f | (precision << 8) | (rounding << 10)
    raw = bytes.fromhex("d97dfc")
    machine = Uc(UC_ARCH_X86, UC_MODE_32)
    machine.mem_map(0x1000, 0x1000)
    machine.mem_map(0x3000, 0x1000)
    machine.mem_write(0x1000, raw)
    machine.mem_write(0x3000, bytes([0xaa]) * 32)
    machine.reg_write(UC_X86_REG_EBP, 0x3010)
    machine.reg_write(UC_X86_REG_FPCW, control)
    machine.emu_start(0x1000, 0x1003)
    instruction = decode_control_word_store(raw)
    assert instruction is not None
    body = control_word_store_body(instruction, continuation=0x1003, registers={})
    inputs = {"mem": (z3.K(z3.BitVecSort(32), z3.BitVecVal(0xaa, 8)), 0),
              "ebp": (z3.BitVecVal(0x3010, 32), 32),
              "x87_control_word": (z3.BitVecVal(control, 16), 16)}
    context = TranslationContext(body, inputs, {item["id"]: item for item in body["assignments"]},
                                 {}, z3, lambda value, **_kwargs: value)
    memory = context.term(body["outputs"]["memory"])
    actual = bytes(machine.mem_read(0x3000, 32))
    modeled = bytes(z3.simplify(z3.Select(memory, z3.BitVecVal(0x3000 + index, 32))).as_long()
                    for index in range(32))
    assert modeled == actual
