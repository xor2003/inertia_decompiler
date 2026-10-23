"""Call composition preserves complete binary-derived repeat-string effects."""

import angr
import pytest

from tools.dosunit.tests.test_flat32_comparator_lane import BASE, _compare_calls, _driver_lane

pytestmark = pytest.mark.ssa_z3


@pytest.mark.parametrize("changed", [False, True])
def test_repeat_after_prefixed_enter_preserves_effects(changed: bool) -> None:
    """A fallback decode marker before ENTER cannot obstruct later REP effects."""
    from tools.dosunit.architectures.flat32_enter_lifter import ensure_flat32_enter_lifter

    ensure_flat32_enter_lifter()
    original = "90 c8000000 f2ae b801000000 c9 c3"
    candidate = "90 c8000000 f2ae " + ("b802000000" if changed else "b801000000") + " c9 c3"
    with _driver_lane("msc8") as lane:
        result = _compare_calls(lane, original, candidate,
            oracle_functions={BASE: len(bytes.fromhex(original))},
            candidate_functions={BASE: len(bytes.fromhex(candidate))},
            outputs=lane.adapter.OUTPUT_REGS)
    assert result["status"] == ("failed" if changed else "passed"), result


def test_repeat_scanner_rejects_unrecovered_decode_marker() -> None:
    """A failed decode with no successful replacement is still refused."""
    from tools.dosunit.compare.flat32_call_contracts import CallCompositionRefusal
    from tools.dosunit.compare.flat32_call_repeat import repeat_boundary_count

    project = angr.load_shellcode(bytes.fromhex("900f0b"), arch="x86", load_address=BASE)
    irsb = project.factory.block(BASE, size=3, opt_level=0).vex
    assert irsb.jumpkind == "Ijk_NoDecode"
    with pytest.raises(CallCompositionRefusal, match=r"^invalid_repeat_instruction_marker$"):
        repeat_boundary_count(project, irsb)


@pytest.mark.parametrize("driver", ["msc8", "bc5"])
@pytest.mark.parametrize("operation", ["f3a4", "f3aa", "f2ae", "f3a6"])
def test_call_composition_admits_isolated_repeat_effects(driver: str, operation: str) -> None:
    """REP summaries retain counter, index, memory, direction and lazy flags."""
    code = "90 " + operation + " c3"
    with _driver_lane(driver) as lane:
        result = _compare_calls(lane, code, code,
            oracle_functions={BASE: 4}, candidate_functions={BASE: 4},
            outputs=lane.adapter.OUTPUT_REGS)
    assert result["status"] == "passed", result


@pytest.mark.parametrize("driver", ["msc8", "bc5"])
def test_store_after_repeat_remains_observable(driver: str) -> None:
    """A changed store following a summarized REP must still fail."""
    original = "f3a4 c60701 c3"
    changed = "f3a4 c60702 c3"
    with _driver_lane(driver) as lane:
        result = _compare_calls(lane, original, changed,
            oracle_functions={BASE: 6}, candidate_functions={BASE: 6},
            outputs=lane.adapter.OUTPUT_REGS)
    assert result["status"] == "failed", result


def test_repeat_with_address_override_is_not_default_summary() -> None:
    """A 16-bit counter override cannot consume the flat32 default contract."""
    code = "67f3a4c3"
    with _driver_lane("msc8") as lane:
        result = _compare_calls(lane, code, code,
            oracle_functions={BASE: 4}, candidate_functions={BASE: 4},
            outputs=lane.adapter.OUTPUT_REGS)
    assert result["status"] == "refused", result


@pytest.mark.parametrize("driver", ["msc8", "bc5"])
def test_repeat_in_called_function_preserves_return_slot(driver: str) -> None:
    """A read-only SCAS callee composes with a checked saved return target."""
    code = "e801000000 c3 90 f2ae c3"
    with _driver_lane(driver) as lane:
        result = _compare_calls(lane, code, code,
            oracle_functions={BASE: 6, BASE + 6: 4},
            candidate_functions={BASE: 6, BASE + 6: 4},
            outputs=lane.adapter.OUTPUT_REGS)
    assert result["status"] == "passed", result
    assert result["oracle_inlined_calls"] == 1
    assert result["candidate_inlined_calls"] == 1


def test_public_retry_publishes_complete_repeat_only_composition() -> None:
    """A complete checked REP composition needs no CALL to discharge its root."""
    from tools.dosunit.compare.flat32_proof_retry import retry_function_proof

    project = angr.load_shellcode(bytes.fromhex("90f2aec3"), arch="x86", load_address=BASE)
    context = project, project, {"f": (BASE, 4)}, {"f": (BASE, 4)}
    with _driver_lane("msc8") as lane:
        result = retry_function_proof("f", {"status": "refused", "reason": "region_lowering_incomplete"},
                                      context, lane.adapter.OUTPUT_REGS, 10000)
    assert result["status"] == "passed", result
    assert result["oracle_repeat_summaries"] == 1
    assert result["candidate_repeat_summaries"] == 1
    assert result["oracle_inlined_calls"] == 0


def test_region_scanner_isolates_native_prefix_before_repeat(tmp_path) -> None:
    """A native prefix cannot prevent admission of the following REP summary."""
    from tools.dosunit.tests.test_flat32_conditional_boundaries import _scan_region

    with _driver_lane("msc8") as lane, lane.adapter.installed(region=True):
        parts = _scan_region("90f3a4c3", tmp_path)
        result = lane.region.compare_region(parts, parts, outputs=("eax", "esp"), timeout_ms=3000)
    assert result["status"] == "passed", result
    assert len(parts) == 3


@pytest.mark.parametrize("driver", ["msc8", "bc5"])
@pytest.mark.parametrize("changed", [False, True])
def test_public_retry_inducts_loop_containing_repeat(driver: str, changed: bool) -> None:
    """REP summaries inside a real outer loop require checked cyclic induction."""
    from tools.dosunit.compare.flat32_proof_retry import checked_environment_verdict, retry_function_proof

    original = bytes.fromhex("f2ae 4b 75fb c3")
    candidate = bytes.fromhex("f2ae " + ("43" if changed else "4b") + " 75fb c3")
    projects = tuple(angr.load_shellcode(code, arch="x86", load_address=BASE) for code in (original, candidate))
    context = *projects, {"f": (BASE, len(original))}, {"f": (BASE, len(candidate))}
    with _driver_lane(driver) as lane:
        result = retry_function_proof("f", {"status": "refused", "reason": "loop_requires_inductive_proof"},
                                      context, lane.adapter.OUTPUT_REGS, 10000)
        result = checked_environment_verdict(result, context, [], [])
    if changed:
        assert result["status"] != "passed", result
    else:
        assert result["status"] == "passed", result
        assert result["proof_method"] in {"closed_call_loop_induction", "closed_reblocked_cfg_induction"}
        if result["proof_method"] == "closed_call_loop_induction":
            assert result["oracle_inlined_calls"] == result["candidate_inlined_calls"] == 0
        else:
            assert result["proof_scope"] == "cutpoint_simulation"
            assert result["graph_evidence"]["paired_cutpoints"] >= 2


@pytest.mark.parametrize("driver", ["msc8", "bc5"])
@pytest.mark.parametrize("operation", ["f3a4", "f3ab", "f2ae", "f3a7", "66f3a5", "f366ab", "66f2af", "f366a7"])
@pytest.mark.parametrize("changed", [False, True])
def test_zero_count_repeat_matches_no_memory_operation(operation, changed, driver) -> None:
    """An actual zero-count REP preserves all effects; a following store cannot vanish."""
    original = "31c9 " + operation + " c3"
    candidate = "31c9 " + ("c60701 " if changed else "") + "c3"
    with _driver_lane(driver) as lane:
        result = _compare_calls(lane, original, candidate,
            oracle_functions={BASE: len(bytes.fromhex(original))},
            candidate_functions={BASE: len(bytes.fromhex(candidate))},
            outputs=lane.adapter.OUTPUT_REGS)
    assert result["status"] == ("failed" if changed else "passed"), result


@pytest.mark.parametrize("operation,comparison", [
    ("f2ae", "3c00"), ("f2af", "3d00000000"),
    ("f3a6", "3c00"), ("f3a7", "3d00000000"),
    ("66f2af", "663d0000"), ("f366a7", "663d0000"),
])
@pytest.mark.parametrize("count", (0, 1, 7))
def test_repeat_comparison_has_exact_subtraction_selector(operation, comparison, count) -> None:
    """Nonempty SCAS/CMPS select SUB; empty scans retain incoming flag state."""
    prefix = "31c9" if count == 0 else "b9" + count.to_bytes(4, "little").hex()
    original = prefix + operation + "c3"
    candidate = prefix + operation + (comparison if count else "") + "c3"
    with _driver_lane("msc8") as lane:
        result = _compare_calls(lane, original, candidate,
            oracle_functions={BASE: len(bytes.fromhex(original))},
            candidate_functions={BASE: len(bytes.fromhex(candidate))},
            outputs=("cc_op", "cc_ndep"))
    assert result["status"] == "passed", result


def test_repeat_subtraction_selector_rejects_wrong_width() -> None:
    """A byte scan cannot claim the dword comparison selector."""
    original = "b901000000f2aec3"
    candidate = "b901000000f2ae3d00000000c3"
    with _driver_lane("msc8") as lane:
        result = _compare_calls(lane, original, candidate,
            oracle_functions={BASE: len(bytes.fromhex(original))},
            candidate_functions={BASE: len(bytes.fromhex(candidate))},
            outputs=("cc_op",))
    assert result["status"] == "failed", result


@pytest.mark.parametrize("operation", ("f3a4", "f3a5", "f3aa", "f3ab"))
def test_counted_repeat_finishes_with_zero_counter(operation) -> None:
    """Completed MOVS/STOS counters are zero for all initial counts."""
    original = operation + "89c8c3"
    candidate = operation + "31c0c3"
    with _driver_lane("msc8") as lane:
        result = _compare_calls(lane, original, candidate,
            oracle_functions={BASE: len(bytes.fromhex(original))},
            candidate_functions={BASE: len(bytes.fromhex(candidate))}, outputs=("eax",))
    assert result["status"] == "passed", result


@pytest.mark.parametrize("operation", ("f3a4", "f3a5", "f3aa", "f3ab"))
def test_counted_repeat_memory_does_not_depend_on_arithmetic_flags(operation) -> None:
    """Different preceding CMP flags cannot change an otherwise identical copy."""
    original = "83f800" + operation + "c3"
    candidate = "83f801" + operation + "c3"
    with _driver_lane("msc8") as lane:
        result = _compare_calls(lane, original, candidate,
            oracle_functions={BASE: len(bytes.fromhex(original))},
            candidate_functions={BASE: len(bytes.fromhex(candidate))},
            outputs=lane.adapter.GPRS)
    assert result["status"] == "passed", result


@pytest.mark.parametrize("changed", (False, True))
@pytest.mark.parametrize("direction", ("fc", "fd"))
@pytest.mark.parametrize("operation,scale", (("f3a4", ""), ("f3a5", "c1e002")))
def test_counted_repeat_index_delta_matches_native_arithmetic(direction, operation, scale, changed) -> None:
    """Index displacement equals signed direction times original byte extent."""
    original = direction + "89fb" + operation + "89f829d8c3"
    candidate = direction + "89fb89c8" + scale + ("f7d8" if direction == "fd" else "") + operation + ("83c001" if changed else "") + "c3"
    with _driver_lane("msc8") as lane:
        result = _compare_calls(lane, original, candidate,
            oracle_functions={BASE: len(bytes.fromhex(original))},
            candidate_functions={BASE: len(bytes.fromhex(candidate))}, outputs=("eax",))
    assert result["status"] == ("failed" if changed else "passed"), result


@pytest.mark.parametrize("opcode,family,width", [
    ("f3a4", "movs", 1), ("f3a5", "movs", 4),
    ("f3aa", "stos", 1), ("f3ab", "stos", 4),
    ("66f3a5", "movs", 2), ("f366ab", "stos", 2),
])
@pytest.mark.parametrize("direction", (1, -1))
def test_counted_repeat_registers_match_unicorn(opcode, family, width, direction) -> None:
    """Observe actual REP index/count effects independently of the SSA formulas."""
    import z3
    from unicorn import UC_ARCH_X86, UC_MODE_32, Uc
    from unicorn.x86_const import (
        UC_X86_REG_ECX,
        UC_X86_REG_EDI,
        UC_X86_REG_EFLAGS,
        UC_X86_REG_ESI,
    )

    from tools.dosunit.compare import straightline_ssa as S
    from tools.dosunit.contracts.ssa import SsaExpr
    from tools.dosunit.ssa.repeat_counted import counted_repeat_outputs

    def evaluate(expr):
        if expr.op == "const":
            return z3.BitVecVal(expr.value, expr.width)
        return S._z3_apply(expr.op, expr.width, [evaluate(arg) for arg in expr.args], z3)

    machine = Uc(UC_ARCH_X86, UC_MODE_32)
    machine.mem_map(0x100000, 0x4000)
    code = bytes.fromhex(opcode)
    machine.mem_write(0x100000, code)
    for count in (0, 1, 3, 16):
        values = {"ecx": count, "esi": 0x101800, "edi": 0x102800, "d": direction}
        before = {name: SsaExpr("const", 32, value=value) for name, value in values.items()}
        after = dict(before)
        counted_repeat_outputs(before, after, family=family, width=width)
        machine.reg_write(UC_X86_REG_ECX, count)
        machine.reg_write(UC_X86_REG_ESI, values["esi"])
        machine.reg_write(UC_X86_REG_EDI, values["edi"])
        machine.reg_write(UC_X86_REG_EFLAGS, 2 | (0x400 if direction == -1 else 0))
        machine.emu_start(0x100000, 0x100000 + len(code), count=count + 2)
        for name, register in (("ecx", UC_X86_REG_ECX), ("esi", UC_X86_REG_ESI), ("edi", UC_X86_REG_EDI)):
            assert z3.simplify(evaluate(after[name])).as_long() == machine.reg_read(register)


@pytest.mark.parametrize("operation", ("f3a4", "f3a5", "f3aa", "f3ab"))
def test_counted_repeat_preserves_observable_incoming_flags(operation) -> None:
    """Removing flags from copy dependencies must not erase their preserved values."""
    original = "83f800" + operation + "9f0fb6c4c3"
    candidate = "83f801" + operation + "9f0fb6c4c3"
    with _driver_lane("msc8") as lane:
        result = _compare_calls(lane, original, candidate,
            oracle_functions={BASE: len(bytes.fromhex(original))},
            candidate_functions={BASE: len(bytes.fromhex(candidate))}, outputs=("eax",))
    assert result["status"] == "failed", result


@pytest.mark.parametrize("operation,scalar", (("f3a4", "a4"), ("f3a5", "a5"), ("f3aa", "aa"), ("f3ab", "ab"),
                                            ("66f3a5", "66a5"), ("f366ab", "66ab")))
@pytest.mark.parametrize("direction", ("fc", "fd"))
@pytest.mark.parametrize("changed", (False, True))
def test_constant_repeat_matches_unrolled_memory_effects(operation, scalar, direction, changed) -> None:
    """REP and scalar iterations agree over arbitrary, potentially overlapping memory."""
    original = direction + "b903000000" + operation + "c3"
    candidate = direction + "b903000000" + scalar * (2 if changed else 3) + "b900000000c3"
    with _driver_lane("msc8") as lane:
        result = _compare_calls(lane, original, candidate,
            oracle_functions={BASE: len(bytes.fromhex(original))},
            candidate_functions={BASE: len(bytes.fromhex(candidate))},
            outputs=lane.adapter.GPRS)
    assert result["status"] == ("failed" if changed else "passed"), result
