
"""Native nonwaiting x87 instructions preserve their complete state effects.

FNCLEX/FNINIT differentials run real instruction execution in Unicorn.
FLDCW uses the declared Pentium-class reserved-bit policy: Unicorn ignores
FLDCW entirely, so the model is checked against the declared constants
(Bochs 5c357ade fpu.cc + recorded host probe), not the emulator.
"""
import pytest
import z3
from unicorn import UC_ARCH_X86, UC_MODE_32, Uc
from unicorn.x86_const import UC_X86_REG_FPCW, UC_X86_REG_FPSW, UC_X86_REG_FPTAG

from tools.dosunit.architectures.flat32_control_word import (
    FLDCW_RESERVED_MASK,
    FLDCW_RESERVED_SET,
    FNCLEX_PRESERVED_MASK,
    X87_PREMISE_CPU_POLICY,
    X87_PREMISE_NO_PENDING_UNMASKED,
    ControlWordLoad,
    FpuInit,
    FpuNop,
    StatusWordClear,
    bind_x87_obligations,
    decode_native_x87,
    native_x87_body,
    unmodeled_x87_status_write,
)
from tools.dosunit.compare import straightline_ssa as S
from tools.dosunit.ssa.materialization import materialize_term
from tools.dosunit.ssa.obligation_codec import decode_obligation
from tools.dosunit.ssa.translation import TranslationContext
from tools.dosunit.tests.test_flat32_comparator_lane import BASE, _compare_calls, _compare_loops, _driver_lane

pytestmark = pytest.mark.ssa_z3

X87_REGISTERS = {
    "x87_control_word": 16, "x87_status_word": 16, "x87_tag_word": 16,
    "x87_fip": 32, "x87_fcs_op": 32, "x87_fdp": 32, "x87_fds": 32,
}


def _evaluate(body, inputs):
    context = TranslationContext(body, inputs, {item["id"]: item for item in body["assignments"]},
                                 {}, z3, lambda value, **_kwargs: value)
    return context


@pytest.mark.parametrize("raw,kind", [
    ("dbe2", StatusWordClear), ("dbe3", FpuInit), ("d9d0", FpuNop), ("d92f", ControlWordLoad),
])
def test_native_x87_decode_admits(raw, kind):
    instruction = decode_native_x87(bytes.fromhex(raw))
    assert isinstance(instruction, kind)
    if isinstance(instruction, ControlWordLoad):
        assert (instruction.source.base, instruction.source.index) == ("edi", None)


@pytest.mark.parametrize("raw", [
    "66dbe2", "66d92f", "67d92f", "64d92f",
    "dbe2c3", "dbe4", "dbe0", "dd", "d9", "9bd8c0",
])
def test_native_x87_decode_refuses(raw):
    assert decode_native_x87(bytes.fromhex(raw)) is None
    assert unmodeled_x87_status_write(bytes.fromhex(raw)) is True


@pytest.mark.parametrize("raw", ["90", "c3", "8b442404", "dfe0", "d93f", "dd3f"])
def test_unmodeled_guard_ignores_non_x87_or_admitted(raw):
    assert unmodeled_x87_status_write(bytes.fromhex(raw)) is False


@pytest.mark.parametrize("status", [0, 1, 0x40, 0x80, 0x4700, 0x3800, 0x8000, 0xffff, 0x7f00])
def test_fnclex_matches_instruction_execution(status):
    machine = Uc(UC_ARCH_X86, UC_MODE_32)
    machine.mem_map(0x1000, 0x1000)
    machine.mem_write(0x1000, bytes.fromhex("dbe2"))
    machine.reg_write(UC_X86_REG_FPSW, status)
    machine.emu_start(0x1000, 0x1002)
    assert machine.reg_read(UC_X86_REG_FPSW) == status & FNCLEX_PRESERVED_MASK
    instruction = decode_native_x87(bytes.fromhex("dbe2"))
    assert isinstance(instruction, StatusWordClear)
    body = native_x87_body(instruction, continuation=0x1002, registers=dict(X87_REGISTERS))
    context = _evaluate(body, {"x87_status_word": (z3.BitVecVal(status, 16), 16),
                               "mem": (z3.K(z3.BitVecSort(32), z3.BitVecVal(0xaa, 8)), 0)})
    modeled = z3.simplify(context.term(body["outputs"]["x87_status_word"])).as_long()
    assert modeled == machine.reg_read(UC_X86_REG_FPSW)
    for name, width in X87_REGISTERS.items():
        if name != "x87_status_word":
            value = z3.FreshConst(z3.BitVecSort(width), name)
            context.inputs[name] = (value, width)
            assert context.term(body["outputs"][name]) is value


def test_fninit_matches_instruction_execution():
    machine = Uc(UC_ARCH_X86, UC_MODE_32)
    machine.mem_map(0x1000, 0x1000)
    machine.mem_write(0x1000, bytes.fromhex("dbe3"))
    machine.reg_write(UC_X86_REG_FPCW, 0xffff)
    machine.reg_write(UC_X86_REG_FPSW, 0xffff)
    machine.reg_write(UC_X86_REG_FPTAG, 0x0000)
    machine.emu_start(0x1000, 0x1002)
    instruction = decode_native_x87(bytes.fromhex("dbe3"))
    assert isinstance(instruction, FpuInit)
    body = native_x87_body(instruction, continuation=0x1002, registers=dict(X87_REGISTERS))
    context = _evaluate(body, {"mem": (z3.K(z3.BitVecSort(32), z3.BitVecVal(0xaa, 8)), 0)})
    assert z3.simplify(context.term(body["outputs"]["x87_control_word"])).as_long() == \
        machine.reg_read(UC_X86_REG_FPCW) == 0x037F
    assert z3.simplify(context.term(body["outputs"]["x87_status_word"])).as_long() == \
        machine.reg_read(UC_X86_REG_FPSW) == 0
    assert z3.simplify(context.term(body["outputs"]["x87_tag_word"])).as_long() == \
        machine.reg_read(UC_X86_REG_FPTAG) == 0xFFFF
    # FNINIT zeroes the whole pointer/opcode environment record.
    for name in ("x87_fip", "x87_fcs_op", "x87_fdp", "x87_fds"):
        assert z3.simplify(context.term(body["outputs"][name])).as_long() == 0


@pytest.mark.parametrize("value", [0, 0x007F, 0x037F, 0x1F80, 0xE0C0, 0xFFFF])
def test_fldcw_declared_reserved_bit_policy(value):
    instruction = decode_native_x87(bytes.fromhex("d96dfc"))
    assert isinstance(instruction, ControlWordLoad)
    body = native_x87_body(instruction, continuation=0x1003, registers=dict(X87_REGISTERS))
    inputs = {"mem": (z3.K(z3.BitVecSort(32), z3.BitVecVal(0xaa, 8)), 0),
              "ebp": (z3.BitVecVal(0x3010, 32), 32),
              "x87_status_word": (z3.BitVecVal(0, 16), 16),
              "x87_control_word": (z3.BitVecVal(0x037F, 16), 16)}
    context = _evaluate(body, inputs)
    memory = z3.Store(context.term(body["outputs"]["memory"]), z3.BitVecVal(0x300c, 32),
                      z3.BitVecVal(0xaa, 8))
    context.inputs["mem"] = (z3.Store(
        z3.Store(z3.K(z3.BitVecSort(32), z3.BitVecVal(0, 8)), z3.BitVecVal(0x300c, 32),
                 z3.BitVecVal(value & 0xFF, 8)),
        z3.BitVecVal(0x300d, 32), z3.BitVecVal(value >> 8, 8)), 0)
    context = _evaluate(body, context.inputs)
    modeled = z3.simplify(context.term(body["outputs"]["x87_control_word"])).as_long()
    assert modeled == ((value & FLDCW_RESERVED_MASK) | FLDCW_RESERVED_SET)
    premise_kinds = {premise["kind"] for premise in body["summary"]["premises"]}
    assert premise_kinds == {X87_PREMISE_NO_PENDING_UNMASKED, X87_PREMISE_CPU_POLICY}
    assert memory is not None


def test_fnop_preserves_complete_state():
    instruction = decode_native_x87(bytes.fromhex("d9d0"))
    assert isinstance(instruction, FpuNop)
    body = native_x87_body(instruction, continuation=0x1002, registers=dict(X87_REGISTERS))
    inputs = {name: (z3.FreshConst(z3.BitVecSort(width), name), width)
              for name, width in X87_REGISTERS.items()}
    context = _evaluate(body, inputs)
    for name, (value, _width) in inputs.items():
        if name in {"x87_fip", "x87_fcs_op"}:
            continue  # FNOP records its last-instruction environment.
        assert context.term(body["outputs"][name]) is value


@pytest.mark.parametrize("driver", ["msc8", "bc5"])
@pytest.mark.parametrize("cfg", [False, True])
def test_fnclex_identity_proves(driver, cfg):
    code = "dbe2dfe0c3"
    with _driver_lane(driver) as lane:
        if cfg:
            result = _compare_loops(lane, code, code, outputs=("eax", "eip"))
        else:
            result = _compare_calls(lane, code, code,
                oracle_functions={BASE: 5}, candidate_functions={BASE: 5}, outputs=("eax",))
    # FNCLEX proves only under the declared Pentium-class condition-code
    # model; the SDM leaves C0-C3 undefined after clearing exceptions.
    assert result["status"] == "conditional", result


@pytest.mark.parametrize("original,candidate", [
    ("dbe3dfe0c3", "dbe2dfe0c3"),   # FNINIT zeroes SW; FNCLEX keeps C bits
    ("dbe2dfe0c3", "dfe0c3"),      # dropped FNCLEX
    ("dbe3dfe0c3", "d9d0dfe0c3"),  # FNOP is not FNINIT
])
def test_status_writer_mismatch_fails(original, candidate):
    with _driver_lane("msc8") as lane:
        result = _compare_calls(lane, original, candidate,
            oracle_functions={BASE: len(bytes.fromhex(original))},
            candidate_functions={BASE: len(bytes.fromhex(candidate))}, outputs=("eax",))
    assert result["status"] == "failed", result


@pytest.mark.parametrize("driver", ["msc8", "bc5"])
def test_fnop_identity_is_conditional(driver):
    # Identical non-trapping behaviour, published conditional on the
    # no-unmasked-pending-exception premise every checking op carries.
    with _driver_lane(driver) as lane:
        result = _compare_calls(lane, "d9d0dfe0c3", "d9d0dfe0c3",
            oracle_functions={BASE: 5}, candidate_functions={BASE: 5}, outputs=("eax",))
    assert result["status"] == "conditional", result


def test_fnop_drop_is_an_environment_counterexample():
    # FNOP records FIP/FCS+opcode in the x87 environment: eliding it is a
    # real observable mismatch, not an equivalence under premises.
    with _driver_lane("msc8") as lane:
        result = _compare_calls(lane, "d9d0dfe0c3", "dfe0c3",
            oracle_functions={BASE: 5}, candidate_functions={BASE: 3}, outputs=("eax",))
    assert result["status"] == "failed", result
    assert any(mismatch["reg"].startswith("x87_") for mismatch in result["mismatches"]), result


def test_fldcw_then_fnstcw_is_not_raw_cw():
    # original: FLDCW [edi]; FNSTCW [edi]; RET stores the masked value.
    # candidate: FNSTCW [edi] alone stores the raw input control word.
    with _driver_lane("msc8") as lane:
        result = _compare_calls(lane, "d92fd93fc3", "d93fc3",
            oracle_functions={BASE: 5}, candidate_functions={BASE: 3},
            outputs=("memory", "x87_control_word"))
    assert result["status"] == "failed", result


def test_fldcw_identity_proves():
    code = "d92fd93fc3"
    with _driver_lane("msc8") as lane:
        result = _compare_calls(lane, code, code,
            oracle_functions={BASE: 5}, candidate_functions={BASE: 5},
            outputs=("memory", "x87_control_word"))
    assert result["status"] == "conditional", result


def test_fninit_identity_proves_cfg():
    code = "dbe3dfe0c3"
    with _driver_lane("bc5") as lane:
        result = _compare_loops(lane, code, code, outputs=("eax", "eip"))
    assert result["status"] == "passed", result


def test_fninit_state_reaches_comparison_observation():
    # Dropping FNINIT must be observable even when only eax is requested:
    # complete x87 state is part of the always-observed output contract.
    with _driver_lane("msc8") as lane:
        result = _compare_calls(lane, "dbe3c3", "c3",
            oracle_functions={BASE: 3}, candidate_functions={BASE: 1}, outputs=("eax",))
    assert result["status"] == "failed", result


@pytest.mark.parametrize("sw_in,loaded,expected_sw", [
    # All exception masks set by the new CW: no unmasked exception remains
    # pending, so ES and B are recomputed clear (Pentium-class policy).
    (0x8081, 0x3FFF, 0x0001),
    # New CW unmasks a pending IE: ES and B must be (re)set.
    (0x0001, 0x3FC0, 0x8081),
    # C bits and TOP flow through untouched.
    (0x4F00, 0x3FFF, 0x4F00),
])
def test_fldcw_recomputes_status_summary(sw_in, loaded, expected_sw):
    instruction = decode_native_x87(bytes.fromhex("d96dfc"))
    assert isinstance(instruction, ControlWordLoad)
    body = native_x87_body(instruction, continuation=0x1003, registers=dict(X87_REGISTERS))
    inputs = {"mem": (z3.Store(z3.Store(z3.K(z3.BitVecSort(32), z3.BitVecVal(0, 8)),
                                       z3.BitVecVal(0x300c, 32), z3.BitVecVal(loaded & 0xFF, 8)),
                               z3.BitVecVal(0x300d, 32), z3.BitVecVal(loaded >> 8, 8)), 0),
              "ebp": (z3.BitVecVal(0x3010, 32), 32),
              "x87_status_word": (z3.BitVecVal(sw_in, 16), 16),
              "x87_control_word": (z3.BitVecVal(0x037F, 16), 16)}
    context = _evaluate(body, inputs)
    modeled = z3.simplify(context.term(body["outputs"]["x87_status_word"])).as_long()
    assert modeled == expected_sw


def test_fnop_updates_last_instruction_environment():
    # Pentium-class contract (Bochs FPU_update_last_instruction): FNOP
    # records its own address as FIP and opcode 0x1D0 with the current CS;
    # FDP/FDS are untouched for register-form instructions.
    instruction = decode_native_x87(bytes.fromhex("d9d0"))
    assert isinstance(instruction, FpuNop)
    body = native_x87_body(instruction, continuation=0x1002, registers=dict(X87_REGISTERS))
    inputs = {"cs": (z3.BitVecVal(0x1234, 16), 16),
              "x87_status_word": (z3.BitVecVal(0, 16), 16),
              "x87_control_word": (z3.BitVecVal(0x037F, 16), 16),
              "x87_fip": (z3.BitVecVal(0, 16), 16),
              "x87_fcs_op": (z3.BitVecVal(0, 16), 16)}
    context = _evaluate(body, inputs)
    assert z3.simplify(context.term(body["outputs"]["x87_fip"])).as_long() == 0x1000
    assert z3.simplify(context.term(body["outputs"]["x87_fcs_op"])).as_long() == (0x01D0 << 16) | 0x1234


def test_fldcw_verdict_is_conditional_not_unconditional():
    # FLDCW only reaches its fallthrough when no unmasked exception is
    # pending, and its reserved-bit policy is a declared CPU contract:
    # the proof is conditional, never a silent unconditional pass.
    code = "d92fd93fc3"
    with _driver_lane("msc8") as lane:
        result = _compare_calls(lane, code, code,
            oracle_functions={BASE: 5}, candidate_functions={BASE: 5},
            outputs=("memory", "x87_control_word"))
    assert result["status"] == "conditional", result
    assert "x87" in result["reason"], result
    assert result["assumptions"]["premises"], result


def test_fldcw_cfg_verdict_is_conditional_not_unconditional():
    # The CFG lane publishes the same declared premises and observes the
    # complete x87 state on internal edges.
    with _driver_lane("msc8") as lane:
        result = _compare_loops(lane, "d92fd93fc3", "d92fd93fc3", outputs=("eax", "memory"))
    assert result["status"] == "conditional", result
    assert any("pending" in str(premise) for premise in result["assumptions"]["premises"]), result


def test_fnop_cfg_identity_is_refused_on_literal_address():
    # FNOP records its own address in FIP. Paired modules sit at different
    # bases, and without a declared relocation contract the comparator
    # honestly cannot prove the literal address outputs equal.
    with _driver_lane("msc8") as lane:
        result = _compare_loops(lane, "d9d0dfe0c3", "d9d0dfe0c3", outputs=("eax",))
    assert result["status"] == "refused", result


def _pending_guard() -> dict:
    return {"op": "eq", "width": 1, "args": [
        {"op": "and", "width": 16, "args": [
            {"op": "input", "width": 16, "name": "x87_status_word"},
            {"op": "and", "width": 16, "args": [
                {"op": "not", "width": 16, "args": [
                    {"op": "input", "width": 16, "name": "x87_control_word"}]},
                {"op": "const", "width": 16, "value": "0x3f"}]}]},
        {"op": "const", "width": 16, "value": "0x0"}]}


def test_obligation_binds_to_composed_site_state():
    # The checking-site predicate binds to the exact state reaching the
    # instruction, never to a global entry assumption: after a rewrite the
    # bound term names the composed inputs, not the raw register names.
    instruction = decode_native_x87(bytes.fromhex("d96dfc"))
    body = native_x87_body(instruction, continuation=0x1003,
                           registers=dict(X87_REGISTERS), address=0x1000)
    assert body["obligations"], body
    obligation = body["obligations"][0]
    assert obligation["kind"] == "x87_pending_check" and obligation["address"] == 0x1000
    incoming = {
        "x87_control_word": {"op": "input", "width": 16, "name": "cw_at_site"},
        "x87_status_word": {"op": "input", "width": 16, "name": "sw_at_site"},
    }
    bound = bind_x87_obligations(body, incoming)
    text = str(bound[0]["predicate"])
    assert "cw_at_site" in text and "sw_at_site" in text
    assert "'x87_control_word'" not in text and "'x87_status_word'" not in text


def test_domain_enforced_inside_solver_query():
    # Candidate differs from oracle only where a pending unmasked exception
    # exists. With the site obligation enforced the solver must not produce
    # that witness as a countermodel — the domain proves equality.
    sw_in = {"op": "input", "width": 16, "name": "x87_status_word"}
    inputs = [{"name": "x87_status_word", "width": 16},
              {"name": "x87_control_word", "width": 16}]
    pending = {"op": "and", "width": 16, "args": [
        sw_in,
        {"op": "and", "width": 16, "args": [
            {"op": "not", "width": 16, "args": [
                {"op": "input", "width": 16, "name": "x87_control_word"}]},
            {"op": "const", "width": 16, "value": "0x3f"}]}]}
    oracle = {"outputs": {"x87_status_word": sw_in}, "inputs": inputs,
              "obligations": [{"kind": "x87_pending_check", "address": 0x1000,
                               "predicate": _pending_guard()}]}
    # sw & ~pending differs from sw exactly when a pending exception exists:
    # inside the declared domain the outputs are equal, outside it they are not.
    assignments: list[dict] = []
    masked = materialize_term(
        {"op": "and", "width": 16, "args": [
            sw_in, {"op": "not", "width": 16, "args": [pending]}]},
        assignments=assignments, memo={}, term_cache={})
    candidate = {"outputs": {"x87_status_word": masked},
                 "assignments": assignments, "inputs": inputs}
    result = S._compare_functions(oracle, candidate, timeout_ms=2000)
    assert result["status"] == "passed", result
    assert result["domain_obligations"], result
    # Without the obligation the same mismatch is a valid countermodel.
    bare = {"outputs": oracle["outputs"], "inputs": inputs}
    unchecked = S._compare_functions(bare, candidate, timeout_ms=2000)
    assert unchecked["status"] == "failed", unchecked


def test_vacuous_domain_is_not_a_proof():
    # An impossible site predicate admits every output relation vacuously;
    # the comparison must refuse instead of publishing an empty-domain proof.
    def const(value: int) -> dict:
        return {"op": "const", "width": 32, "value": hex(value)}

    impossible = {"op": "eq", "width": 1, "args": [
        {"op": "const", "width": 16, "value": "0x0"},
        {"op": "const", "width": 16, "value": "0x1"}]}
    oracle = {"outputs": {"eax": const(0)}, "inputs": [],
              "obligations": [{"kind": "x87_pending_check", "address": 0x1000,
                               "predicate": impossible}]}
    candidate = {"outputs": {"eax": const(1)}, "inputs": []}
    result = S._compare_functions(oracle, candidate, timeout_ms=2000)
    assert result["status"] == "refused", result
    assert result["reason"] == "domain_obligation_vacuous", result


def test_fldcw_mask_change_binds_second_site():
    # FLDCW changes the exception masks; a later checking instruction must be
    # obligated against the NEW control word, not the entry input.
    code = "d92fd9d0c3"  # FLDCW [edi]; FNOP; ret
    with _driver_lane("msc8") as lane:
        result = _compare_calls(lane, code, code,
            oracle_functions={BASE: 5}, candidate_functions={BASE: 5},
            outputs=("memory", "x87_control_word", "x87_status_word"))
    assert result["status"] == "conditional", result
    obligations = result["x87_assumptions"]["obligations"]
    kinds = [o["kind"] for o in obligations]
    assert kinds.count("x87_pending_check") == len(obligations)
    # Two sites per side: the FLDCW guard binds entry SW/CW; the FNOP guard
    # binds the post-FLDCW masked control word (a load-derived term).
    for side in ("oracle", "candidate"):
        texts = [str(decode_obligation(o) if o.get("predicate_encoding") else o["predicate"]) for o in obligations if o["side"] == side]
        assert len(texts) == 2, texts
        assert any("loadle" in text or "load" in text for text in texts), texts


def test_branch_site_obligation_is_guarded():
    # FLDCW sits behind a conditional branch: the site only executes when the
    # branch falls through, so the bound obligation must be ite(guard,…), not
    # an unconditional entry predicate that would over-constrain the domain.
    code = "85c07402d92fc3"  # test eax,eax; jz +2; FLDCW [edi]; ret
    with _driver_lane("msc8") as lane:
        result = _compare_calls(lane, code, code,
            oracle_functions={BASE: 7}, candidate_functions={BASE: 7},
            outputs=("memory", "x87_control_word"))
    assert result["status"] == "conditional", result
    obligations = [o for o in result["x87_assumptions"]["obligations"]
                   if o["side"] == "oracle"]
    assert obligations, result
    assert all((decode_obligation(o) if o.get("predicate_encoding") else o["predicate"]).get("op") == "ite" for o in obligations), obligations
    # The guard references the branch condition, so a pending exception with
    # the branch NOT taken stays inside the compared domain.
    assert any("args" in (decode_obligation(o) if o.get("predicate_encoding") else o["predicate"]) for o in obligations)


def test_cfg_status_writer_mismatch():
    with _driver_lane("msc8") as lane:
        result = _compare_loops(lane, "dbe3dfe0c3", "dbe2dfe0c3", outputs=("eax", "eip"))
    assert result["status"] in {"failed", "refused"}, result
    if result["status"] == "refused":
        assert any(row["status"] == "failed"
                   for row in result["block_compare"]["results"]), result


def test_waiting_forms_carry_pending_exception_obligation():
    for code in ("9b", "9bdbe2", "9bdbe3", "9bd92f"):
        with _driver_lane("msc8") as lane:
            result = _compare_calls(lane, code + "c3", code + "c3",
                oracle_functions={BASE: len(bytes.fromhex(code)) + 1},
                candidate_functions={BASE: len(bytes.fromhex(code)) + 1}, outputs=("eax",))
        # Waiting forms are modeled with their pending-exception check as a
        # typed obligation -> conditional, never a silent normal result.
        assert result["status"] == "conditional", (code, result)
        assert result["reason"] == "declared_x87_premises", (code, result)


def test_leaf_lane_refuses_x87_effects():
    import angr

    import tools.dosunit.compare.straightline_ssa as S
    from tools.dosunit.architectures.flat32_leaf import lower_flat32_leaf_function

    project = angr.load_shellcode(bytes.fromhex("dbe2c3"), arch="x86", load_address=BASE)
    function = {"id": "f", "names": ["f"], "entry": {"offset": "0x0"}, "size": 3}
    parts, refusals, _lifted = lower_flat32_leaf_function(
        project=project, linked_base=BASE, function=function,
        output_regs=("eax",), scan_limit=16, max_assignments_per_function=64)
    assert parts == [] and refusals and refusals[0]["reason"] == "x87_status_update_unmodeled"
    assert isinstance(S, object)


def test_leaf_lane_refuses_fnop():
    # FNOP is a checking instruction (pending-exception check plus the
    # FIP/opcode environment update); the leaf lane must not delete it.
    import angr

    from tools.dosunit.architectures.flat32_leaf import lower_flat32_leaf_function

    project = angr.load_shellcode(bytes.fromhex("d9d0c3"), arch="x86", load_address=BASE)
    function = {"id": "f", "names": ["f"], "entry": {"offset": "0x0"}, "size": 3}
    parts, refusals, _lifted = lower_flat32_leaf_function(
        project=project, linked_base=BASE, function=function,
        output_regs=("eax",), scan_limit=16, max_assignments_per_function=64)
    assert parts == [] and refusals
    assert refusals[0]["reason"] == "x87_status_update_unmodeled"


def test_leaf_lane_refuses_fwait_and_waiting_forms():
    # FWAIT is only a pending-exception check -- exactly the effect the
    # leaf lane cannot model. 9B+FN* waiting forms must not slip through
    # decode admission either.
    import angr

    from tools.dosunit.architectures.flat32_leaf import lower_flat32_leaf_function

    for code in ("9bc3", "9bdbe3c3", "9bdd30"):
        project = angr.load_shellcode(bytes.fromhex(code), arch="x86",
                                      load_address=BASE)
        function = {"id": "f", "names": ["f"],
                    "entry": {"offset": "0x0"}, "size": len(bytes.fromhex(code))}
        parts, refusals, _lifted = lower_flat32_leaf_function(
            project=project, linked_base=BASE, function=function,
            output_regs=("eax",), scan_limit=16,
            max_assignments_per_function=64)
        assert parts == [] and refusals, code
        assert refusals[0]["reason"] == "x87_pending_exception_unmodeled", code


def test_waiting_forms_publish_bound_pending_exception_obligations():
    for code in ("9b", "9bdbe2", "9bdbe3", "9bd92f"):
        with _driver_lane("msc8") as lane:
            result = _compare_calls(lane, code + "c3", code + "c3",
                oracle_functions={BASE: len(bytes.fromhex(code)) + 1},
                candidate_functions={BASE: len(bytes.fromhex(code)) + 1}, outputs=("eax",))
        assert result["status"] == "conditional", (code, result)
        assert result["x87_assumptions"]["obligations"], result


def test_leaf_lane_does_not_erase_fnop_environment_or_pending_check():
    import angr

    from tools.dosunit.architectures.flat32_leaf import lower_flat32_leaf_function

    project = angr.load_shellcode(bytes.fromhex("d9d0c3"), arch="x86", load_address=BASE)
    function = {"id": "f", "names": ["f"], "entry": {"offset": "0x0"}, "size": 3}
    parts, refusals, _lifted = lower_flat32_leaf_function(
        project=project, linked_base=BASE, function=function,
        output_regs=("eax",), scan_limit=16, max_assignments_per_function=64)
    assert not parts and refusals[0]["reason"] == "x87_status_update_unmodeled"
