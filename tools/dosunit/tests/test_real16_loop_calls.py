"""Actual-byte loop/callee proof controls through production proof owners."""

from dataclasses import asdict

import pytest
import pyvex
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.frontend.x86_16.lift_86_16 import Instruction_ANY
from tools.dosunit.tests.test_dosunit_tool import _edge_function, _mz_exe
from unicorn import UC_ARCH_X86, UC_MODE_16, Uc
from unicorn.x86_const import UC_X86_REG_AX, UC_X86_REG_BP, UC_X86_REG_EFLAGS

import tools.dosunit.compare.straightline_ssa as S
from tools.dosunit.contracts.model import write_json
from tools.dosunit.contracts.proof_contracts import ProofStatus, proof_status_from_legacy
from tools.dosunit.compare.real16_binary_compare import compare_binary16
from tools.dosunit.compare.real16_call_contracts import Real16CallLimits, materialize_function
from tools.dosunit.compare.real16_loop_calls import compare_real16_loop_calls
from tools.dosunit.runtime.real16_mz_load import image_from_mz_bytes
from tools.dosunit.runtime.real16_replay import compare_executions, replay
from tools.dosunit.runtime.real16_replay_model import CallerFrame, FrameKind, Real16Agreement, Real16Vector, SegOffset


def _fixture(leaf, body=None):
    image = bytearray(0x300)
    body = body or bytes.fromhex("89c1 83f900 7406 e82600 49 ebf5 c3")
    image[0x200:0x200+len(body)] = body
    image[0x230:0x230+len(leaf)] = leaf
    catalog = {"schema": "dosunit.functions.v1", "id": "functions:test", "module": "demo.exe",
               "program_kind": "mz_exe", "diagnostics": [], "functions": [
                   _edge_function("demo.exe:loop", "loop", offset=0x200, size=len(body)),
                   _edge_function("demo.exe:leaf", "leaf", offset=0x230, size=len(leaf)),
               ]}
    return _mz_exe(bytes(image)), catalog


def _document(tmp_path, tag, leaf, body=None):
    image, catalog = _fixture(leaf, body)
    exe = tmp_path / (tag + ".exe")
    exe.write_bytes(image)
    return S.lower_straightline_ssa_document(exe_path=exe,functions_catalog=catalog,
                                             output_regs=S.INTERNAL_STATE_REGS)


@pytest.mark.parametrize("leaf,expected", [("43c3", True),("9043c3", True),("4bc3", False),
                                         ("6643c3", False),("e8fdffc3", False)])
def test_call_in_loop(tmp_path, leaf, expected):
    original = _document(tmp_path,"original",bytes.fromhex("43c3"))
    candidate = _document(tmp_path,"candidate",bytes.fromhex(leaf))
    proof = compare_real16_loop_calls(original,candidate,"demo.exe:loop",timeout_ms=60000)
    assert (proof.status is ProofStatus.PROVED) is expected, proof
    if expected:
        assert proof.counters.failure_count == 0
        assert proof.dependencies[0]["callees"][0]["body_size"] == 2


def test_loop_obligations_refuse_missing_callee_and_budget(tmp_path):
    original = _document(tmp_path,"original",bytes.fromhex("43c3"))
    exhausted = compare_real16_loop_calls(original,original,"demo.exe:loop",
        limits=Real16CallLimits(max_inlined_calls=0),timeout_ms=60000)
    assert exhausted.status is ProofStatus.UNKNOWN
    assert exhausted.counters.failure_count > 0
    assert exhausted.transitions
    missing = dict(original)
    missing["functions"] = [part for part in original["functions"]
                            if part["function"]["id"] == "demo.exe:loop"]
    refused = compare_real16_loop_calls(original,missing,"demo.exe:loop",timeout_ms=60000)
    assert refused.status is ProofStatus.UNKNOWN
    assert refused.counters.failure_count > 0


def test_changed_loop_guard_cannot_pass(tmp_path):
    original = _document(tmp_path,"original",bytes.fromhex("43c3"))
    candidate = _document(tmp_path,"candidate",bytes.fromhex("43c3"),
                          bytes.fromhex("89c1 83f900 7506 e82600 49 ebf5 c3"))
    proof = compare_real16_loop_calls(original,candidate,"demo.exe:loop",timeout_ms=60000)
    assert proof.status is ProofStatus.UNKNOWN
    assert proof.counters.failure_count > 0


@pytest.mark.parametrize("leaf,expected", [("9043c3", "proved"), ("4bc3", "unknown")])
def test_public_call_loop_induction(tmp_path, leaf, expected):
    original, catalog = _fixture(bytes.fromhex("43c3"))
    candidate, other_catalog = _fixture(bytes.fromhex(leaf))
    original_path, candidate_path = tmp_path / "original.exe", tmp_path / "candidate.exe"
    original_path.write_bytes(original)
    candidate_path.write_bytes(candidate)
    report = compare_binary16(original_path, candidate_path, catalog, other_catalog, selected=("loop",))
    assert report["status"] == expected, {"proof": report["proof"], "backend": report["backend"]}
    if expected == "proved":
        assert report["proof"]["verdicts"][0]["method"] == "ssa_z3_closed_call_loop_induction"


@pytest.mark.parametrize("iterations", [0, 1, 100])
def test_call_loop_zero_one_many_independent_execution(iterations):
    original, _ = _fixture(bytes.fromhex("43c3"))
    equivalent, _ = _fixture(bytes.fromhex("9043c3"))
    mutated, _ = _fixture(bytes.fromhex("4bc3"))
    images = [image_from_mz_bytes(data) for data in (original, equivalent, mutated)]
    entry = SegOffset(images[0].load_segment, 0x200)
    vector = Real16Vector(
        registers=(("ax", iterations), ("bx", 7), ("sp", 0x100), ("flags", 2)),
        segments=(("ss", 0x7000), ("ds", entry.segment), ("es", entry.segment)),
        frame=CallerFrame(FrameKind.NEAR16, SegOffset(entry.segment, 0x8000)),
    )
    results = [replay(image, entry, vector, instruction_limit=10000) for image in images]
    assert dict(results[0].registers)["bx"] == 7 + iterations
    assert compare_executions(results[0], results[1]).agreement is Real16Agreement.AGREED
    expected = Real16Agreement.AGREED if iterations == 0 else Real16Agreement.MISMATCHED
    assert compare_executions(results[0], results[2]).agreement is expected


NESTED_BODY = bytes.fromhex("89c1 e30f 89f2 85d2 7406 e82300 4a ebf6 49 75f1 c3")


@pytest.mark.parametrize("branch", (0x74, 0x75))
@pytest.mark.parametrize("original,candidate", (
    ("3d0500", "83fb07"), ("39d8", "39ca"),
    ("3b4604", "3b5e04"), ("3b060402", "3b1e0402"),
    ("80f805", "80fb07"),
), ids=("immediate", "register", "stack", "absolute", "byte"))
def test_cmp_jcc_cannot_hide_changed_observable_flags(monkeypatch, original, candidate, branch):
    """Equal branch destinations do not make different CMP flag effects equal."""
    monkeypatch.setattr(Instruction_ANY, "_inertia_pending_condition_sources_by_addr", {})
    monkeypatch.setattr(Instruction_ANY, "_inertia_module_condition_cache", {})
    states, native_flags = [], []
    for prefix in (original, candidate):
        code = bytes.fromhex(prefix) + bytes((branch, 0))
        block = pyvex.IRSB(code, 0x4000, Arch86_16(), opt_level=0)
        lowered = S._lower_irsb(block, output_regs=S.INTERNAL_STATE_REGS, max_assignments_per_function=0)
        assert isinstance(lowered, dict), lowered
        states.append(lowered)
        machine = Uc(UC_ARCH_X86, UC_MODE_16)
        machine.mem_map(0, 0x1000)
        machine.mem_map(0x4000, 0x1000)
        machine.mem_write(0x4000, code)
        machine.reg_write(UC_X86_REG_AX, 5)
        machine.reg_write(UC_X86_REG_BP, 0x100)
        machine.reg_write(UC_X86_REG_EFLAGS, 2)
        machine.emu_start(0x4000, 0x4000 + len(code), count=2)
        native_flags.append(machine.reg_read(UC_X86_REG_EFLAGS) & 0xffff)
    assert native_flags[0] != native_flags[1], native_flags
    result = S._compare_functions(*states, timeout_ms=15000)
    assert proof_status_from_legacy(result["status"]) is ProofStatus.COUNTEREXAMPLE, result


@pytest.mark.parametrize("opcode", (0x74, 0x75))
@pytest.mark.parametrize("producer", ("test", "flags", "cmp"))
def test_jcc_execution_ignores_unbound_prior_image_condition(monkeypatch, opcode, producer):
    """A prior image's same-address CMP cannot replace live TEST or FLAGS."""
    monkeypatch.setattr(Instruction_ANY, "_inertia_pending_condition_sources_by_addr", {})
    monkeypatch.setattr(Instruction_ANY, "_inertia_module_condition_cache", {})
    arch = Arch86_16()
    # The first image publishes CMP provenance at its branch successors.
    pyvex.IRSB(bytes.fromhex("3d05007406"), 0x4003, arch, opt_level=0)
    assert 0x4008 in Instruction_ANY._inertia_pending_condition_sources_by_addr
    prefix, address = {"test": ("89f285d2", 0x4004),
                       "flags": ("", 0x4008), "cmp": ("3d0700", 0x4005)}[producer]
    block = pyvex.IRSB(bytes.fromhex(prefix) + bytes((opcode, 6)), address, arch, opt_level=0)
    lowered = S._lower_irsb(block, output_regs=S.INTERNAL_STATE_REGS, max_assignments_per_function=0)
    assert isinstance(lowered, dict), lowered
    def constant(value: int, width: int) -> dict[str, object]:
        """Build one exact bitvector literal for the independent predicate."""
        return {"op": "const", "value": hex(value), "width": width}

    def register(name: str) -> dict[str, object]:
        """Read the current symbolic architectural word register."""
        return {"op": "input", "name": name, "width": 16}
    if producer == "flags":
        zero = {"op": "ne", "width": 1, "args": [
            {"op": "and", "width": 16, "args": [register("flags"), constant(0x40, 16)]},
            constant(0, 16)]}
    else:
        zero = {"op": "eq", "width": 1, "args": [
            register("si" if producer == "test" else "ax"),
            constant(0 if producer == "test" else 7, 16)]}
    taken, fallthrough = 0x4010, 0x400a
    if opcode == 0x75:
        taken, fallthrough = fallthrough, taken
    expected = materialize_function("expected", {
        "control_ip": {"op": "ite", "width": 32,
                       "args": [zero, constant(taken, 32), constant(fallthrough, 32)]}})
    lowered["outputs"] = {"control_ip": lowered["outputs"]["control_ip"]}
    result = S._compare_functions(lowered, expected, timeout_ms=15000)
    assert proof_status_from_legacy(result["status"]) is ProofStatus.PROVED, result


@pytest.mark.parametrize("inner_guard,expected", [(0x74, ProofStatus.PROVED), (0x75, ProofStatus.UNKNOWN)])
def test_nested_call_loop_induction_checks_inner_exit(tmp_path, inner_guard, expected):
    """An inner and outer loop both require complete transition obligations."""
    original = _document(tmp_path, "nested-original", bytes.fromhex("43c3"), NESTED_BODY)
    changed = bytearray(NESTED_BODY)
    changed[8] = inner_guard
    candidate = _document(tmp_path, "nested-candidate", bytes.fromhex("9043c3"), bytes(changed))
    proof = compare_real16_loop_calls(original, candidate, "demo.exe:loop", timeout_ms=60000)
    failure_receipt = tmp_path / "nested-loop-failure.json"
    if proof.status is not expected:
        write_json(failure_receipt, {"original": original, "candidate": candidate,
                                     "proof": asdict(proof)})
    assert proof.status is expected, {"proof": proof, "receipt": str(failure_receipt)}
    assert proof.transitions
    assert (proof.counters.failure_count == 0) is (expected is ProofStatus.PROVED)


@pytest.mark.parametrize("outer,inner", [(0, 7), (7, 0), (1, 1), (10, 100)])
def test_nested_call_loops_match_independent_execution(outer, inner):
    """Zero-trip inner/outer loops and repeated calls agree in fresh guests."""
    original, _ = _fixture(bytes.fromhex("43c3"), NESTED_BODY)
    equivalent, _ = _fixture(bytes.fromhex("9043c3"), NESTED_BODY)
    changed = bytearray(NESTED_BODY)
    changed[8] = 0x75
    mutated, _ = _fixture(bytes.fromhex("9043c3"), bytes(changed))
    images = [image_from_mz_bytes(data) for data in (original, equivalent, mutated)]
    entry = SegOffset(images[0].load_segment, 0x200)
    vector = Real16Vector(
        registers=(("ax", outer), ("si", inner), ("bx", 7), ("sp", 0x100), ("flags", 2)),
        segments=(("ss", 0x7000), ("ds", entry.segment), ("es", entry.segment)),
        frame=CallerFrame(FrameKind.NEAR16, SegOffset(entry.segment, 0x8000)),
    )
    results = [replay(image, entry, vector, instruction_limit=20000) for image in images]
    assert dict(results[0].registers)["bx"] == 7 + outer * inner
    assert compare_executions(results[0], results[1]).agreement is Real16Agreement.AGREED
    if outer and inner:
        assert compare_executions(results[0], results[2]).agreement is Real16Agreement.MISMATCHED
