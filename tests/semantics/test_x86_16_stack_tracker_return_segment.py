"""Keep native SP transfer consistent with proven far-return prefixes."""

import io
from dataclasses import replace

import angr
import pytest
from angr.calling_conventions import SimCCStdcall
from angr.sim_type import SimTypeFunction, SimTypeInt
import inertia.frontend.x86_16.stack_tracker_return_segment as adapter
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.ir import IRFunctionArtifact, IRValue, MemSpace
from inertia.ir.vex_import import _block_to_ir
from tests.frontend.test_x86_16_packed_mz import _mz
from tests.semantics.test_x86_16_call_return_segment import _project
from tests.semantics.test_x86_16_call_stack_effects import _summary

from inertia.semantics.call_return_segment import collect_return_segment_frames_8616
from inertia.semantics.call_stack_effects import materialize_call_stack_effects_8616


def _track_machine_frame(call):
    # Save DI, pass one word, call, discard the argument, then restore DI.
    # Unknown indirect targets do not change the encoded machine frame width.
    prefix = bytes.fromhex("55 8b ec 57 50 " + call)
    code = prefix + bytes.fromhex("83 c4 02 5f 8b e5 5d c3")
    code = code.ljust(0x20, b"\x90") + b"\xcb"
    project = angr.load_shellcode(code, arch=Arch86_16(), load_address=0x1000)
    cfg = project.analyses.CFGFast(normalize=True, function_starts=[0x1000])
    tracker = project.analyses.StackPointerTracker(cfg.kb.functions[0x1000], {project.arch.sp_offset})
    return tracker, 0x1000 + len(prefix) + 3, project.arch.sp_offset


@pytest.mark.parametrize(("call", "adjustment"), [
    ("ff 56 06", 0), ("ff 5e 06", 2), ("9a 20 10 00 00", 2),
    ("66 ff 56 06", 2), ("66 ff 5e 06", 6),
])
def test_native_tracker_balances_machine_call_frame_before_restore(call, adjustment):
    tracker, restore, sp_offset = _track_machine_frame(call)
    assert tracker.offset_before(restore, sp_offset) == (-4 & 0xffffffff)
    reports = tracker._inertia_machine_call_frames_8616
    assert reports
    assert all(report.adjustment == adjustment for report in reports)
    assert all(report.raw_fact_count == report.normalized_fact_count == 1 for report in reports)
    assert all(report.classified_fact_count == report.materialized_count == 1 for report in reports)
    assert all(report.failure_count == 0 for report in reports)


@pytest.mark.parametrize("refusal", ["unknown", "wrong_return_edge"])
def test_native_tracker_refuses_unproven_machine_frame(monkeypatch, refusal):
    original = adapter.decode_machine_call_frame_8616

    def decode(project, address):
        frame = original(project, address)
        if refusal == "unknown":
            return None
        return replace(frame, return_addr=frame.return_addr + 1)

    monkeypatch.setattr(adapter, "decode_machine_call_frame_8616", decode)
    tracker, restore, sp_offset = _track_machine_frame("ff 5e 06")
    assert tracker.offset_before(restore, sp_offset) is None
    assert all(report.failure_count == 1 for report in tracker._inertia_machine_call_frames_8616)
    assert all(report.materialized_count == 0 for report in tracker._inertia_machine_call_frames_8616)


@pytest.mark.parametrize("base", [0x1000, 0x11000])
@pytest.mark.parametrize(("callee", "expected"), [("c2 08 00", 0), ("c3", -8)])
def test_native_cleanup_resolves_near_targets_in_loaded_code_segment(base, callee, expected):
    code = bytes.fromhex("50 50 50 50 e8 01 00 c3 " + callee)
    project = angr.Project(
        io.BytesIO(_mz(code, header_paragraphs=4)), auto_load_libs=False,
        main_opts={"backend": "dos_mz", "base_addr": base},
    )
    cfg = project.analyses.CFGFast(normalize=True, function_starts=[base, base + 8])
    tracker = project.analyses.StackPointerTracker(cfg.kb.functions[base], {project.arch.sp_offset})
    assert tracker.offset_before(base + 7, project.arch.sp_offset) == (expected & 0xffffffff)


def _patched_call_import(monkeypatch, mutate_block):
    """Patch the adapter's IR import with one block-level mutation."""
    real_import = adapter._block_to_ir
    seen = []

    def _imported(block):
        imported, transport, terminal_evidence = real_import(block)
        if any(instruction.op == "CALL" for instruction in imported.instrs):
            seen.append(imported)
        return mutate_block(imported), transport, terminal_evidence

    monkeypatch.setattr(adapter, "_block_to_ir", _imported)
    return seen


def _unbound_operand(block):
    """Replace the retained symbolic CALL operand with an unbound temporary."""
    return replace(
        block,
        instrs=tuple(
            replace(
                instruction,
                args=(IRValue(MemSpace.TMP, name="unbound_test_operand", size=4),),
            )
            if instruction.op == "CALL"
            else instruction
            for instruction in block.instrs
        ),
    )


def _changed_producer(block):
    """Rewrite the CALL operand's producer instruction to a foreign shape."""
    call = next(instruction for instruction in block.instrs if instruction.op == "CALL")
    producer_tmp = call.args[0].source_tmp
    return replace(
        block,
        instrs=tuple(
            replace(instruction, op="Iop_Xor32")
            if instruction.dst is not None
            and instruction.dst.source_tmp == producer_tmp
            else instruction
            for instruction in block.instrs
        ),
    )


def _retargeted_operand(block):
    """Point the CALL operand at a real but foreign block temporary."""
    return replace(
        block,
        instrs=tuple(
            replace(
                instruction,
                args=(replace(instruction.args[0], source_tmp=0),),
            )
            if instruction.op == "CALL"
            else instruction
            for instruction in block.instrs
        ),
    )


@pytest.mark.parametrize("mutate", [_unbound_operand, _changed_producer, _retargeted_operand])
def test_native_cleanup_refuses_an_unproven_call_operand(monkeypatch, mutate):
    """A forged or retargeted CALL operand must not admit the decoded target."""
    project, function = _project("c2 02 00")
    seen = _patched_call_import(monkeypatch, mutate)
    tracker = project.analyses.StackPointerTracker(function, {project.arch.sp_offset})
    assert seen
    assert tracker.offset_before(0x1004, project.arch.sp_offset) == (-2 & 0xffffffff)


def test_native_cleanup_binds_the_imported_call_operand():
    """The adapter consumes the binding owner's proven target, not a guess."""
    project, _function = _project("c3")
    bound = adapter._bound_terminal_direct_call_8616(
        project, project.factory.block(0x1000).vex,
    )
    assert bound is not None
    _block, instruction, target = bound
    assert instruction.op == "CALL" and instruction.addr == 0x1001
    assert target == 0x1005


def test_native_cleanup_refuses_a_divergent_slice_original_encoding():
    """The slice→original correspondence must match the exact call encoding."""
    code = bytes.fromhex("50 50 50 50 e8 01 00 c3 c2 08 00")
    divergent = code[:4] + bytes.fromhex("e8 00 00") + code[7:]
    original = angr.Project(
        io.BytesIO(_mz(divergent, header_paragraphs=4)), auto_load_libs=False,
        main_opts={"backend": "dos_mz", "base_addr": 0x10000},
    )
    sliced = angr.Project(
        io.BytesIO(code[:8]), auto_load_libs=False,
        main_opts={"backend": "blob", "arch": original.arch, "base_addr": 0x1000, "entry_point": 0x1000},
    )
    sliced._inertia_original_project = original
    sliced._inertia_original_linear_delta = 0xf000
    cfg = sliced.analyses.CFGFast(normalize=True)
    tracker = sliced.analyses.StackPointerTracker(cfg.kb.functions[0x1000], {sliced.arch.sp_offset})
    assert tracker.offset_before(0x1007, sliced.arch.sp_offset) == (-8 & 0xffffffff)


def test_native_cleanup_rebases_out_of_slice_target_exactly_once():
    code = bytes.fromhex("50 50 50 50 e8 01 00 c3 c2 08 00")
    original = angr.Project(
        io.BytesIO(_mz(code, header_paragraphs=4)), auto_load_libs=False,
        main_opts={"backend": "dos_mz", "base_addr": 0x10000},
    )
    sliced = angr.Project(
        io.BytesIO(code[:8]), auto_load_libs=False,
        main_opts={"backend": "blob", "arch": original.arch, "base_addr": 0x1000, "entry_point": 0x1000},
    )
    sliced._inertia_original_project = original
    sliced._inertia_original_linear_delta = 0xf000
    cfg = sliced.analyses.CFGFast(normalize=True)
    tracker = sliced.analyses.StackPointerTracker(cfg.kb.functions[0x1000], {sliced.arch.sp_offset})
    assert tracker.offset_before(0x1007, sliced.arch.sp_offset) == 0


@pytest.mark.parametrize("callee", ["cb", "85 c0 74 01 cb cb"])
def test_native_tracker_consumes_proven_return_segment(callee):
    project, function = _project(callee)
    tracker = project.analyses.StackPointerTracker(function, {project.arch.sp_offset})
    assert tracker.offset_before(0x1004, project.arch.sp_offset) == 0


def test_native_tracker_keeps_cs_argument_for_near_return():
    project, function = _project("c3")
    tracker = project.analyses.StackPointerTracker(function, {project.arch.sp_offset})
    assert tracker.offset_before(0x1004, project.arch.sp_offset) == (-2 & 0xffffffff)


@pytest.mark.parametrize(("callee", "expected"), [("c2 02 00", 0), ("c3", -2)])
def test_native_tracker_consumes_binary_near_argument_cleanup(callee, expected):
    project, function = _project(callee)
    tracker = project.analyses.StackPointerTracker(function, {project.arch.sp_offset})
    assert tracker.offset_before(0x1004, project.arch.sp_offset) == (expected & 0xffffffff)


@pytest.mark.parametrize("callee", ["c2 02 00", "c3"])
def test_binary_cleanup_replaces_native_prototype_estimate(callee):
    project, function = _project(callee)
    target = project.kb.functions[0x1005]
    target.calling_convention = SimCCStdcall(project.arch)
    target.prototype = SimTypeFunction([SimTypeInt()], SimTypeInt()).with_arch(project.arch)
    tracker = project.analyses.StackPointerTracker(function, {project.arch.sp_offset})
    expected = 0 if callee.startswith("c2") else -2
    assert tracker.offset_before(0x1004, project.arch.sp_offset) == (expected & 0xffffffff)


@pytest.mark.parametrize("callee", ["85 c0 74 03 c2 02 00 c3", "ff e0"])
def test_native_cleanup_does_not_guess_from_incomplete_or_mixed_returns(callee):
    project, function = _project(callee)
    tracker = project.analyses.StackPointerTracker(function, {project.arch.sp_offset})
    assert tracker.offset_before(0x1004, project.arch.sp_offset) == (-2 & 0xffffffff)


@pytest.mark.parametrize(("callee", "adjustment"), [("cb", 2), ("c3", 0)])
@pytest.mark.parametrize("arg_widths", [(), (2, 2)])
def test_ir_call_effect_consumes_the_same_return_segment_proof(callee, adjustment, arg_widths):
    project, function = _project(callee)
    block, _transport, _terminal_evidence = _block_to_ir(project.factory.block(0x1000))
    artifact = IRFunctionArtifact(0x1000, (block,))
    summary = replace(
        _summary(arg_widths=arg_widths, cleanup=sum(arg_widths)),
        callsite_addr=0x1001, target_addr=0x1005, return_addr=0x1004,
    )
    frames = collect_return_segment_frames_8616(project, function, {0x1001: 0x1004})
    result = materialize_call_stack_effects_8616(
        artifact, {0x1001: summary}, return_segment_frames={frame.callsite_addr: frame for frame in frames},
    )
    assert result.complete
    assert result.facts[0].effect.net_stack_delta == adjustment


def test_block_scoped_return_proof_matches_full_function_collection():
    project, function = _project("cb")
    full = collect_return_segment_frames_8616(project, function, {0x1001: 0x1004})
    scoped = collect_return_segment_frames_8616(project, function, {0x1001: 0x1004}, block_addr=0x1000)
    assert scoped == full
    refused = collect_return_segment_frames_8616(project, function, {0x1001: 0x1004}, block_addr=0x1005)
    assert refused[0].additional_return_bytes is None
