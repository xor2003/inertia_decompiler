"""Independent genuine-MZ boot intake regression for parent review."""
import io
from dataclasses import replace

import angr
import pytest

from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.frontend.x86_16.frontend_direct_callsite_index import build_boundary_direct_callsite_index_8616
from inertia.frontend.x86_16.frontend_function_boundary import exact_function_range_boundary_8616
from inertia.ir import entry_domain_call_preservation as owner
from inertia.ir.function_ir_registry import FunctionIRArtifactVerdict8616, registered_function_ir_artifact_8616
from inertia.ir.real16_invocation_domain import real16_native_census_import_8616
from inertia.lowering.analysis_helpers import resolve_direct_call_target_from_instruction_8616
from tools.dosunit.runtime.real16_program_boot import program_from_mz_bytes
from tools.dosunit.runtime.real16_replay_model import LinearRange


def _mz(image: bytes) -> bytes:
    """Build a source-bound MZ with an initialized stack disjoint from code."""
    header = bytearray(32)
    header[:2] = b"MZ"
    values = {2: (32 + len(image)) % 512, 4: (32 + len(image) + 511) // 512,
              8: 2, 10: 0x10, 12: 0x20, 14: 0x10, 16: 0x100, 24: 0x1c}
    for offset, value in values.items():
        header[offset:offset + 2] = value.to_bytes(2, "little")
    return bytes(header) + image


def _recompute(boot: object) -> object:
    """Reconstruct source authority without borrowing its derived entry."""
    return program_from_mz_bytes(boot.source, boot.environment, code_ranges=boot.image.code_ranges)


def _world(prefix: bytes = bytes.fromhex("eb0e")) -> tuple:
    """Retain genuine bytes, frontend census and raw native IR."""
    from tools.dosunit.runtime.real16_program_boot import ProgramEnvironment
    image = prefix + bytes.fromhex("90") * (16 - len(prefix)) + bytes.fromhex("e81000c3") + bytes(0x23-0x14) + bytes.fromhex("c3")
    environment = ProgramEnvironment(psp_segment=0xff0, allocation=bytes(0x300),
        registers=tuple((name, 0) for name in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eflags")), fs=0, gs=0)
    boot = program_from_mz_bytes(_mz(image), environment, code_ranges=(LinearRange(0x10000, len(prefix)), LinearRange(0x10010, 4), LinearRange(0x10023, 1)))
    arch = Arch86_16()
    arch.bits = 32
    project = angr.Project(io.BytesIO(boot.image.chunks[0][1]), main_opts={"backend":"blob", "arch":arch, "base_addr":0x10000, "entry_point":0x10000}, auto_load_libs=False)
    boundary = exact_function_range_boundary_8616(project,0x10000,0x10014)
    assert boundary is not None
    raw = real16_native_census_import_8616(project,boundary)
    assert raw is not None
    return project, boundary, raw, boot


def test_authenticated_boot_pending_jump_reaches_call_without_registry_publication(monkeypatch):
    project, boundary, raw, boot = _world()
    assert any(block.refusals for block in raw.blocks)
    index = build_boundary_direct_callsite_index_8616(boundary, direct_target_resolver=lambda instruction:resolve_direct_call_target_from_instruction_8616(project,instruction))
    source = owner.Real16InvocationSource8616(boot,_recompute,index)
    owner.install_real16_invocation_source_8616(project,source)
    monkeypatch.setattr(owner,"_exact_boundary_for_8616",lambda current,head:boundary if current is project and head==0x10000 else None)
    result = owner._registered_invocation_premise_8616(project,0x10000,0x10010,source,owner._PremiseResolution8616())
    assert result is not None, "raw boot census must run before universal jump closure"
    assert result.complete
    assert registered_function_ir_artifact_8616(project,0x10000).verdict is not FunctionIRArtifactVerdict8616.PROVEN


def _prove(project, boundary, raw, boot):
    from inertia.ir.real16_boot_entry_link import RawBootEntrySurface8616
    from inertia.ir.real16_invocation_domain import prove_real16_raw_boot_invocation_domain_8616
    return prove_real16_raw_boot_invocation_domain_8616(project, RawBootEntrySurface8616(raw,boundary),0x10010,boot=boot,boot_recompute=_recompute)


def test_raw_boot_proof_rejects_changed_native_source():
    project, boundary, raw, boot = _world()
    premise = _prove(project,boundary,raw,boot)
    assert premise.complete
    project.loader.memory.store(0x10000, bytes.fromhex("90"))
    assert not premise.complete
    assert not _prove(project,boundary,raw,boot).complete


def test_raw_boot_proof_rejects_foreign_project():
    _, boundary, raw, boot = _world()
    foreign, _, _, _ = _world()
    assert not _prove(foreign,boundary,raw,boot).complete


def test_raw_boot_proof_rejects_tampered_native_capture():
    project, boundary, raw, boot = _world()
    block = raw.blocks[0]
    row = next(i for i in block.instrs if i.op == "JMP")
    assert row.args[0].source_tmp is not None
    forged = replace(row,args=(replace(row.args[0],source_tmp=row.args[0].source_tmp+1),))
    rows = tuple(forged if i is row else i for i in block.instrs)
    changed = replace(raw,blocks=(replace(block,instrs=rows),*raw.blocks[1:]))
    assert not _prove(project,boundary,changed,boot).complete


def test_raw_boot_proof_rejects_tampered_native_metadata():
    project, boundary, raw, boot = _world()
    block = raw.blocks[0]
    changed = replace(raw,blocks=(replace(block,addr=block.addr+1),*raw.blocks[1:]))
    assert not _prove(project,boundary,changed,boot).complete


def test_raw_boot_proof_rejects_pending_edge_treated_as_exit():
    project, boundary, raw, boot = _world()
    block = next(b for b in raw.blocks if b.refusals)
    dropped = replace(block,successor_addrs=())
    changed = replace(raw,blocks=tuple(dropped if b is block else b for b in raw.blocks))
    assert not _prove(project,boundary,changed,boot).complete


@pytest.mark.parametrize("prefix", [bytes.fromhex("c606000190eb09"), bytes.fromhex("cd21eb0c"), bytes.fromhex("ffd0eb0c")])
def test_raw_boot_proof_keeps_code_store_undeclared_interrupt_and_unmodeled_call_unproven(prefix):
    project,boundary,raw,boot = _world(prefix)
    assert not _prove(project,boundary,raw,boot).complete


@pytest.mark.parametrize("returns_premise", [True, False])
def test_standalone_deadline_blocks_late_raw_result_and_universal_retry(monkeypatch, returns_premise):
    project,boundary,raw,boot = _world()
    valid = _prove(project,boundary,raw,boot)
    assert valid.complete
    index = build_boundary_direct_callsite_index_8616(boundary,direct_target_resolver=lambda instruction:resolve_direct_call_target_from_instruction_8616(project,instruction))
    source = owner.Real16InvocationSource8616(boot,_recompute,index)
    elapsed = [0.0]
    def raw_intake(*args):
        elapsed[0] = 11.0
        return valid if returns_premise else None
    def forbidden_universal(*args):
        pytest.fail("expired raw work must not enter universal intake")
    monkeypatch.setattr(owner,"_raw_boot_invocation_premise_8616",raw_intake)
    monkeypatch.setattr(owner,"_resolution_deadline_expired_8616",lambda current,deadline:elapsed[0] >= deadline)
    monkeypatch.setattr(owner,"_caller_premise_surface_8616",forbidden_universal)
    resolution = owner._PremiseResolution8616(deadline=10.0)
    result = owner._registered_invocation_premise_8616(project,0x10000,0x10010,source,resolution)
    assert result is None
    assert resolution.in_flight == frozenset()


@pytest.mark.parametrize("prefix,complete", [
    ("ba34122e89165000eb06", True),
    ("ba34122e89161000eb06", False),
    ("2e8907eb0b", False),
    ("ba34122e67891650000000eb03", False),
])
def test_native_cs_store_requires_safe_captured_span(prefix, complete):
    """Prove CS data writes; reject direct/indexed code writes and address32."""
    project, boundary, raw, boot = _world(bytes.fromhex(prefix))
    result = _prove(project, boundary, raw, boot)
    assert result.complete is complete
    assert result.classified_fact_count == result.materialized_count + result.failure_count
    if complete:
        assert result.failure is None
        assert result.checked_store_count == 4
        assert result.callsite_memory is not None
        known = dict(result.callsite_memory.known)
        assert known[0x10050] == 0x34
        assert known[0x10051] == 0x12


@pytest.mark.parametrize("tamper", ["origin", "offset"])
def test_native_cs_store_rejects_forged_capture_or_displaced_effect(tamper):
    """A copied origin cannot authenticate an altered raw write."""
    project, boundary, raw, boot = _world(bytes.fromhex("ba34122e89165000eb06"))
    block = raw.blocks[0]
    store = next(row for row in block.instrs if row.op == "STORE")
    assert store.origin is not None and store.origin.address_tmp is not None
    if tamper == "origin":
        changed_store = replace(store, origin=replace(store.origin, address_tmp=store.origin.address_tmp + 1))
    else:
        changed_store = replace(store, args=(replace(store.args[0], offset=store.args[0].offset + 1), store.args[1]))
    changed_block = replace(block, instrs=tuple(changed_store if row is store else row for row in block.instrs))
    changed = replace(raw, blocks=(changed_block, *raw.blocks[1:]))
    assert not _prove(project, boundary, changed, boot).complete


def test_native_cs_store_uses_capture_or_proven_instruction_entry():
    """Unknown addresses refuse; either native capture or entry facts prove a span."""
    from inertia.ir.real16_invocation_domain import _native_store_span_8616

    _project, _boundary, raw, _boot = _world(bytes.fromhex("ba34122e89165000eb06"))
    store = next(row for row in raw.blocks[0].instrs if row.op == "STORE")
    assert store.origin is not None and store.origin.address_tmp is not None
    capture = store.origin.address_tmp
    assert _native_store_span_8616(store, {}, set(), {}) is None
    assert _native_store_span_8616(store, {"cs": 0x1000}, set(), {}) == (0x10050, 1)
    assert _native_store_span_8616(store, {"cs": 0x1200}, {"cs"}, {capture: 0x10050}) == (0x10050, 1)


def test_native_store_rejects_capture_contradicting_segmented_span():
    """A native capture must agree with any independently proven DS span."""
    from inertia.ir.real16_invocation_domain import _native_store_span_8616

    _project, _boundary, raw, _boot = _world(bytes.fromhex("ba341289165000eb07"))
    store = next(row for row in raw.blocks[0].instrs if row.op == "STORE")
    assert store.origin is not None and store.origin.address_tmp is not None
    capture = store.origin.address_tmp
    assert _native_store_span_8616(store, {"ds": 0x1100}, set(), {capture: 0x10050}) is None
    assert _native_store_span_8616(store, {"ds": 0x1000}, set(), {capture: 0x10050}) == (0x10050, 1)


def test_raw_boot_retains_declared_service_refusal(monkeypatch):
    """Unknown version selector remains typed and cannot start deep intake."""
    from inertia.frontend.x86_16.mz_static_boot import mz_static_boot_8616, recompute_mz_static_boot_8616
    from inertia.ir.real16_invocation_domain import Real16InvocationFailure8616

    project, boundary, _, declared_boot = _world(bytes.fromhex("b430cd21eb0a"))
    boot = mz_static_boot_8616(declared_boot.source, 0x1000)
    index = build_boundary_direct_callsite_index_8616(
        boundary, direct_target_resolver=lambda instruction:
        resolve_direct_call_target_from_instruction_8616(project, instruction),
    )
    source = owner.Real16InvocationSource8616(boot, recompute_mz_static_boot_8616, index)
    monkeypatch.setattr(owner, "_exact_boundary_for_8616", lambda current, head: boundary)
    refused = owner._raw_boot_invocation_premise_8616(project, 0x10000, 0x10010, source)
    assert refused is not None, "an attempted census must retain its typed refusal"
    assert refused.failure is Real16InvocationFailure8616.DECLARED_SERVICE_UNPROVEN
    assert not refused.complete
    assert refused.failure_count > 0

    def forbidden_universal(*args):
        pytest.fail("deep intake cannot provide a missing declared service")

    monkeypatch.setattr(owner, "_caller_premise_surface_8616", forbidden_universal)
    resolution = owner._PremiseResolution8616()
    assert owner._registered_invocation_premise_8616(
        project, 0x10000, 0x10010, source, resolution,
    ) is None
    assert resolution.in_flight == frozenset()
    assert registered_function_ir_artifact_8616(project, 0x10000).verdict is not FunctionIRArtifactVerdict8616.PROVEN


@pytest.mark.parametrize("failure_name,incoming,expected_fallback", [
    (None, False, True),
    ("CALL_BOUNDARY_UNPROVEN", False, True),
    ("CENSUS_DEADLINE_EXCEEDED", False, True),
    ("DECLARED_SERVICE_UNPROVEN", False, False),
    ("DECLARED_SERVICE_UNPROVEN", True, True),
])
def test_raw_boot_refusal_preserves_other_premise_routes(monkeypatch, failure_name, incoming, expected_fallback):
    """Unavailable/call-bound raw facts and incoming edges retain recovery."""
    from types import SimpleNamespace

    from inertia.ir.real16_invocation_domain import Real16InvocationFailure8616

    project, boundary, raw, boot = _world()
    valid = _prove(project, boundary, raw, boot)
    assert valid.complete
    refused = None if failure_name is None else replace(
        valid, failure=Real16InvocationFailure8616[failure_name],
    )
    index = build_boundary_direct_callsite_index_8616(
        boundary, direct_target_resolver=lambda instruction:
        resolve_direct_call_target_from_instruction_8616(project, instruction),
    )
    source = owner.Real16InvocationSource8616(boot, _recompute, index)
    if incoming:
        # Only nonempty incoming evidence matters here; no row is consumed.
        source = replace(source, callsite_index=SimpleNamespace(for_target=lambda head: (object(),)))
    calls = []
    def universal(*args):
        calls.append(True)
        return None
    monkeypatch.setattr(owner, "_raw_boot_invocation_premise_8616", lambda *args: refused)
    monkeypatch.setattr(owner, "_caller_premise_surface_8616", universal)
    resolution = owner._PremiseResolution8616()
    assert owner._registered_invocation_premise_8616(
        project, 0x10000, 0x10010, source, resolution,
    ) is None
    assert bool(calls) is expected_fallback
    assert resolution.in_flight == frozenset()


@pytest.mark.parametrize("complete", [True, False])
def test_raw_completeness_replay_cannot_outlive_request(monkeypatch, complete):
    """The post-intake deadline includes costly completeness replay."""
    from types import SimpleNamespace

    elapsed = [0.0]
    class LatePremise:
        failure = None
        @property
        def complete(self):
            elapsed[0] = 11.0
            return complete

    project = object()
    source = owner.Real16InvocationSource8616(
        object(), None, SimpleNamespace(for_target=lambda head: ()),
    )
    def forbidden_universal(*args):
        pytest.fail("expired completeness replay must not enter deep intake")
    monkeypatch.setattr(owner, "_raw_boot_invocation_premise_8616", lambda *args: LatePremise())
    monkeypatch.setattr(owner, "_resolution_deadline_expired_8616", lambda current, deadline: elapsed[0] >= deadline)
    monkeypatch.setattr(owner, "_caller_premise_surface_8616", forbidden_universal)
    resolution = owner._PremiseResolution8616(deadline=10.0)
    assert owner._registered_invocation_premise_8616(project, 0x10000, 0x10010, source, resolution) is None
    assert resolution.in_flight == frozenset()


@pytest.mark.parametrize("expired,incoming,expected_fallback", [
    (True, False, False), (True, True, False), (False, True, True),
])
def test_raw_census_deadline_retry_belongs_to_current_traversal(monkeypatch, expired, incoming, expected_fallback):
    """Expired shared census budget stops retries; fresh budget retains them."""
    import time
    from types import SimpleNamespace

    from inertia.ir.real16_invocation_domain import Real16InvocationFailure8616
    from inertia.ir.segment_call_preservation import segment_call_dependency_traversal_scope_8616

    project = object()
    refused = SimpleNamespace(failure=Real16InvocationFailure8616.CENSUS_DEADLINE_EXCEEDED, complete=False)
    source = owner.Real16InvocationSource8616(
        object(), None, SimpleNamespace(for_target=lambda head: (object(),) if incoming else ()),
    )
    calls = []
    def universal(*args):
        calls.append(True)
        return None
    monkeypatch.setattr(owner, "_raw_boot_invocation_premise_8616", lambda *args: refused)
    monkeypatch.setattr(owner, "_caller_premise_surface_8616", universal)
    resolution = owner._PremiseResolution8616()
    with segment_call_dependency_traversal_scope_8616() as traversal:
        deadline = time.monotonic() + (-1 if expired else 60)
        traversal.census_deadline = deadline
        assert owner._registered_invocation_premise_8616(project, 0x10000, 0x10010, source, resolution) is None
        assert traversal.census_deadline == deadline
    assert bool(calls) is expected_fallback
    assert resolution.in_flight == frozenset()


def test_static_service_blocker_reuses_only_same_request(monkeypatch):
    """Repeated immutable startup prerequisites do not repeat native census."""
    from inertia.frontend.x86_16.mz_static_boot import mz_static_boot_8616, recompute_mz_static_boot_8616

    project, boundary, _, declared_boot = _world(bytes.fromhex("b430cd21eb0a"))
    boot = mz_static_boot_8616(declared_boot.source, 0x1000)
    index = build_boundary_direct_callsite_index_8616(
        boundary, direct_target_resolver=lambda instruction:
        resolve_direct_call_target_from_instruction_8616(project, instruction),
    )
    source = owner.Real16InvocationSource8616(boot, recompute_mz_static_boot_8616, index)
    monkeypatch.setattr(owner, "_exact_boundary_for_8616", lambda current, head: boundary)
    original = owner._raw_boot_invocation_premise_8616
    calls = []
    def observed(*args):
        calls.append(True)
        return original(*args)
    monkeypatch.setattr(owner, "_raw_boot_invocation_premise_8616", observed)
    monkeypatch.setattr(owner, "_caller_premise_surface_8616", lambda *args: None)
    session = owner._PremiseResolution8616()
    for _ in range(2):
        assert owner._registered_invocation_premise_8616(project, 0x10000, 0x10010, source, session) is None
    assert len(calls) == 1
    assert session.blocked_prefix_reuse_count == 1
    session.remaining = 0
    assert owner._registered_invocation_premise_8616(project, 0x10000, 0x10010, source, session) is None
    assert session.blocked_prefix_reuse_count == 1
    session.remaining = 10
    session.deadline = 0.0
    assert owner._registered_invocation_premise_8616(project, 0x10000, 0x10010, source, session) is None
    assert session.blocked_prefix_reuse_count == 1
    assert owner._registered_invocation_premise_8616(
        project, 0x10000, 0x10010, source, owner._PremiseResolution8616(),
    ) is None
    assert len(calls) == 2


@pytest.mark.parametrize("changed", ["source", "boot", "index", "image", "architecture", "registers", "registry", "incoming", "environment"])
def test_static_service_blocker_rechecks_current_snapshot(monkeypatch, changed):
    """Every mutable prerequisite change invalidates a retained refusal."""
    from inertia.frontend.x86_16.mz_static_boot import mz_static_boot_8616, recompute_mz_static_boot_8616
    from inertia.ir.raw_boot_blocked_prefix import (
        raw_boot_blocked_prefix_matches_8616,
        retain_raw_boot_blocked_prefix_8616,
    )

    project, boundary, _, declared_boot = _world(bytes.fromhex("b430cd21eb0a"))
    boot = mz_static_boot_8616(declared_boot.source, 0x1000)
    index = build_boundary_direct_callsite_index_8616(
        boundary, direct_target_resolver=lambda instruction:
        resolve_direct_call_target_from_instruction_8616(project, instruction),
    )
    source = owner.Real16InvocationSource8616(boot, recompute_mz_static_boot_8616, index)
    monkeypatch.setattr(owner, "_exact_boundary_for_8616", lambda current, head: boundary)
    refused = owner._raw_boot_invocation_premise_8616(project, 0x10000, 0x10010, source)
    retained = retain_raw_boot_blocked_prefix_8616(project, source, 0x10000, 0x10010, refused)
    assert retained is not None
    assert raw_boot_blocked_prefix_matches_8616(retained, project, source, 0x10000, 0x10010)
    if changed == "source":
        source = replace(source)
    elif changed == "boot":
        source = replace(source, boot=replace(boot))
    elif changed == "index":
        source = replace(source, callsite_index=replace(index))
    elif changed == "image":
        project.loader.memory.store(0x10000, b"\x90")
    elif changed == "architecture":
        project.arch.bits = 16
    elif changed == "registers":
        project.arch.registers = dict(project.arch.registers, ax=(999, 2))
    elif changed == "registry":
        project._inertia_function_ir_artifacts_8616 = {}
    elif changed == "incoming":
        index._entries_by_normalized_target[index.target_identity(0x10000)] = next(iter(index._entries_by_normalized_target.values()))
        assert index.for_target(0x10000)
    else:
        source = replace(source, boot=declared_boot, boot_recompute=_recompute)
    assert not raw_boot_blocked_prefix_matches_8616(retained, project, source, 0x10000, 0x10010)


@pytest.mark.parametrize("changed", ["project", "site", "refusal_site", "count", "budget"])
def test_static_service_blocker_rejects_unbound_refusals(monkeypatch, changed):
    """Only an actual source-bound classified service failure is retained."""
    from inertia.frontend.x86_16.mz_static_boot import mz_static_boot_8616, recompute_mz_static_boot_8616
    from inertia.ir.raw_boot_blocked_prefix import retain_raw_boot_blocked_prefix_8616
    from inertia.ir.real16_invocation_domain import Real16InvocationFailure8616

    project, boundary, _, declared_boot = _world(bytes.fromhex("b430cd21eb0a"))
    boot = mz_static_boot_8616(declared_boot.source, 0x1000)
    index = build_boundary_direct_callsite_index_8616(
        boundary, direct_target_resolver=lambda instruction:
        resolve_direct_call_target_from_instruction_8616(project, instruction),
    )
    source = owner.Real16InvocationSource8616(boot, recompute_mz_static_boot_8616, index)
    monkeypatch.setattr(owner, "_exact_boundary_for_8616", lambda current, head: boundary)
    refused = owner._raw_boot_invocation_premise_8616(project, 0x10000, 0x10010, source)
    assert refused is not None
    if changed == "project":
        refused = replace(refused, project=object())
    elif changed == "site":
        refused = replace(refused, callsite_addr=0x10011)
    elif changed == "refusal_site":
        refused = replace(refused, refusal_site=None)
    elif changed == "count":
        refused = replace(refused, failure_count=0)
    else:
        refused = replace(refused, failure=Real16InvocationFailure8616.CENSUS_DEADLINE_EXCEEDED)
    assert retain_raw_boot_blocked_prefix_8616(project, source, 0x10000, 0x10010, refused) is None


@pytest.mark.parametrize("changed", ["call", "branch", "bytes", "vector"])
def test_static_service_blocker_requires_unavoidable_native_prefix(monkeypatch, changed):
    """Preceding transfers and corrupt native captures cannot certify a blocker."""
    from types import SimpleNamespace

    from capstone import CS_GRP_CALL, CS_GRP_JUMP

    from inertia.frontend.x86_16.mz_static_boot import mz_static_boot_8616, recompute_mz_static_boot_8616
    from inertia.ir import raw_boot_blocked_prefix as blocked_owner

    project, boundary, _, declared_boot = _world(bytes.fromhex("b430cd21eb0a"))
    boot = mz_static_boot_8616(declared_boot.source, 0x1000)
    index = build_boundary_direct_callsite_index_8616(
        boundary, direct_target_resolver=lambda instruction:
        resolve_direct_call_target_from_instruction_8616(project, instruction),
    )
    source = owner.Real16InvocationSource8616(boot, recompute_mz_static_boot_8616, index)
    monkeypatch.setattr(owner, "_exact_boundary_for_8616", lambda current, head: boundary)
    refused = owner._raw_boot_invocation_premise_8616(project, 0x10000, 0x10010, source)
    assert refused is not None and refused.refusal_site is not None
    assert blocked_owner._unavoidable_interrupt_8616(refused, boot)
    native = blocked_owner._native_instructions_8616(refused.chain.boundary)
    address = refused.refusal_site.instruction_addr if changed == "vector" else 0x10000
    original = native[address]
    native[address] = SimpleNamespace(
        address=original.address, size=original.size, id=original.id,
        bytes=b"\x90" * original.size if changed == "bytes" else bytes(original.bytes),
        operands=(SimpleNamespace(imm=0x22),) if changed == "vector" else original.operands,
        group=lambda group: group == CS_GRP_CALL if changed == "call" else group == CS_GRP_JUMP if changed == "branch" else original.group(group),
    )
    monkeypatch.setattr(blocked_owner, "_native_instructions_8616", lambda surface: native)
    assert not blocked_owner._unavoidable_interrupt_8616(refused, boot)


@pytest.mark.parametrize("route,head,expected_imports", [
    ("unavailable", 0x10010, 0), ("boot", 0x10000, 1),
    ("incoming", 0x10023, 1), ("enclosed", 0x10022, 1),
    ("unknown", 0x10010, 1),
])
def test_current_entry_route_controls_universal_import(monkeypatch, route, head, expected_imports):
    """Only absence of both current entry routes avoids expensive import."""
    from inertia.frontend.x86_16.frontend_caller_entry_identity import CallerEntryIdentity8616

    project, boundary, _, boot = _world()
    index = build_boundary_direct_callsite_index_8616(
        boundary, direct_target_resolver=lambda instruction:
        resolve_direct_call_target_from_instruction_8616(project, instruction),
    )
    if route == "enclosed":
        # Exercise the index owner's canonical enclosing/NOP alias normalization.
        identity = CallerEntryIdentity8616(0x10022, 0x10024, 0x10023, b"\x90")
        index = replace(index, entry_identities=(identity,))
        assert index.for_target(head)
    source = owner.Real16InvocationSource8616(object() if route == "unknown" else boot, _recompute, index)
    calls = []
    monkeypatch.setattr(owner, "_request_raw_boot_premise_8616", lambda *args: None)
    monkeypatch.setattr(owner, "_caller_premise_surface_8616", lambda *args: calls.append(args))
    resolution = owner._PremiseResolution8616()
    remaining = resolution.remaining
    assert owner._registered_invocation_premise_8616(project, head, 0x10010, source, resolution) is None
    assert len(calls) == expected_imports
    assert resolution.remaining == remaining - 1
    assert resolution.in_flight == frozenset()


def test_current_entry_route_is_rechecked_for_fresh_source(monkeypatch):
    """An unavailable route is not negatively cached across source snapshots."""
    project, boundary, _, boot = _world()
    index = build_boundary_direct_callsite_index_8616(
        boundary, direct_target_resolver=lambda instruction:
        resolve_direct_call_target_from_instruction_8616(project, instruction),
    )
    missing = replace(index, _entries_by_normalized_target={})
    absent = owner.Real16InvocationSource8616(boot, _recompute, missing)
    fresh = replace(absent, callsite_index=index)
    calls = []
    monkeypatch.setattr(owner, "_request_raw_boot_premise_8616", lambda *args: None)
    monkeypatch.setattr(owner, "_caller_premise_surface_8616", lambda *args: calls.append(args))
    resolution = owner._PremiseResolution8616()
    for source in (absent, fresh):
        assert owner._registered_invocation_premise_8616(project, 0x10023, 0x10010, source, resolution) is None
    assert len(calls) == 1
    assert resolution.in_flight == frozenset()


def test_current_entry_route_extraction_consumes_request_budget(monkeypatch):
    """Boot-evidence extraction cannot admit import after the shared deadline."""
    from inertia.ir import real16_invocation_domain as domain

    project, boundary, _, boot = _world()
    index = build_boundary_direct_callsite_index_8616(
        boundary, direct_target_resolver=lambda instruction:
        resolve_direct_call_target_from_instruction_8616(project, instruction),
    )
    source = owner.Real16InvocationSource8616(boot, _recompute, index)
    expired = [False]
    extraction = domain._invocation_boot_evidence_8616
    def late_evidence(current):
        evidence = extraction(current)
        expired[0] = True
        return evidence
    monkeypatch.setattr(domain, "_invocation_boot_evidence_8616", late_evidence)
    monkeypatch.setattr(owner, "_request_raw_boot_premise_8616", lambda *args: None)
    monkeypatch.setattr(owner, "_resolution_deadline_expired_8616", lambda *args: expired[0])
    monkeypatch.setattr(owner, "_caller_premise_surface_8616", lambda *args: pytest.fail("expired route extraction must not import"))
    resolution = owner._PremiseResolution8616(deadline=10.0)
    assert owner._registered_invocation_premise_8616(project, 0x10000, 0x10010, source, resolution) is None
    assert expired[0]
    assert resolution.in_flight == frozenset()


@pytest.mark.parametrize(("segment_prefix", "register"), [(b"", "ds"), (b"\x36", "ss")])
def test_native_store_capture_survives_segment_state_loss(segment_prefix, register):
    """Native physical write evidence does not guess a missing segment alias."""
    from inertia.ir.real16_invocation_domain import _native_store_span_8616

    prefix = bytes.fromhex("ba3412") + segment_prefix + bytes.fromhex("89165000")
    prefix += bytes((0xeb, 16 - len(prefix) - 2))
    _, _, raw, _ = _world(prefix)
    store = next(row for row in raw.blocks[0].instrs if row.op == "STORE")
    assert store.origin is not None and store.origin.address_tmp is not None
    capture = store.origin.address_tmp
    assert _native_store_span_8616(store, {}, set(), {}) is None
    assert _native_store_span_8616(store, {register: 0x1000}, set(), {}) == (0x10050, 1)
    assert _native_store_span_8616(store, {register: 0x1200}, {register}, {capture: 0x10050}) == (0x10050, 1)
    assert _native_store_span_8616(store, {register: 0x1000}, set(), {capture: 0x10051}) is None



@pytest.mark.parametrize("known", [False, True])
def test_typed_compound_jump_target_closes_or_refuses_without_attribute_error(known):
    """Transfer checks evaluate typed value expressions without assuming IRValue fields."""
    from types import SimpleNamespace

    from inertia.ir import IRBinaryValue, IRValue, MemSpace
    from inertia.ir import real16_invocation_domain as invocation
    from inertia.ir.real16_boot_entry_link import RawBootEntrySurface8616

    _, boundary, raw, _ = _world()
    block = raw.blocks[0]
    assert block.refusals and len(block.successor_addrs) == 1
    jump = next(row for row in block.instrs if row.op == "JMP")
    target = IRBinaryValue(
        "Iop_Add32", IRValue(MemSpace.CONST, const=block.successor_addrs[0] - 1, size=4),
        IRValue(MemSpace.CONST, const=1, size=4) if known else IRValue(MemSpace.REG, name="eax", size=4),
        size=4,
    )
    changed = replace(jump, args=(target,))
    from inertia.ir.real16_path_memory8616 import PathMemory8616

    row = (block.addr, block.instrs.index(jump))
    ctx = SimpleNamespace(
        callsite_addr=0x10010, callee_return_rows=(), chain=RawBootEntrySurface8616(raw, boundary),
        work_units=1, accounted_work_units=0, work_limit=100,
        raw_facts={row}, normalized_facts=set(), classified_facts=set(), materialized_facts=set(),
        failures=0, first_failure_site=None,
    )
    verdict = invocation._simulate_instruction_8616(
        ctx, raw, block, changed, {}, {}, {}, set(), PathMemory8616(), row,
    )
    expected = None if known else invocation.Real16InvocationFailure8616.CS_PATH_UNPROVEN
    assert verdict is expected
    assert len(ctx.raw_facts) == len(ctx.normalized_facts) == len(ctx.classified_facts) == 1
    assert len(ctx.materialized_facts) == int(known)
    assert ctx.failures == int(not known)
    assert len(ctx.classified_facts) == len(ctx.materialized_facts) + ctx.failures
