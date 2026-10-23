"""Raw-boot record-backed prefix retry regression.

Layer: tests.
Responsibility: pin the exact ``CALL_BOUNDARY_UNPROVEN`` retry contract.

Fixture provenance: genuine MZ relocated at linear ``0x1000``. The boot
head JMPs over a NOP gap to ``0x1020``, which CALLs the leaf at ``0x1040``
and JMPs back to the pending selector-window block at ``0x1010`` whose own
CALL ``0x1080`` is the callsite. The prior interior call sits at a
*higher* address than the callsite, so only CFG ancestry — never numeric
address order — can select the records the raw census needs.

Obligation: the record-free raw proof refuses ``CALL_BOUNDARY_UNPROVEN``;
the registered premise route must retry exactly that failure with
independently proven prefix records before demanding whole-caller
coverage. Mutation, absent-evidence, and selection controls pin the
refusal legs.
"""
from __future__ import annotations

import io
from dataclasses import replace

import angr
import pytest

from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.frontend.x86_16.frontend_direct_callsite_index import (
    build_boundary_direct_callsite_index_8616,
)
from inertia.frontend.x86_16.frontend_function_boundary import (
    exact_function_range_boundary_8616,
)
from inertia.ir import entry_domain_call_preservation as owner
from inertia.ir import real16_invocation_domain as domain
from inertia.ir.core import IRBlock, IRFunctionArtifact, IRInstr
from inertia.ir.real16_boot_entry_link import RawBootEntrySurface8616
from inertia.ir.real16_invocation_domain import (
    Real16InvocationFailure8616,
    Real16InvocationKind8616,
    prove_real16_raw_boot_invocation_domain_8616,
    real16_native_census_import_8616,
)
from inertia.lowering.analysis_helpers import (
    resolve_direct_call_target_from_instruction_8616,
)
from tools.dosunit.runtime.real16_program_boot import program_from_mz_bytes
from tools.dosunit.runtime.real16_replay_model import LinearRange

HEAD = 0x1000
HEAD_END = 0x1025
CALLSITE = 0x1010
PREFIX_CALL = 0x1020
PREFIX_CALLEE = 0x1040


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


def _prefix_world() -> tuple:
    """Retain genuine bytes, frontend census and raw native IR.

    ``eb 1e`` at the head jumps to the prior CALL at ``0x1020``; that
    block calls the ``0x1040`` RET leaf and jumps back to the pending
    selector-window block at ``0x1010`` — the callsite — which calls the
    ``0x1080`` RET leaf and returns.
    """
    from tools.dosunit.runtime.real16_program_boot import ProgramEnvironment

    image = bytearray(b"\x90" * 0x81)
    image[:2] = bytes.fromhex("eb1e")
    image[0x10:0x14] = bytes.fromhex("e86d00c3")
    image[0x20:0x25] = bytes.fromhex("e81d00ebeb")
    image[0x40] = 0xC3
    image[0x80] = 0xC3
    environment = ProgramEnvironment(
        psp_segment=0xF0, allocation=bytes(0x300),
        registers=tuple(
            (name, 0)
            for name in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eflags")
        ),
        fs=0, gs=0,
    )
    boot = program_from_mz_bytes(
        _mz(bytes(image)),
        environment,
        code_ranges=(
            LinearRange(0x1000, 0x25),
            LinearRange(0x1040, 1),
            LinearRange(0x1080, 1),
        ),
    )
    arch = Arch86_16()
    arch.bits = 32
    project = angr.Project(
        io.BytesIO(boot.image.chunks[0][1]),
        main_opts={
            "backend": "blob",
            "arch": arch,
            "base_addr": 0x1000,
            "entry_point": 0x1000,
        },
        auto_load_libs=False,
    )
    boundary = exact_function_range_boundary_8616(project, HEAD, HEAD_END)
    assert boundary is not None
    raw = real16_native_census_import_8616(project, boundary)
    assert raw is not None
    return project, boundary, raw, boot


def _resolver(project: object):
    """Bind the public direct-call decoder to one loaded image."""
    return lambda instruction: resolve_direct_call_target_from_instruction_8616(
        project, instruction
    )


def _install(
    monkeypatch: pytest.MonkeyPatch, project: object, boundary: object, boot: object,
) -> object:
    """Install the typed source and bind the exact boot-boundary seam."""
    index = build_boundary_direct_callsite_index_8616(
        boundary, direct_target_resolver=_resolver(project)
    )
    source = owner.Real16InvocationSource8616(boot, _recompute, index)
    owner.install_real16_invocation_source_8616(project, source)
    original = owner._exact_boundary_for_8616
    monkeypatch.setattr(
        owner,
        "_exact_boundary_for_8616",
        lambda current, head: boundary
        if current is project and head == HEAD
        else original(current, head),
    )
    return source


def test_record_free_raw_boot_refuses_unproven_prefix_call() -> None:
    """The identical raw surface cannot cross an unrecorded interior CALL."""
    project, boundary, raw, boot = _prefix_world()
    premise = prove_real16_raw_boot_invocation_domain_8616(
        project, RawBootEntrySurface8616(raw, boundary), CALLSITE,
        boot=boot, boot_recompute=_recompute,
    )
    assert premise.failure is Real16InvocationFailure8616.CALL_BOUNDARY_UNPROVEN
    assert not premise.complete


def test_raw_boot_retry_collects_only_cfg_prefix_calls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Orchestration retries CALL_BOUNDARY with ancestor-path records only."""
    project, boundary, _raw, boot = _prefix_world()
    source = _install(monkeypatch, project, boundary, boot)
    seen: list[tuple[object, ...]] = []
    original = owner.collect_entry_domain_call_preservations_8616

    def observed(*args: object, **kwargs: object) -> object:
        records = original(*args, **kwargs)
        seen.append(records)
        return records

    monkeypatch.setattr(
        owner, "collect_entry_domain_call_preservations_8616", observed
    )
    premise = owner._registered_invocation_premise_8616(
        project, HEAD, CALLSITE, source, owner._PremiseResolution8616()
    )
    assert premise is not None
    assert premise.complete
    assert premise.kind is Real16InvocationKind8616.RAW_BOOT_ENTRY_PATH
    assert premise.callsite_addr == CALLSITE
    collected = {
        record.callsite_addr
        for records in seen
        for record in records
        if record.artifact is premise.chain.artifact
    }
    # The CALL at 0x1020 sits above the callsite numerically but precedes it
    # on the CFG; the callsite row itself and non-ancestor calls are absent.
    assert collected == {PREFIX_CALL}


def test_raw_boot_prefix_records_require_target_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Absent target evidence keeps the record and the premise refused."""
    project, boundary, _raw, boot = _prefix_world()
    source = _install(monkeypatch, project, boundary, boot)
    seen: list[tuple[object, ...]] = []
    original = owner.collect_entry_domain_call_preservations_8616

    def observed(*args: object, **kwargs: object) -> object:
        records = original(*args, **kwargs)
        seen.append(records)
        return records

    monkeypatch.setattr(
        owner, "collect_entry_domain_call_preservations_8616", observed
    )
    monkeypatch.setattr(
        owner,
        "_premise_target_resolver_8616",
        lambda project: lambda instruction: None,
    )
    premise = owner._raw_boot_invocation_premise_8616(
        project, HEAD, CALLSITE, source, owner._PremiseResolution8616()
    )
    assert premise is not None
    assert premise.failure is Real16InvocationFailure8616.CALL_BOUNDARY_UNPROVEN
    assert not premise.complete
    refused = [
        record
        for records in seen
        for record in records
        if record.artifact is premise.chain.artifact
    ]
    assert [record.callsite_addr for record in refused] == [PREFIX_CALL]
    assert all(record.failure is not None for record in refused)


def test_raw_boot_prefix_premise_rejects_mutated_callee_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Bytes mutated under a proven interior call revoke the retained premise."""
    project, boundary, _raw, boot = _prefix_world()
    source = _install(monkeypatch, project, boundary, boot)
    premise = owner._registered_invocation_premise_8616(
        project, HEAD, CALLSITE, source, owner._PremiseResolution8616()
    )
    assert premise is not None and premise.complete
    project.loader.memory.store(PREFIX_CALLEE, b"\xf4")
    assert not premise.complete
    assert (
        owner._registered_invocation_premise_8616(
            project, HEAD, CALLSITE, source, owner._PremiseResolution8616()
        )
        is None
    )


def test_raw_boot_retry_runs_only_for_call_boundary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A non-call-boundary refusal never triggers prefix record collection."""
    project, boundary, raw, boot = _prefix_world()
    source = _install(monkeypatch, project, boundary, boot)
    refused = prove_real16_raw_boot_invocation_domain_8616(
        project, RawBootEntrySurface8616(raw, boundary), CALLSITE,
        boot=boot, boot_recompute=_recompute,
    )
    refused = replace(
        refused, failure=Real16InvocationFailure8616.DECLARED_SERVICE_UNPROVEN
    )
    monkeypatch.setattr(
        domain,
        "prove_real16_raw_boot_invocation_domain_8616",
        lambda *args, **kwargs: refused,
    )
    monkeypatch.setattr(
        owner,
        "collect_entry_domain_call_preservations_8616",
        lambda *args, **kwargs: pytest.fail(
            "non-call-boundary refusal entered record collection"
        ),
    )
    premise = owner._raw_boot_invocation_premise_8616(
        project, HEAD, CALLSITE, source, owner._PremiseResolution8616()
    )
    assert premise is refused


def test_prefix_selection_uses_cfg_ancestors_not_address_order() -> None:
    """A numerically higher prior CALL is selected; unreachable calls are not."""
    prior_call = IRInstr("CALL", None, (), addr=0x1020)
    callsite = IRInstr("CALL", None, (), addr=0x1010)
    dead_call = IRInstr("CALL", None, (), addr=0x1040)
    head = IRBlock(
        0x1000, (IRInstr("JMP", None, (), addr=0x1000),), successor_addrs=(0x1020,)
    )
    prior = IRBlock(0x1020, (prior_call,), successor_addrs=(0x1010,))
    site = IRBlock(0x1010, (callsite,))
    unreachable = IRBlock(0x1040, (dead_call,))
    artifact = IRFunctionArtifact(0x1000, (head, site, prior, unreachable))
    assert owner._prefix_call_sites_8616(artifact, 0x1010) == frozenset({0x1020})


def test_prefix_selection_stops_at_the_callsite_row() -> None:
    """The callsite's own CALL and later rows are not preceding calls."""
    early = IRInstr("CALL", None, (), addr=0x1010)
    site = IRInstr("CALL", None, (), addr=0x1014)
    late = IRInstr("CALL", None, (), addr=0x1018)
    block = IRBlock(0x1010, (early, site, late))
    artifact = IRFunctionArtifact(0x1010, (block,))
    assert owner._prefix_call_sites_8616(artifact, 0x1014) == frozenset({0x1010})


def test_prefix_selection_refuses_unbound_or_ambiguous_callsite() -> None:
    """No unique owner block means no exact selection exists."""
    call = IRInstr("CALL", None, (), addr=0x1010)
    ambiguous = IRFunctionArtifact(
        0x1000, (IRBlock(0x1000, ()), IRBlock(0x1010, (call,)), IRBlock(0x1020, (call,)))
    )
    assert not owner._prefix_call_sites_8616(ambiguous, 0x1010)
    unbound = IRFunctionArtifact(0x1000, (IRBlock(0x1000, (call,)),))
    assert not owner._prefix_call_sites_8616(unbound, 0x1999)


@pytest.mark.parametrize("retry_boot", [False, True])
def test_registered_retry_collects_only_its_cfg_prefix(
    monkeypatch: pytest.MonkeyPatch, retry_boot: bool,
) -> None:
    """A caller-prefix retry must not recursively resolve its own or later CALL."""
    from types import SimpleNamespace

    project = SimpleNamespace()
    early = IRInstr("CALL", None, (), addr=0x1010)
    target = IRInstr("CALL", None, (), addr=0x1014)
    late = IRInstr("CALL", None, (), addr=0x1018)
    artifact = IRFunctionArtifact(0x1010, (IRBlock(0x1010, (early, target, late)),))
    boundary = SimpleNamespace(project=project, addr=artifact.function_addr)
    source = SimpleNamespace(callsite_index=SimpleNamespace(for_target=lambda _head: (object(),)))
    resolution = owner._PremiseResolution8616()
    selected: list[frozenset[int] | None] = []

    def collect_no_proof(*_args: object, selected_callsites: frozenset[int] | None = None, **_kwargs: object) -> tuple:
        """Observe selection while granting no evidence for any call."""
        selected.append(selected_callsites)
        return ()

    monkeypatch.setattr(owner, "collect_entry_domain_call_preservations_8616", collect_no_proof)
    monkeypatch.setattr(owner, "_boot_retry_invocation_premise_8616", lambda *_args: None)
    monkeypatch.setattr(owner, "_retry_registered_parent_edges_8616", lambda *_args: None)
    assert owner._retry_registered_invocation_premise_8616(
        project, artifact.function_addr, target.addr, artifact, boundary, None,
        source, resolution, retry_boot=retry_boot,
    ) is None
    assert selected == [frozenset({early.addr})]
