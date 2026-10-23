"""Native prefix proof must not demand the called application or its suffix."""
import io

import angr
import pytest

from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.frontend.x86_16.frontend_direct_callsite_index import build_boundary_direct_callsite_index_8616
from inertia.frontend.x86_16.frontend_function_boundary import exact_function_range_boundary_8616
from inertia.ir import entry_domain_call_preservation as owner
from inertia.ir.real16_invocation_domain import real16_native_census_import_8616
from inertia.lowering.analysis_helpers import resolve_direct_call_target_from_instruction_8616
from tests.ir.test_x86_16_boot_entry_link import _mz, _recompute
from tools.dosunit.runtime.real16_program_boot import ProgramEnvironment, program_from_mz_bytes
from tools.dosunit.runtime.real16_replay_model import LinearRange

pytestmark = pytest.mark.decompiler


def _world(monkeypatch, *, suffix_call=False):
    """The prior helper lies after the target call in address order, before it in CFG order."""
    image = bytearray(b"\x90" * 0x81)
    image[:2] = bytes.fromhex("eb1e")
    image[0x10:0x14] = bytes.fromhex("e86d00 c3")
    image[0x20:0x25] = bytes.fromhex("e81d00 ebeb")
    image[0x40] = image[0x80] = 0xc3
    if suffix_call:
        # An unmodeled callee after the target call cannot justify an entry premise.
        image[0x13:0x17] = bytes.fromhex("e8ea0f c3")
    environment = ProgramEnvironment(
        psp_segment=0xf0, allocation=bytes(0x300),
        registers=tuple((name, 0) for name in (
            "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eflags",
        )), fs=0, gs=0,
    )
    boot = program_from_mz_bytes(
        _mz(bytes(image)), environment,
        code_ranges=(LinearRange(0x1000, 0x25), LinearRange(0x1040, 1), LinearRange(0x1080, 1)),
    )
    arch = Arch86_16()
    arch.bits = 32
    project = angr.Project(
        io.BytesIO(boot.image.chunks[0][1]),
        main_opts={"backend": "blob", "arch": arch, "base_addr": 0x1000, "entry_point": 0x1000},
        auto_load_libs=False,
    )
    boundary = exact_function_range_boundary_8616(project, 0x1000, 0x1025)
    assert boundary is not None
    raw = real16_native_census_import_8616(project, boundary)
    assert raw is not None and any(block.refusals for block in raw.blocks)
    index = build_boundary_direct_callsite_index_8616(
        boundary, direct_target_resolver=lambda instruction:
        resolve_direct_call_target_from_instruction_8616(project, instruction),
    )
    source = owner.Real16InvocationSource8616(boot, _recompute, index)
    owner.install_real16_invocation_source_8616(project, source)
    original_boundary = owner._exact_boundary_for_8616
    monkeypatch.setattr(
        owner, "_exact_boundary_for_8616",
        lambda current, head: boundary if current is project and head == 0x1000
        else original_boundary(current, head),
    )
    return project, source


@pytest.mark.parametrize("suffix_call", [False, True])
def test_raw_boot_prefix_uses_only_prior_cfg_calls(monkeypatch, suffix_call):
    project, source = _world(monkeypatch, suffix_call=suffix_call)
    sites = []
    original = owner.prove_entry_domain_call_preservation_8616

    def observe(*args, **kwargs):
        sites.append(args[4].addr)
        return original(*args, **kwargs)

    monkeypatch.setattr(owner, "prove_entry_domain_call_preservation_8616", observe)
    premise = owner._registered_invocation_premise_8616(
        project, 0x1000, 0x1010, source, owner._PremiseResolution8616(),
    )
    assert premise is not None and premise.complete
    assert set(sites) == {0x1020}
    project.loader.memory.store(0x1040, b"\x90")
    assert not premise.complete


def test_raw_boot_prefix_rejects_missing_call_records(monkeypatch):
    project, source = _world(monkeypatch)
    monkeypatch.setattr(owner, "collect_entry_domain_call_preservations_8616", lambda *args, **kwargs: ())
    premise = owner._registered_invocation_premise_8616(
        project, 0x1000, 0x1010, source, owner._PremiseResolution8616(),
    )
    assert premise is None


def test_inflight_boot_can_prove_independent_earlier_prefix(monkeypatch):
    """An earlier call needs no effect evidence from the later in-flight call."""
    project, source = _world(monkeypatch)
    resolution = owner._PremiseResolution8616(in_flight=frozenset({0x1000}))
    monkeypatch.setattr(
        owner, "collect_entry_domain_call_preservations_8616",
        lambda *args, **kwargs: pytest.fail("reentrant boot prefix must stay record-free"),
    )
    premise = owner._registered_invocation_premise_8616(project, 0x1000, 0x1020, source, resolution)
    assert premise is not None and premise.complete
    assert resolution.in_flight == frozenset({0x1000})


def test_inflight_boot_cannot_assume_its_own_call_effects(monkeypatch):
    project, source = _world(monkeypatch)
    resolution = owner._PremiseResolution8616(in_flight=frozenset({0x1000}))
    monkeypatch.setattr(
        owner, "collect_entry_domain_call_preservations_8616",
        lambda *args, **kwargs: pytest.fail("reentrant boot prefix must stay record-free"),
    )
    assert owner._registered_invocation_premise_8616(project, 0x1000, 0x1010, source, resolution) is None


@pytest.mark.parametrize("limit", ["deadline", "remaining", "depth"])
def test_reentrant_boot_respects_existing_request_limits(monkeypatch, limit):
    project, source = _world(monkeypatch)
    resolution = owner._PremiseResolution8616(in_flight=frozenset({0x1000}))
    if limit == "deadline":
        resolution.deadline = -1.0
    elif limit == "remaining":
        resolution.remaining = 0
    else:
        resolution.in_flight = frozenset(0x1000 + index for index in range(owner._ENTRY_PREMISE_MAX_DEPTH_8616))
    monkeypatch.setattr(
        owner, "_raw_boot_invocation_premise_8616",
        lambda *args, **kwargs: pytest.fail("exhausted request must not start raw intake"),
    )
    assert owner._registered_invocation_premise_8616(project, 0x1000, 0x1020, source, resolution) is None


def test_unbound_symbolic_target_does_not_start_callee_proof(monkeypatch):
    """Resolve the caller's target before traversing a potentially circular callee."""
    from tests.ir.test_call_collection_staging import (
        _call_entry,
        _collect,
        _install_world,
        _selector_binding,
        _symbolic_artifact,
    )

    artifact = _symbolic_artifact((0x10000,))
    entries = (_call_entry(0x10000, 0x11003),)
    project, boundary = _install_world(
        monkeypatch, artifact, entries,
        lambda project, *, block, instruction, coordinates, invocation=None:
        _selector_binding(coordinates.callsite_addr),
    )
    monkeypatch.setattr(owner, "_caller_invocation_premise_8616", lambda *args: None)
    monkeypatch.setattr(
        owner, "_callee_closure_8616",
        lambda *args, **kwargs: pytest.fail("unbound target must not enter callee proof"),
    )
    records = _collect(project, artifact, boundary)
    assert len(records) == 1 and records[0].failure is not None
    assert not records[0].complete
