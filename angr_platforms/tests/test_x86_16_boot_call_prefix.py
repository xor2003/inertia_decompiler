"""Native boot-prefix call evidence and post-return stack-state controls."""

from __future__ import annotations

import io
from dataclasses import replace
from functools import partial

import angr
import pytest
from angr_platforms.X86_16.analysis_helpers import (
    resolve_direct_call_target_from_instruction_8616,
)
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.frontend_direct_callsite_index import (
    build_boundary_direct_callsite_index_8616,
)
from angr_platforms.X86_16.frontend_function_boundary import (
    exact_function_range_boundary_8616,
)
from angr_platforms.X86_16.ir import entry_domain_call_preservation as edcp
from angr_platforms.X86_16.ir import real16_invocation_domain as domain
from angr_platforms.X86_16.ir import vex_import as vi
from angr_platforms.X86_16.ir.function_ir_registry import (
    publish_function_ir_artifact_8616,
)
from angr_platforms.X86_16.ir.ir_boundary_cfg import (
    prove_ir_boundary_coverage_8616,
)

from tools.dosunit.real16_program_boot import (
    ProgramBoot,
    ProgramEnvironment,
    program_from_mz_bytes,
)
from tools.dosunit.real16_replay_model import LinearRange

LOAD_SEGMENT = 0x100
PSP_SEGMENT = LOAD_SEGMENT - 0x10
BASE = LOAD_SEGMENT << 4

STUB = BASE + 0x00
HELPER_A = BASE + 0x100
HELPER_B = BASE + 0x110
MAIN = BASE + 0x120
LEAF_C = BASE + 0x130
CALLSITE = STUB + 0x06

HELPER_A_CODE = bytes.fromhex("b8 34 12 c3")
HELPER_B_CODE = bytes.fromhex("b8 78 56 c3")
LEAF_C_CODE = b"\xc3"
MAIN_CODE = (
    b"\xe8"
    + ((LEAF_C - (MAIN + 3)) & 0xFFFF).to_bytes(2, "little")
    + b"\xc3"
)
STUB_CODE = (
    b"\xe8" + ((HELPER_A - (STUB + 3)) & 0xFFFF).to_bytes(2, "little")
    + b"\xe8" + ((HELPER_B - (STUB + 6)) & 0xFFFF).to_bytes(2, "little")
    + b"\xe8" + ((MAIN - (STUB + 9)) & 0xFFFF).to_bytes(2, "little")
    + b"\xc3"
)

CODE_RANGES = (
    LinearRange(STUB, len(STUB_CODE)),
    LinearRange(HELPER_A, len(HELPER_A_CODE)),
    LinearRange(HELPER_B, len(HELPER_B_CODE)),
    LinearRange(MAIN, len(MAIN_CODE)),
    LinearRange(LEAF_C, len(LEAF_C_CODE)),
)


def _build_image(helper_b: bytes = HELPER_B_CODE) -> bytes:
    image = b""
    cursor = BASE
    for address, code in (
        (STUB, STUB_CODE),
        (HELPER_A, HELPER_A_CODE),
        (HELPER_B, helper_b),
        (MAIN, MAIN_CODE),
        (LEAF_C, LEAF_C_CODE),
    ):
        image += bytes(address - cursor) + code
        cursor = address + len(code)
    return image


def _build_mz(image: bytes) -> bytes:
    header_size = 32
    exe_size = header_size + len(image)
    header = bytearray(header_size)
    header[0:2] = b"MZ"
    header[0x02:0x04] = (exe_size % 512).to_bytes(2, "little")
    header[0x04:0x06] = ((exe_size + 511) // 512).to_bytes(2, "little")
    header[0x06:0x08] = (1).to_bytes(2, "little")
    header[0x08:0x0A] = (2).to_bytes(2, "little")
    header[0x0A:0x0C] = (0x10).to_bytes(2, "little")
    header[0x0C:0x0E] = (0x20).to_bytes(2, "little")
    header[0x0E:0x10] = (0x10).to_bytes(2, "little")
    header[0x10:0x12] = (0x100).to_bytes(2, "little")
    header[0x14:0x16] = (0).to_bytes(2, "little")
    header[0x16:0x18] = (0).to_bytes(2, "little")
    header[0x18:0x1A] = (0x1C).to_bytes(2, "little")
    header[0x1C:0x1E] = (0x20).to_bytes(2, "little")
    return bytes(header) + image


def _recompute(boot: object) -> object:
    assert isinstance(boot, ProgramBoot)
    return program_from_mz_bytes(
        boot.source, boot.environment, code_ranges=boot.image.code_ranges
    )


def _resolver(project: object) -> object:
    return partial(resolve_direct_call_target_from_instruction_8616, project)


def _build_world(helper_b: bytes = HELPER_B_CODE) -> dict:
    ranges = tuple(LinearRange(r.address, len(helper_b)) if r.address == HELPER_B else r for r in CODE_RANGES)
    mz = _build_mz(_build_image(helper_b))
    boot = program_from_mz_bytes(
        mz,
        ProgramEnvironment(
            psp_segment=PSP_SEGMENT,
            allocation=bytes(0x400),
            registers=tuple(
                (name, 0)
                for name in (
                    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp",
                    "esp", "eflags",
                )
            ),
            fs=0,
            gs=0,
        ),
        code_ranges=ranges,
    )
    assert boot.entry.linear() == STUB
    project = angr.Project(
        io.BytesIO(boot.image.chunks[0][1]),
        main_opts={
            "backend": "blob", "arch": Arch86_16(),
            "base_addr": BASE, "entry_point": BASE,
        },
        auto_load_libs=False,
    )
    project._inertia_caller_function_ranges_8616 = tuple(
        (r.address, r.address + r.size) for r in ranges
    )
    boundaries = {}
    artifacts = {}
    coverages = {}
    for rng in ranges:
        head = rng.address
        boundary = exact_function_range_boundary_8616(
            project, head, head + rng.size
        )
        assert boundary is not None
        artifact = vi.build_x86_16_ir_function_artifact(project, boundary)
        publish_function_ir_artifact_8616(project, artifact)
        coverages[head] = prove_ir_boundary_coverage_8616(
            project, boundary, artifact
        )
        boundaries[head] = boundary
        artifacts[head] = artifact
    stub_index = build_boundary_direct_callsite_index_8616(
        boundaries[STUB], direct_target_resolver=_resolver(project)
    )
    return {
        "boot": boot, "project": project, "boundaries": boundaries,
        "artifacts": artifacts, "coverages": coverages,
        "stub_index": stub_index,
    }


@pytest.fixture(scope="module")
def world() -> dict:
    return _build_world()


def _records(world: dict, edcp: object) -> tuple:
    return edcp.collect_entry_domain_call_preservations_8616(
        world["project"],
        world["artifacts"][STUB],
        world["boundaries"][STUB],
        direct_target_resolver=_resolver(world["project"]),
    )


def _install(world: dict, edcp: object) -> None:
    edcp.install_real16_invocation_source_8616(
        world["project"],
        edcp.Real16InvocationSource8616(
            boot=world["boot"],
            boot_recompute=_recompute,
            callsite_index=world["stub_index"],
        ),
    )


def test_boot_propagates_entry_records(world: dict) -> None:
    records = _records(world, edcp)
    assert all(record.complete for record in records)
    premise = domain.prove_real16_invocation_domain_8616(
        world["project"],
        world["coverages"][STUB],
        CALLSITE,
        boot=world["boot"],
        boot_recompute=_recompute,
        entry_call_preservations=records,
    )
    assert premise.complete and premise.failure is None
    assert premise.kind is domain.Real16InvocationKind8616.BOOT_ENTRY_PATH
    assert premise.raw_fact_count == premise.materialized_count
    assert premise.failure_count == 0
    assert dict(premise.callsite_call_state)["sp"] == 0xFE


def test_registered_premise_retries_boot(world: dict) -> None:
    _install(world, edcp)
    try:
        session = edcp._PremiseResolution8616()
        premise = edcp._registered_invocation_premise_8616(
            world["project"],
            STUB,
            CALLSITE,
            edcp._real16_invocation_source_8616(world["project"]),
            session,
        )
    finally:
        edcp.install_real16_invocation_source_8616(world["project"], None)
    assert premise is not None
    assert premise.complete and premise.failure is None


def test_refusals(world: dict) -> None:
    records = _records(world, edcp)
    args = (
        world["project"],
        world["coverages"][STUB],
        CALLSITE,
    )
    kwargs = {"boot": world["boot"], "boot_recompute": _recompute}
    boundary = domain.Real16InvocationFailure8616.CALL_BOUNDARY_UNPROVEN

    empty = domain.prove_real16_invocation_domain_8616(
        *args, entry_call_preservations=(), **kwargs
    )
    assert empty.failure is boundary

    omitted = domain.prove_real16_invocation_domain_8616(
        *args, entry_call_preservations=records[:1], **kwargs
    )
    assert omitted.failure is boundary

    forged_callsite = replace(records[1], callsite_addr=STUB + 0x40)
    forged_target = replace(records[1], target_addr=HELPER_A)
    for forged in (forged_callsite, forged_target):
        pool = (records[0], forged, records[2])
        premise = domain.prove_real16_invocation_domain_8616(
            *args, entry_call_preservations=pool, **kwargs
        )
        assert not premise.complete and premise.failure is not None


def test_cycle_guard(world: dict) -> None:
    _install(world, edcp)
    try:
        session = edcp._PremiseResolution8616()
        session.in_flight = {STUB}
        premise = edcp._registered_invocation_premise_8616(
            world["project"],
            STUB,
            CALLSITE,
            edcp._real16_invocation_source_8616(world["project"]),
            session,
        )
    finally:
        edcp.install_real16_invocation_source_8616(world["project"], None)
    assert premise is None


def test_lazy_direct_success(world: dict) -> None:
    _install(world, edcp)
    collected = []
    real_collect = edcp._surface_call_preservations_8616

    def counting(*args, **kwargs):
        collected.append(1)
        return real_collect(*args, **kwargs)

    edcp._surface_call_preservations_8616 = counting
    try:
        session = edcp._PremiseResolution8616()
        premise = edcp._registered_invocation_premise_8616(
            world["project"],
            STUB,
            STUB,
            edcp._real16_invocation_source_8616(world["project"]),
            session,
        )
    finally:
        edcp._surface_call_preservations_8616 = real_collect
        edcp.install_real16_invocation_source_8616(world["project"], None)
    assert premise is not None and premise.complete
    assert collected == []


@pytest.mark.parametrize("code,expected_sp", [("c3", 0xFE), ("c20200", 0x100), ("85c07403c20200c3", None)])
def test_return_state_uses_native_cleanup(code: str, expected_sp: int | None) -> None:
    """Carry actual RET cleanup; disagreeing returns cannot invent an SP."""
    world = _build_world(bytes.fromhex(code))
    premise = domain.prove_real16_invocation_domain_8616(
        world["project"], world["coverages"][STUB], CALLSITE,
        boot=world["boot"], boot_recompute=_recompute,
        entry_call_preservations=_records(world, edcp),
    )
    if expected_sp is None:
        assert not premise.complete and premise.failure is not None
    else:
        assert premise.complete and premise.failure is None
        assert dict(premise.callsite_call_state)["sp"] == expected_sp


def test_changed_callee_bytes_invalidate_retained_pool() -> None:
    """A previously complete record cannot authorize mutated native RET bytes."""
    world = _build_world()
    records = _records(world, edcp)
    assert all(record.complete for record in records)
    world["project"].loader.memory.store(HELPER_B + len(HELPER_B_CODE) - 1, b"\x90")
    premise = domain.prove_real16_invocation_domain_8616(
        world["project"], world["coverages"][STUB], CALLSITE,
        boot=world["boot"], boot_recompute=_recompute,
        entry_call_preservations=records,
    )
    assert not premise.complete and premise.failure is not None
