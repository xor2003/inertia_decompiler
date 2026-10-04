"""Layer: test support.
Responsibility: own replay capture emission fixture contracts and evidence.
"""
from __future__ import annotations

import random
from typing import Any

from replay_capture_contracts_test_support import CaptureWindow, DeclaredExtent
from replay_capture_fixture_test_support import (
    F32_CALLEE,
    F32_DATA,
    F32_ESP,
    F32_SENTINEL,
    F32_SPIN,
    FUZZ_COUNT,
    R16_ARRAY,
    R16_CALLEE,
    R16_LOAD,
    R16_OUT,
    R16_SENTINEL,
    R16_SP,
    R16_SPIN,
    R16_SS,
    SEED,
)
from replay_capture_manifest_test_support import (
    VectorKind,
    _capture_record,
    _capture_refusal,
    _f32_vector,
    _f32_window_patches,
    _r16_vector,
    _r16_window_patches,
)
from replay_capture_setup_test_support import F32_CAPTURE_WINDOWS, R16_CAPTURE_WINDOWS
from replay_capture_windows_test_support import flat32_window_check, real16_window_check

from tools.dosunit.flat32_replay_model import (
    Flat32CaptureResult,
)
from tools.dosunit.real16_replay_model import (
    Real16CaptureResult,
)
from tools.dosunit.replay_capture_model import CaptureStatus


def emit_real16(
    capture: Real16CaptureResult,
    extents: tuple[DeclaredExtent, ...],
    rng: random.Random,
    *,
    windows: tuple[CaptureWindow, ...] = R16_CAPTURE_WINDOWS,
    stack_segment: int = R16_SS,
    declared_sp: int | None = R16_SP,
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    """Emit the real16 cohort: runtime, edge and deterministic-fuzz vectors."""
    vectors: list[dict[str, Any]] = []
    provenance: dict[str, dict[str, Any]] = {}
    base_segs = {"ds": R16_LOAD, "es": R16_LOAD, "ss": R16_SS, "fs": 0, "gs": 0}
    base_regs = {"ax": 0, "bx": 0, "cx": 0, "dx": 0, "si": 0, "di": 0, "bp": 0,
                 "sp": R16_SP, "flags": 0x0002}

    if capture.status is CaptureStatus.CAPTURED:
        check = real16_window_check(
            capture, extents, windows,
            stack_segment=stack_segment, declared_sp=declared_sp, stack_only=True,
        )
        if check.refusal is None:
            regs = dict(capture.registers)
            low = {name: regs[name] for name in ("ax", "bx", "cx", "dx", "si", "di", "bp", "sp", "flags")}
            highs = {name: regs[name] >> 16 for name in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")}
            highs["eflags"] = regs["eflags"] >> 16
            segs = {name: regs[name] for name in ("ds", "es", "ss", "fs", "gs")}
            patches, replaced = _r16_window_patches(check, regs["ss"])
            vector = _r16_vector(
                "r16-rt-00", entry_off=R16_CALLEE, regs=low, segs=segs,
                memory=patches, high_halves=highs,
                observations=[{"segment": f"{regs['ds']:#06x}", "offset": f"{R16_OUT:#06x}", "size": 2}],
            )
            vectors.append(vector)
            provenance[vector["id"]] = {
                "kind": VectorKind.RUNTIME.value,
                "capture": _capture_record(
                    capture.boundary.linear(), capture.status.value,
                    capture.execution_status.value if capture.execution_status is not None else None,
                    capture.instructions, capture.detail, capture.fetch_trace,
                    capture.trap_linear, check, replaced,
                    "executed caller prefix under the real16 Unicorn backend "
                    "through replay's shared guarded capture loop",
                ),
            }
        else:
            provenance["r16-rt-00"] = {
                "kind": VectorKind.RUNTIME.value,
                "refusal": _capture_refusal(
                    capture.status.value,
                    capture.execution_status.value if capture.execution_status is not None else None,
                    capture.instructions, capture.detail, capture.fetch_trace, check,
                ),
            }
    else:
        provenance["r16-rt-00"] = {
            "kind": VectorKind.RUNTIME.value,
            "refusal": _capture_refusal(
                capture.status.value,
                capture.execution_status.value if capture.execution_status is not None else None,
                capture.instructions, capture.detail, capture.fetch_trace,
            ),
        }

    def edge(vector_id: str, *, entry_off: int = R16_CALLEE, regs: dict[str, int],
             segs: dict[str, int] | None = None,
             memory: list[dict[str, Any]] | None = None,
             observations: list[dict[str, Any]] | None = None) -> None:
        vectors.append(_r16_vector(vector_id, entry_off=entry_off,
                                   regs={**base_regs, **regs}, segs={**base_segs, **(segs or {})},
                                   memory=memory or [], observations=observations))
        provenance[vector_id] = {"kind": VectorKind.EDGE.value}

    edge("r16-edge-alias", regs={"bx": 0x0300, "cx": 4},
         segs={"ds": 0x0FF0},
         observations=[{"segment": "0x0ff0", "offset": f"{R16_OUT:#06x}", "size": 2}])
    provenance["r16-edge-alias"]["rationale"] = "DS:BX 0x0ff0:0x0300 aliases the image array at linear 0x10200"
    edge("r16-edge-miniter", regs={"bx": R16_ARRAY, "cx": 1})
    edge("r16-edge-cpuid", regs={"bx": R16_ARRAY, "cx": 4, "dx": R16_SENTINEL})
    edge("r16-edge-loopwrap", regs={"bx": R16_ARRAY, "cx": 0})
    edge("r16-edge-budget", entry_off=R16_SPIN, regs={})

    for index in range(FUZZ_COUNT):
        vector_id = f"r16-fuzz-{index:02d}"
        array = bytes(rng.randrange(256) for _ in range(8))
        regs = {"bx": R16_ARRAY, "cx": rng.randint(1, 6), "dx": rng.randint(0, 0xFF),
                "si": rng.randrange(0x10000), "di": rng.randrange(0x10000),
                "bp": rng.randrange(0x10000)}
        memory = [{"segment": f"{R16_LOAD:#06x}", "offset": f"{R16_ARRAY:#06x}", "bytes": array.hex()}]
        vectors.append(_r16_vector(vector_id, entry_off=R16_CALLEE,
                                   regs={**base_regs, **regs}, segs=dict(base_segs), memory=memory))
        provenance[vector_id] = {"kind": VectorKind.FUZZ.value, "seed": SEED, "index": index}
    return vectors, provenance


def emit_flat32(
    capture: Flat32CaptureResult,
    extents: tuple[DeclaredExtent, ...],
    rng: random.Random,
    *,
    windows: tuple[CaptureWindow, ...] = F32_CAPTURE_WINDOWS,
    declared_esp: int | None = F32_ESP,
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    """Emit the flat32 cohort in the public `replay-flat32` vector format."""
    vectors: list[dict[str, Any]] = []
    provenance: dict[str, dict[str, Any]] = {}
    base_regs = {"eax": 0, "ebx": 0, "ecx": 0, "edx": 0, "esi": 0, "edi": 0,
                 "ebp": 0, "esp": F32_ESP, "eflags": 0x2}

    if capture.status is CaptureStatus.CAPTURED:
        check = flat32_window_check(capture, extents, windows, declared_esp=declared_esp)
        if check.refusal is None:
            regs = dict(capture.registers)
            inputs = {name: regs[name] for name in
                      ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eflags")}
            patches, replaced, mappings = _f32_window_patches(check)
            vector = _f32_vector("f32-rt-00", entry=F32_CALLEE, regs=inputs,
                                 memory=patches, mappings=mappings)
            vectors.append(vector)
            provenance[vector["id"]] = {
                "kind": VectorKind.RUNTIME.value,
                "capture": _capture_record(
                    capture.boundary, capture.status.value,
                    capture.execution_status.value if capture.execution_status is not None else None,
                    capture.instructions, capture.detail, capture.fetch_trace,
                    capture.trap, check, replaced,
                    "executed caller prefix under the flat32 Unicorn backend "
                    "through replay's shared guarded capture loop",
                ),
            }
        else:
            provenance["f32-rt-00"] = {
                "kind": VectorKind.RUNTIME.value,
                "refusal": _capture_refusal(
                    capture.status.value,
                    capture.execution_status.value if capture.execution_status is not None else None,
                    capture.instructions, capture.detail, capture.fetch_trace, check,
                ),
            }
    else:
        provenance["f32-rt-00"] = {
            "kind": VectorKind.RUNTIME.value,
            "refusal": _capture_refusal(
                capture.status.value,
                capture.execution_status.value if capture.execution_status is not None else None,
                capture.instructions, capture.detail, capture.fetch_trace,
            ),
        }

    def edge(vector_id: str, *, entry: int = F32_CALLEE, regs: dict[str, int],
             memory: list[dict[str, Any]] | None = None,
             observations: list[dict[str, Any]] | None = None) -> None:
        vectors.append(_f32_vector(vector_id, entry=entry, regs={**base_regs, **regs},
                                   memory=memory, observations=observations))
        provenance[vector_id] = {"kind": VectorKind.EDGE.value}

    edge("f32-edge-miniter", regs={"ebx": F32_DATA, "ecx": 1})
    edge("f32-edge-cpuid", regs={"ebx": F32_DATA, "ecx": 4, "edx": F32_SENTINEL})
    edge("f32-edge-budget", entry=F32_SPIN, regs={})
    edge("f32-edge-unmapped-obs", regs={"ebx": F32_DATA, "ecx": 1},
         observations=[{"address": "0x800000", "size": 4}])
    provenance["f32-edge-unmapped-obs"]["rationale"] = (
        "declared observation on a page with no FILE/VECTOR coverage stays a typed UNMAPPED non-result"
    )

    for index in range(FUZZ_COUNT):
        vector_id = f"f32-fuzz-{index:02d}"
        array = b"".join(rng.randrange(0x10000).to_bytes(4, "little") for _ in range(4))
        regs = {"ebx": F32_DATA, "ecx": rng.randint(1, 6), "edx": rng.randint(0, 0xFF),
                "esi": rng.randrange(0x10000), "edi": rng.randrange(0x10000),
                "ebp": rng.randrange(0x10000)}
        memory = [{"address": f"{F32_DATA:#x}", "bytes": array.hex()}]
        vectors.append(_f32_vector(vector_id, entry=F32_CALLEE,
                                   regs={**base_regs, **regs}, memory=memory))
        provenance[vector_id] = {"kind": VectorKind.FUZZ.value, "seed": SEED, "index": index}
    return vectors, provenance
