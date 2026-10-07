"""Collect optional rizin function discovery candidates for CLI orchestration.

Layer: CLI/fallback/reporting.
Responsibility: collect optional rizin function seeds without making them semantic proof.
"""

from __future__ import annotations

import contextlib
import json
import shutil
import subprocess
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from .cache import _load_cache_json, _recovery_cache_key, _store_cache_json
from .cache_source_manifest import RecoveryCacheSourceScope8616

_RIZIN_FUNCTION_ANALYSIS_COMMAND = "aa;aflj"
_RIZIN_DISCOVERY_POLICY_SCHEMA = 4
_DOS_MZ_LOAD_BASE = 0x10000

__all__ = [
    "RizinDiscoveryResult",
    "RizinDiscoveryStatus",
    "discover_function_offsets_with_rizin",
    "discover_rizin_function_entries",
]


class RizinDiscoveryStatus(Enum):
    """Typed outcomes for optional rizin discovery."""

    OK = "ok"
    UNAVAILABLE = "unavailable"
    TIMEOUT = "timeout"
    ERROR = "error"
    EMPTY = "empty"


@dataclass(frozen=True)
class RizinDiscoveryResult:
    """Rizin function-seed discovery result."""

    status: RizinDiscoveryStatus
    offsets: tuple[int, ...]
    elapsed_ms: float
    detail: str = ""


def _rizin_available() -> bool:
    return shutil.which("rizin") is not None


def _json_int(value: object, default: int = 0) -> int:
    """Return an integer from a JSON scalar, or a fallback for non-scalars."""
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int | float | str):
        try:
            return int(value)
        except (TypeError, ValueError):
            return default
    return default


def _score_aflj_entry(entry: dict[str, object]) -> tuple[int, int]:
    name = str(entry.get("name", "") or "")
    size = _json_int(entry.get("size"))
    nbbs = _json_int(entry.get("nbbs"))
    ncallrefs = _json_int(entry.get("ncallrefs"))
    imported_penalty = 1000 if name.startswith("sym.imp.") else 0
    score = (ncallrefs * 10) + (nbbs * 4) + min(size, 512) - imported_penalty
    offset = _json_int(entry.get("offset"))
    return score, -offset


def _rizin_offset_to_inertia_addr(binary_path: Path, offset: int) -> int:
    """Translate a Rizin load-module offset into Inertia's DOS MZ address space.

    Rizin's MZ backend reports ``aflj`` offsets relative to the DOS load module,
    while :class:`DOSMZ` maps that module at ``0x10000``.  Non-MZ offsets are
    already addresses in their loader's coordinate space and remain unchanged.
    """
    try:
        is_mz = binary_path.read_bytes()[:2] == b"MZ"
    except OSError:
        return offset
    return _DOS_MZ_LOAD_BASE + offset if is_mz else offset


def _cache_key(binary_path: Path, *, timeout_sec: int, max_count: int | None) -> dict[str, object] | None:
    key = _recovery_cache_key(
        binary_path=binary_path,
        kind="rizin_aflj_function_seeds",
        source_scope=RecoveryCacheSourceScope8616.FUNCTION_DISCOVERY,
        extra={
            "policy_schema": _RIZIN_DISCOVERY_POLICY_SCHEMA,
            "timeout_sec": timeout_sec,
            "max_count": max_count or 0,
        },
    )
    return key if isinstance(key, dict) else None


def _run_rizin_json(binary_path: Path, command: str, *, timeout_sec: int) -> object:
    """Return decoded optional rizin JSON, or None when the probe cannot complete."""
    cmd = ["rizin", "-2", "-q", "-c", command, str(binary_path)]
    try:
        completed = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
            timeout=max(1, int(timeout_sec)),
        )
    except subprocess.TimeoutExpired:
        return None
    if completed.returncode != 0:
        return None
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError:
        return None


def _mz_executable_segments(segments: list[object]) -> list[tuple[int, int, int]]:
    """Return executable (paddr, vaddr, vsize) triples from a rizin segment map."""
    executable_segments: list[tuple[int, int, int]] = []
    for seg in segments:
        if not isinstance(seg, dict):
            continue
        paddr = int(seg.get("paddr", 0) or 0)
        vaddr = int(seg.get("vaddr", 0) or 0)
        vsize = int(seg.get("vsize", 0) or 0)
        perm = str(seg.get("perm", ""))
        if paddr <= 0 or vaddr < 0:
            continue
        if not perm.startswith("-rwx") and "x" not in perm:
            continue
        executable_segments.append((paddr, vaddr, max(0, vsize)))
    return executable_segments


def _mz_scan_base(
    segments: list[object],
    executable_segments: list[tuple[int, int, int]],
) -> tuple[int, int] | None:
    """Choose the physical/virtual base used for linear prologue mapping."""
    if not executable_segments:
        # Fallback: keep prior behavior for binaries with sparse rizin segment metadata.
        chosen = None
        for seg in segments:
            if not isinstance(seg, dict):
                continue
            paddr = int(seg.get("paddr", 0) or 0)
            vaddr = int(seg.get("vaddr", 0) or 0)
            if paddr > 0 and vaddr >= 0 and (chosen is None or paddr < int(chosen.get("paddr", 0) or 0)):
                chosen = {"paddr": paddr, "vaddr": vaddr}
        if chosen is None:
            return None
        return int(chosen["paddr"]), int(chosen["vaddr"])
    # Prefer largest executable segment with known code size, otherwise first encountered.
    exec_vsize, pbase, vbase = max(
        ((vsize, paddr, vaddr) for paddr, vaddr, vsize in executable_segments),
        key=lambda item: (item[0], item[1]),
    )
    if exec_vsize <= 0:
        pbase = executable_segments[0][0]
        vbase = executable_segments[0][1]
    return pbase, vbase


def _mz_prologue_candidates(data: bytes, pbase: int, vbase: int) -> list[int]:
    """Scan raw bytes for standard x16 frame prologues mapped to load addresses."""
    patterns = (b"\x55\x8b\xec", b"\x55\x89\xe5")
    candidates: list[int] = []
    for pat in patterns:
        start = 0
        while True:
            idx = data.find(pat, start)
            if idx < 0:
                break
            start = idx + 1
            if idx < pbase:
                continue
            vaddr = vbase + (idx - pbase)
            if vaddr < 0:
                continue
            # angr DOS MZ loader base is 0x10000 in this pipeline.
            candidates.append(0x10000 + vaddr)
    return candidates


def _mz_entrypoint_probe(binary_path: Path) -> int | None:
    """Probe rizin for the executable entrypoint as one extra candidate."""
    try:
        entry_raw = subprocess.run(
            ["rizin", "-2", "-q", "-c", "ieq", str(binary_path)],
            check=False,
            capture_output=True,
            text=True,
            timeout=2,
        )
    except subprocess.TimeoutExpired:
        return None
    if entry_raw.returncode != 0:
        return None
    entry_text = entry_raw.stdout.strip()
    if not entry_text.startswith("0x"):
        return None
    with contextlib.suppress(ValueError):
        return 0x10000 + int(entry_text, 16)
    return None


def _mz_linear_candidates_from_prologues(binary_path: Path) -> tuple[list[int], str]:
    """Collect MZ prologue candidates even when optional entrypoint probing times out."""
    data = binary_path.read_bytes()
    segments = _run_rizin_json(binary_path, "iSj", timeout_sec=3)
    if not isinstance(segments, list):
        return [], "no_segment_map"
    executable_segments = _mz_executable_segments(segments)
    base = _mz_scan_base(segments, executable_segments)
    if base is None:
        return [], "no_mappable_segment"
    pbase, vbase = base
    candidates = _mz_prologue_candidates(data, pbase, vbase)
    entry_candidate = _mz_entrypoint_probe(binary_path)
    if entry_candidate is not None:
        candidates.append(entry_candidate)
    dedup: set[int] = set()
    ordered: list[int] = []
    for addr in sorted(candidates):
        if addr in dedup:
            continue
        dedup.add(addr)
        ordered.append(addr)
    return ordered, "mz_prologue_fallback"


def _cached_discovery_result(key: str, started: float) -> RizinDiscoveryResult | None:
    """Return a persisted discovery result for one cache key when present."""
    cached = _load_cache_json("recovery", key)
    if not isinstance(cached, dict):
        return None
    cached_status_raw = str(cached.get("status", "") or "").strip().lower()
    cached_detail = str(cached.get("detail", "") or "")
    offsets_raw = cached.get("offsets")
    cached_offsets: tuple[int, ...]
    cached_offsets = tuple(_json_int(x) for x in offsets_raw) if isinstance(offsets_raw, list) else ()
    if not cached_status_raw:
        return None
    for status in RizinDiscoveryStatus:
        if status.value == cached_status_raw:
            return RizinDiscoveryResult(
                status,
                cached_offsets,
                (time.perf_counter() - started) * 1000.0,
                f"cache_hit:{cached_detail or cached_status_raw}",
            )
    return None


def _cached_error_result(key: str | None, started: float, detail: str) -> RizinDiscoveryResult:
    """Build, persist, and return one ERROR discovery result."""
    error_result = RizinDiscoveryResult(
        RizinDiscoveryStatus.ERROR,
        (),
        (time.perf_counter() - started) * 1000.0,
        detail,
    )
    if key is not None:
        _store_cache_json(
            "recovery", key, {"status": error_result.status.value, "offsets": [], "detail": error_result.detail}
        )
    return error_result


def _empty_result(key: str | None, started: float, detail: str) -> RizinDiscoveryResult:
    """Build, persist, and return one EMPTY discovery result."""
    empty_result = RizinDiscoveryResult(
        RizinDiscoveryStatus.EMPTY,
        (),
        (time.perf_counter() - started) * 1000.0,
        detail,
    )
    if key is not None:
        _store_cache_json(
            "recovery", key, {"status": empty_result.status.value, "offsets": [], "detail": empty_result.detail}
        )
    return empty_result


def _call_target_candidates(binary_path: Path, timeout_sec: int) -> list[dict[str, object]]:
    """Collect direct CALL xref targets as extra function-entry seeds."""
    xrefs_payload = _run_rizin_json(binary_path, "aa;axlj", timeout_sec=timeout_sec)
    candidates: list[dict[str, object]] = []
    if isinstance(xrefs_payload, list):
        for item in xrefs_payload:
            if not isinstance(item, dict):
                continue
            if str(item.get("type", "")).strip().upper() != "CALL":
                continue
            target = _json_int(item.get("to"), default=-1)
            if target < 0:
                continue
            candidates.append(
                {
                    "offset": target,
                    "name": "rizin.call_target",
                    "size": 0,
                    "nbbs": 0,
                    "ncallrefs": 0,
                }
            )
    return candidates


def _mz_fallback_result(
    key: str | None, started: float, binary_path: Path
) -> RizinDiscoveryResult:
    """Return a linear MZ prologue result when rizin found no candidates."""
    mz_fallback, fallback_detail = _mz_linear_candidates_from_prologues(binary_path)
    if not mz_fallback:
        return _empty_result(key, started, "no function entries")
    if key is not None:
        _store_cache_json(
            "recovery",
            key,
            {
                "status": RizinDiscoveryStatus.OK.value,
                "offsets": mz_fallback,
                "detail": fallback_detail,
                "engine": "rizin",
            },
        )
    return RizinDiscoveryResult(
        RizinDiscoveryStatus.OK,
        tuple(mz_fallback),
        (time.perf_counter() - started) * 1000.0,
        fallback_detail,
    )


def _run_function_analysis(
    binary_path: Path, key: str | None, started: float, timeout_sec: int
) -> tuple[subprocess.CompletedProcess[str] | None, RizinDiscoveryResult | None]:
    """Run rizin's conservative analysis; return (process, early_result)."""
    cmd = ["rizin", "-2", "-q", "-c", _RIZIN_FUNCTION_ANALYSIS_COMMAND, str(binary_path)]
    try:
        completed = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
            timeout=max(1, int(timeout_sec)),
        )
    except subprocess.TimeoutExpired:
        timeout_result = RizinDiscoveryResult(
            RizinDiscoveryStatus.TIMEOUT,
            (),
            (time.perf_counter() - started) * 1000.0,
            "subprocess timeout",
        )
        if key is not None:
            _store_cache_json(
                "recovery", key, {"status": timeout_result.status.value, "offsets": [], "detail": timeout_result.detail}
            )
        return None, timeout_result
    except Exception as ex:
        return None, _cached_error_result(key, started, str(ex))
    if completed.returncode != 0:
        return None, _cached_error_result(key, started, f"exit={completed.returncode}")
    return completed, None


def _normalize_candidate_offsets(
    candidates: list[dict[str, object]], binary_path: Path
) -> list[int]:
    """Map candidate offsets to Inertia addresses, sorted and deduplicated."""
    ordered = sorted(candidates, key=_score_aflj_entry, reverse=True)
    dedup: set[int] = set()
    offsets: list[int] = []
    for item in ordered:
        raw_offset = _json_int(item.get("offset"))
        if raw_offset < 0:
            continue
        offset = _rizin_offset_to_inertia_addr(binary_path, raw_offset)
        if offset <= 0 or offset in dedup:
            continue
        dedup.add(offset)
        offsets.append(offset)
    return offsets


def discover_rizin_function_entries(binary_path: Path, *, timeout_sec: int = 8) -> RizinDiscoveryResult:
    """Discover candidate function entry offsets with rizin."""
    started = time.perf_counter()
    if not _rizin_available():
        return RizinDiscoveryResult(RizinDiscoveryStatus.UNAVAILABLE, (), 0.0, "rizin not found")
    key = _cache_key(binary_path, timeout_sec=timeout_sec, max_count=None)
    if key is not None:
        cached_result = _cached_discovery_result(key, started)
        if cached_result is not None:
            return cached_result
    # Rizin's aggressive ``aaa`` analysis is not segment-safe for DOS MZ files:
    # a 16-bit offset from one segment can be followed into another segment's
    # data at the same numeric address.  Keep Rizin's conservative entry/xref
    # analysis as optional seed evidence and let Inertia build the real CFG.
    completed, early = _run_function_analysis(binary_path, key, started, timeout_sec)
    if early is not None:
        return early
    try:
        payload = json.loads(completed.stdout)
    except Exception:
        return _cached_error_result(key, started, "invalid JSON")
    if not isinstance(payload, list):
        return _cached_error_result(key, started, "aflj payload is not a list")
    candidates: list[dict[str, object]] = [item for item in payload if isinstance(item, dict)]
    # Rizin may merge a large 16-bit segmented call graph into one function even
    # though its xref engine still identifies the direct CALL destinations.  A
    # direct call target is a stronger function-entry seed than the resulting
    # oversized ``aflj`` container, so retain both sources for Inertia.
    candidates.extend(_call_target_candidates(binary_path, timeout_sec))
    if not candidates:
        return _mz_fallback_result(key, started, binary_path)
    offsets = _normalize_candidate_offsets(candidates, binary_path)
    if not offsets:
        return _empty_result(key, started, "no valid offsets")
    if key is not None:
        _store_cache_json(
            "recovery",
            key,
            {"status": RizinDiscoveryStatus.OK.value, "offsets": offsets, "detail": "ok", "engine": "rizin"},
        )
    return RizinDiscoveryResult(
        RizinDiscoveryStatus.OK,
        tuple(offsets),
        (time.perf_counter() - started) * 1000.0,
        "ok",
    )


def discover_function_offsets_with_rizin(
    binary_path: Path,
    *,
    max_count: int | None = None,
) -> tuple[list[int], str]:
    """Return optional rizin function offsets and a status/detail label."""
    result = discover_rizin_function_entries(binary_path, timeout_sec=8)
    if result.status is not RizinDiscoveryStatus.OK:
        return [], result.status.value
    offsets = list(result.offsets)
    if max_count:
        offsets = offsets[:max_count]
    return offsets, result.detail or "ok"
