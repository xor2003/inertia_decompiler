from __future__ import annotations  # noqa: D100

from pathlib import Path
from typing import Any

from tools.dosunit.discovery import function_for_linear
from tools.dosunit.model import DosUnitError, load_json, normalize_hex, stable_id


def _int_from_hex_key(value: object) -> int | None:
    if not isinstance(value, str):
        return None
    try:
        return int(value, 0)
    except ValueError:
        return None


def _module_relative(linear: int, loadseg: int | None) -> str | None:
    if loadseg is None:
        return None
    base = loadseg << 4
    if linear < base:
        return None
    return normalize_hex(linear - base)


def _load_optional_json(path: Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    value = load_json(path)
    if not isinstance(value, dict):
        raise DosUnitError(f"{path} must contain a JSON object")
    return value


def import_libdosbox_trace(  # noqa: D103
    *,
    trace_path: Path,
    functions_path: Path | None = None,
    dump_path: Path | None = None,
    meta_path: Path | None = None,
) -> dict[str, Any]:
    trace = _load_optional_json(trace_path)
    if trace is None:
        raise DosUnitError("trace is required")
    catalog = _load_optional_json(functions_path)
    dump_meta = _load_optional_json(meta_path)

    meta = trace.get("Meta", {}) if isinstance(trace.get("Meta", {}), dict) else {}
    loadseg_raw = meta.get("DosboxLoadSeg")
    loadseg = int(loadseg_raw) if isinstance(loadseg_raw, int) else None

    priorities = _code_priorities(trace, catalog, loadseg)
    access_ranges = _access_ranges(trace, loadseg)
    seeds = _seed_vectors(trace)

    refusals: list[dict[str, Any]] = []
    if not seeds:
        refusals.append(
            {
                "status": "refused",
                "reason": "oracle_unavailable",
                "detail": {
                    "message": "runtime JSON is aggregate-only; per-call snapshots are required for direct replay vectors"
                },
            }
        )

    document_without_id = {
        "schema": "dosunit.libdosbox_import.v1",
        "trace": str(trace_path),
        "dump": None if dump_path is None else str(dump_path),
        "meta": meta,
        "dump_meta": dump_meta,
        "priorities": priorities,
        "access_ranges": access_ranges,
        "seed_vectors": seeds,
        "refusals": refusals,
    }
    document = dict(document_without_id)
    document["id"] = stable_id("libdosbox-import", document_without_id)
    return document


def _code_priorities(
    trace: dict[str, Any],
    catalog: dict[str, Any] | None,
    loadseg: int | None,
) -> list[dict[str, Any]]:
    """Collect sorted execution priorities from the trace Code inventory."""
    priorities: list[dict[str, Any]] = []
    code = trace.get("Code", {})
    if isinstance(code, dict):
        for addr_text, info in code.items():
            linear = _int_from_hex_key(addr_text)
            if linear is None or not isinstance(info, dict):
                continue
            function = function_for_linear(catalog, linear) if catalog is not None else None
            priorities.append(
                {
                    "linear": normalize_hex(linear),
                    "module_offset": _module_relative(linear, loadseg),
                    "exec_count": int(info.get("ExecCount", 0) or 0),
                    "function_id": None if function is None else function.get("id"),
                    "sources": ["libdosbox_runtime_json"],
                    "segments": {key: info.get(key, []) for key in ("cs", "ds", "es", "ss", "fs", "gs") if key in info},
                    "accessed_data": info.get("Accdat", []),
                }
            )
    priorities.sort(key=lambda item: (-int(item.get("exec_count", 0)), str(item.get("linear", ""))))
    return priorities


def _access_ranges(trace: dict[str, Any], loadseg: int | None) -> list[dict[str, Any]]:
    """Collect normalized data-access ranges from the trace AccessSites."""
    access_ranges: list[dict[str, Any]] = []
    access_sites = trace.get("AccessSites", {})
    if not isinstance(access_sites, dict):
        return access_ranges
    for site in access_sites.values():
        if not isinstance(site, dict):
            continue
        min_addr = _int_from_hex_key(site.get("MinAddr"))
        max_addr = _int_from_hex_key(site.get("MaxAddr"))
        csip = _int_from_hex_key(site.get("Csip"))
        if min_addr is None or max_addr is None:
            continue
        access_ranges.append(
            {
                "csip": None if csip is None else normalize_hex(csip),
                "min_linear": normalize_hex(min_addr),
                "max_linear": normalize_hex(max_addr),
                "module_min": _module_relative(min_addr, loadseg),
                "module_max": _module_relative(max_addr, loadseg),
                "count": int(site.get("Count", 0) or 0),
                "rw_mask": int(site.get("RwMask", 0) or 0),
                "size_mask": int(site.get("SizeMask", 0) or 0),
                "value_classes": site.get("ValueClasses", []),
                "samples": site.get("Samples", []),
            }
        )
    return access_ranges


def _seed_vectors(trace: dict[str, Any]) -> list[dict[str, Any]]:
    """Convert per-call snapshots into replay vectors."""
    seeds: list[dict[str, Any]] = []
    snapshots = trace.get("CallSnapshots", [])
    if not isinstance(snapshots, list):
        return seeds
    for idx, snapshot in enumerate(snapshots):
        if not isinstance(snapshot, dict):
            continue
        vector = _snapshot_to_vector(snapshot, idx=idx)
        if vector is not None:
            seeds.append(vector)
    return seeds




def _snapshot_to_vector(snapshot: dict[str, Any], *, idx: int) -> dict[str, Any] | None:
    entry = snapshot.get("entry")
    exit_state = snapshot.get("exit")
    function = snapshot.get("function")
    if not isinstance(entry, dict) or not isinstance(exit_state, dict) or not isinstance(function, dict):
        return None
    module = str(snapshot.get("module", "unknown.exe")).lower()
    regs = entry.get("regs", {}) if isinstance(entry.get("regs"), dict) else {}
    sregs = entry.get("sregs", {}) if isinstance(entry.get("sregs"), dict) else {}
    flags = entry.get("flags")
    if flags is not None:
        regs = dict(regs)
        regs["flags"] = flags
    vector = {
        "schema": "dosunit.vector.v1",
        "module": module,
        "function": {
            "name": function.get("name", f"snapshot_{idx}"),
            "entry": {
                "cs": function.get("cs", "auto"),
                "ip": function.get("ip", "0x0000"),
                "kind": function.get("kind", "near"),
            },
        },
        "source": {
            "kind": "libdosbox",
            "origin": "per_call_snapshot",
            "assumptions": [],
        },
        "pre": {
            "regs": regs,
            "sregs": sregs,
            "memory": entry.get("memory", []) if isinstance(entry.get("memory", []), list) else [],
        },
        "observe": {
            "regs": sorted(exit_state.get("regs", {}).keys()) if isinstance(exit_state.get("regs"), dict) else [],
            "sregs": sorted(exit_state.get("sregs", {}).keys()) if isinstance(exit_state.get("sregs"), dict) else [],
            "flags_mask": exit_state.get("flags_mask", "0xffff"),
            "memory": exit_state.get("memory_writes", [])
            if isinstance(exit_state.get("memory_writes", []), list)
            else [],
            "calls": True,
            "return": True,
        },
        "expected": {
            "status": "trapped",
            "regs": exit_state.get("regs", {}),
            "sregs": exit_state.get("sregs", {}),
            "flags": {"value": exit_state.get("flags", "0x0000"), "mask": exit_state.get("flags_mask", "0xffff")},
            "memory": exit_state.get("memory_writes", []),
            "return": exit_state.get("return", {}),
            "calls": exit_state.get("calls", []),
        },
    }
    from tools.dosunit.model import normalize_vector

    return normalize_vector(vector)
