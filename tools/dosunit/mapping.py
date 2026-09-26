from __future__ import annotations  # noqa: D100

import copy
from dataclasses import dataclass
from typing import Any

from tools.dosunit.model import DosUnitError, normalize_hex, parse_int, stable_id


@dataclass(frozen=True)
class MappingResolutionError(DosUnitError):  # noqa: D101
    reason: str
    message: str

    def __str__(self) -> str:  # noqa: D105
        return self.message


def apply_candidate_mapping(  # noqa: D103
    vector: dict[str, Any],
    *,
    mapping_document: dict[str, Any] | None,
    functions_catalog: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if mapping_document is None:
        return copy.deepcopy(vector)
    if mapping_document.get("schema") != "dosunit.mapping.v1":
        raise MappingResolutionError("mapping_missing", "mapping document schema must be dosunit.mapping.v1")

    function = vector.get("function", {})
    if not isinstance(function, dict):
        raise MappingResolutionError("mapping_missing", "vector.function must be an object")
    oracle_id = function.get("id")
    oracle_name = function.get("name")
    candidates: list[dict[str, Any]] = []
    for item in mapping_document.get("functions", []) or []:
        if not isinstance(item, dict):
            continue
        if oracle_id is not None and item.get("oracle_id") == oracle_id:
            candidates.append(item)
            continue
        if oracle_name is not None and item.get("oracle_name") == oracle_name:
            candidates.append(item)

    if not candidates:
        raise MappingResolutionError(
            "mapping_missing",
            f"no candidate mapping for {oracle_id or oracle_name or '<unnamed function>'}",
        )
    if len(candidates) > 1:
        raise MappingResolutionError(
            "mapping_ambiguous",
            f"multiple candidate mappings for {oracle_id or oracle_name or '<unnamed function>'}",
        )

    selected = candidates[0]
    candidate_entry = selected.get("candidate_entry")
    if not isinstance(candidate_entry, dict):
        raise MappingResolutionError("mapping_missing", "mapping entry has no candidate_entry object")

    mapped = copy.deepcopy(vector)
    mapped_function = mapped.setdefault("function", {})
    if not isinstance(mapped_function, dict):
        mapped["function"] = mapped_function = {}
    mapped_function["id"] = selected.get("candidate_id", mapped_function.get("id"))
    mapped_function["name"] = selected.get("candidate_name", mapped_function.get("name", mapped_function.get("id")))
    mapped_function["entry"] = _resolve_candidate_entry(
        candidate_entry,
        functions_catalog=functions_catalog,
        fallback_kind=str(function.get("entry", {}).get("kind", "near"))
        if isinstance(function.get("entry"), dict)
        else "near",
    )
    if "candidate_module" in mapping_document:
        mapped["module"] = mapping_document["candidate_module"]
    return mapped


def _resolve_candidate_entry(
    entry: dict[str, Any],
    *,
    functions_catalog: dict[str, Any] | None,
    fallback_kind: str,
) -> dict[str, str]:
    raw_cs = entry.get("cs", entry.get("segment_para"))
    if raw_cs is None and "segment" in entry:
        raw_cs = _segment_para_for_name(functions_catalog, str(entry["segment"]))
    if raw_cs is None:
        raise MappingResolutionError("mapping_missing", "candidate_entry needs cs, segment_para, or resolvable segment")
    raw_ip = entry.get("ip", entry.get("offset"))
    if raw_ip is None:
        raise MappingResolutionError("mapping_missing", "candidate_entry needs ip or offset")
    return {
        "cs": normalize_hex(raw_cs, width=4, field="candidate_entry.cs"),
        "ip": normalize_hex(raw_ip, width=4, field="candidate_entry.ip"),
        "kind": str(entry.get("kind", fallback_kind)).lower(),
    }


def _segment_para_for_name(functions_catalog: dict[str, Any] | None, name: str) -> int | None:
    if not isinstance(functions_catalog, dict):
        return None
    for segment in functions_catalog.get("segments", []) or []:
        if not isinstance(segment, dict):
            continue
        if segment.get("name") == name and "paragraph" in segment:
            return parse_int(segment["paragraph"], field=f"segment {name}.paragraph")
    return None


def _name_match_key(name: str) -> str:
    """Whitespace-insensitive key for joining linker-map symbol names."""
    return "".join(str(name).split())


def make_mapping_document(  # noqa: D103
    *,
    oracle_catalog: dict[str, Any],
    candidate_catalog: dict[str, Any],
    mode: str = "name",
) -> dict[str, Any]:
    if mode != "name":
        raise DosUnitError(f"unsupported mapping mode: {mode}")
    candidates_by_name: dict[str, list[dict[str, Any]]] = {}
    for function in candidate_catalog.get("functions", []) or []:
        if not isinstance(function, dict):
            continue
        for name in function.get("names", []) or []:
            candidates_by_name.setdefault(_name_match_key(name), []).append(function)

    functions: list[dict[str, Any]] = []
    diagnostics: list[dict[str, Any]] = []
    for oracle_function in oracle_catalog.get("functions", []) or []:
        if not isinstance(oracle_function, dict):
            continue
        names = [str(name) for name in oracle_function.get("names", []) or []]
        name = names[0] if names else None
        if name is None:
            diagnostics.append(
                {
                    "reason": "mapping_missing",
                    "oracle_id": oracle_function.get("id"),
                    "message": "oracle function has no name",
                }
            )
            continue
        candidates: list[dict[str, Any]] = []
        matched_name = name
        for candidate_name in names:
            candidates = candidates_by_name.get(_name_match_key(candidate_name), [])
            if candidates:
                matched_name = candidate_name
                break
        if not candidates:
            diagnostics.append(
                {"reason": "mapping_missing", "oracle_id": oracle_function.get("id"), "oracle_name": name}
            )
            continue
        if len(candidates) > 1:
            diagnostics.append(
                {"reason": "mapping_ambiguous", "oracle_id": oracle_function.get("id"), "oracle_name": name}
            )
            continue
        candidate = candidates[0]
        candidate_entry = _entry_for_mapping(
            candidate, return_kind=str(oracle_function.get("return_kind", candidate.get("return_kind", "near")))
        )
        if candidate_entry is None:
            diagnostics.append(
                {
                    "reason": "mapping_missing",
                    "oracle_id": oracle_function.get("id"),
                    "oracle_name": name,
                    "message": "candidate entry has no concrete segment",
                }
            )
            continue
        candidate_names = [str(item) for item in candidate.get("names", []) or []]
        sources = ["name_match"]
        if matched_name != name:
            sources.append("name_alias")
        functions.append(
            {
                "oracle_id": oracle_function.get("id"),
                "oracle_name": name,
                "candidate_id": candidate.get("id"),
                "candidate_name": candidate_names[0] if candidate_names else matched_name,
                "matched_name": matched_name,
                "candidate_entry": candidate_entry,
                "sources": sources,
            }
        )

    document_without_id = {
        "schema": "dosunit.mapping.v1",
        "oracle_module": oracle_catalog.get("module"),
        "candidate_module": candidate_catalog.get("module"),
        "mode": mode,
        "functions": functions,
        "diagnostics": diagnostics,
        "summary": {
            "oracle_functions": len(oracle_catalog.get("functions", []) or []),
            "candidate_functions": len(candidate_catalog.get("functions", []) or []),
            "mapped": len(functions),
            "diagnostics": len(diagnostics),
        },
    }
    document = dict(document_without_id)
    document["id"] = stable_id("mapping", document_without_id)
    return document


def _entry_for_mapping(function: dict[str, Any], *, return_kind: str) -> dict[str, str] | None:
    entry = function.get("entry", {})
    if not isinstance(entry, dict):
        return None
    cs = entry.get("segment_para")
    if cs is None:
        return None
    return {
        "cs": normalize_hex(cs, width=4, field="candidate.entry.segment_para"),
        "ip": normalize_hex(entry.get("offset", "0x0000"), width=4, field="candidate.entry.offset"),
        "kind": return_kind.lower(),
    }
