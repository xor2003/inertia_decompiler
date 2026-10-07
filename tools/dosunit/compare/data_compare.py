from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from tools.dosunit.contracts.model import DosUnitError, normalize_hex, parse_int, stable_id


@dataclass(frozen=True)
class LoadedMzImage:  # noqa: D101
    memory: bytes
    image_size: int
    load_base_para: int
    relocs: tuple[tuple[int, int], ...]


@dataclass(frozen=True)
class DataRange:  # noqa: D101
    oracle_segment: str
    candidate_segment: str
    start: int
    end: int


@dataclass(frozen=True)
class CodePointerNormalization:  # noqa: D101
    oracle_segment: str
    oracle_offset: int
    candidate_segment: str
    candidate_offset: int
    symbol: str


def compare_loaded_data_images(  # noqa: D103
    *,
    oracle_exe: Path,
    candidate_exe: Path,
    oracle_catalog: dict[str, Any],
    candidate_catalog: dict[str, Any],
    ranges: list[str],
    code_pointer_normalizations: list[str] | None = None,
    oracle_load_base_para: int = 0,
    candidate_load_base_para: int = 0,
    max_mismatches: int = 32,
) -> dict[str, Any]:
    parsed_ranges = [_parse_range_spec(item) for item in ranges]
    parsed_normalizations = [_parse_code_pointer_spec(item) for item in code_pointer_normalizations or []]
    oracle_min_size, candidate_min_size = _required_sizes(
        oracle_catalog=oracle_catalog,
        candidate_catalog=candidate_catalog,
        ranges=parsed_ranges,
        normalizations=parsed_normalizations,
    )
    oracle_image = load_mz_image(oracle_exe, load_base_para=oracle_load_base_para, min_size=oracle_min_size)
    candidate_image = load_mz_image(candidate_exe, load_base_para=candidate_load_base_para, min_size=candidate_min_size)

    normalization_results = _evaluate_code_pointer_normalizations(
        normalizations=parsed_normalizations,
        oracle_catalog=oracle_catalog,
        candidate_catalog=candidate_catalog,
        oracle_image=oracle_image,
        candidate_image=candidate_image,
    )
    skip_pairs = _normalization_skip_pairs(parsed_normalizations)
    range_results = _compare_ranges(
        ranges=parsed_ranges,
        oracle_catalog=oracle_catalog,
        candidate_catalog=candidate_catalog,
        oracle_image=oracle_image,
        candidate_image=candidate_image,
        skip_pairs=skip_pairs,
        max_mismatches=max_mismatches,
    )

    literal_mismatches = sum(int(result["mismatch_count"]) for result in range_results)
    normalization_failures = sum(1 for result in normalization_results if result["status"] != "passed")
    status = "passed" if literal_mismatches == 0 and normalization_failures == 0 else "failed"
    document_without_id = {
        "schema": "dosunit.data_compare.v1",
        "status": status,
        "oracle_exe": str(oracle_exe),
        "candidate_exe": str(candidate_exe),
        "oracle_load_base": normalize_hex(oracle_load_base_para, width=4),
        "candidate_load_base": normalize_hex(candidate_load_base_para, width=4),
        "ranges": range_results,
        "normalizations": normalization_results,
        "summary": {
            "ranges": len(range_results),
            "literal_mismatches": literal_mismatches,
            "normalization_failures": normalization_failures,
            "normalized_fields": len(normalization_results),
        },
    }
    document = dict(document_without_id)
    document["id"] = stable_id("data-compare", document_without_id)
    return document


def load_mz_image(path: Path, *, load_base_para: int = 0, min_size: int = 0) -> LoadedMzImage:  # noqa: D103
    data = path.read_bytes()
    if len(data) < 0x1C or data[:2] not in {b"MZ", b"ZM"}:
        raise DosUnitError(f"data comparison currently requires a DOS MZ .exe: {path}")
    lastsize = int.from_bytes(data[0x02:0x04], "little")
    nblocks = int.from_bytes(data[0x04:0x06], "little") & 0x7FF
    nreloc = int.from_bytes(data[0x06:0x08], "little")
    hdr_paras = int.from_bytes(data[0x08:0x0A], "little")
    minalloc = int.from_bytes(data[0x0A:0x0C], "little")
    reloc_pos = int.from_bytes(data[0x18:0x1A], "little")
    exe_size = ((nblocks - 1) << 9) + lastsize if lastsize else nblocks << 9
    header_size = hdr_paras << 4
    if exe_size <= header_size or exe_size > len(data):
        raise DosUnitError(f"bad MZ image/header size in {path}")
    image = data[header_size:exe_size]
    memory_size = max(len(image) + (minalloc << 4), len(image), min_size)
    memory = bytearray(memory_size)
    memory[: len(image)] = image
    relocs: list[tuple[int, int]] = []
    for idx in range(nreloc):
        at = reloc_pos + idx * 4
        if at + 4 > len(data):
            raise DosUnitError(f"truncated MZ relocation table in {path}")
        off = int.from_bytes(data[at : at + 2], "little")
        seg = int.from_bytes(data[at + 2 : at + 4], "little")
        linear = (seg << 4) + off
        if linear + 2 > len(memory):
            raise DosUnitError(f"relocation outside loaded image: {seg:04x}:{off:04x}")
        current = int.from_bytes(memory[linear : linear + 2], "little")
        memory[linear : linear + 2] = ((current + load_base_para) & 0xFFFF).to_bytes(2, "little")
        relocs.append((off, seg))
    return LoadedMzImage(
        memory=bytes(memory), image_size=len(image), load_base_para=load_base_para, relocs=tuple(relocs)
    )


def _parse_range_spec(spec: str) -> DataRange:
    left, body = _split_optional_mapping(spec, field="range")
    oracle_segment = left
    candidate_segment, range_text = _split_segment_body(body, field="range")
    if ".." in range_text:
        start_text, end_text = range_text.split("..", 1)
        start = parse_int(start_text, field="range.start")
        end = parse_int(end_text, field="range.end")
    else:
        start_text, size_text = range_text.split(":", 1)
        start = parse_int(start_text, field="range.start")
        end = start + parse_int(size_text, field="range.size")
    if end < start:
        raise DosUnitError(f"range end is before start: {spec}")
    return DataRange(oracle_segment=oracle_segment, candidate_segment=candidate_segment, start=start, end=end)


def _parse_code_pointer_spec(spec: str) -> CodePointerNormalization:
    if "=" in spec:
        left, body = _split_optional_mapping(spec, field="code pointer normalization")
        oracle_segment, oracle_offset_text = _split_location(left, field="code pointer normalization")
    else:
        raw_parts = spec.split(":")
        if len(raw_parts) < 3:
            raise DosUnitError(f"code pointer normalization must be SEG:OFFSET:SYMBOL: {spec}")
        oracle_segment = raw_parts[0]
        oracle_offset_text = raw_parts[1]
        body = spec
    parts = body.split(":")
    if len(parts) < 3:
        raise DosUnitError(f"code pointer normalization must be SEG:OFFSET:SYMBOL: {spec}")
    candidate_segment = parts[0]
    candidate_offset = parse_int(parts[1], field="code pointer normalization.candidate_offset")
    symbol = ":".join(parts[2:])
    if not symbol:
        raise DosUnitError(f"code pointer normalization symbol is empty: {spec}")
    return CodePointerNormalization(
        oracle_segment=oracle_segment,
        oracle_offset=parse_int(oracle_offset_text, field="code pointer normalization.oracle_offset"),
        candidate_segment=candidate_segment,
        candidate_offset=candidate_offset,
        symbol=symbol,
    )


def _split_optional_mapping(spec: str, *, field: str) -> tuple[str, str]:
    if "=" in spec:
        left, right = spec.split("=", 1)
        if not left or not right:
            raise DosUnitError(f"{field} mapping is incomplete: {spec}")
        return left, right
    segment, _body = _split_segment_body(spec, field=field)
    return segment, spec


def _split_segment_body(spec: str, *, field: str) -> tuple[str, str]:
    if ":" not in spec:
        raise DosUnitError(f"{field} must include a segment and offset/range: {spec}")
    segment, body = spec.split(":", 1)
    if not segment or not body:
        raise DosUnitError(f"{field} is incomplete: {spec}")
    return segment, body


def _split_location(spec: str, *, field: str) -> tuple[str, str]:
    segment, body = _split_segment_body(spec, field=field)
    if ":" in body or ".." in body:
        raise DosUnitError(f"{field} location must be SEG:OFFSET: {spec}")
    return segment, body


def _required_sizes(
    *,
    oracle_catalog: dict[str, Any],
    candidate_catalog: dict[str, Any],
    ranges: list[DataRange],
    normalizations: list[CodePointerNormalization],
) -> tuple[int, int]:
    oracle_size = 0
    candidate_size = 0
    for item in ranges:
        oracle_size = max(oracle_size, _segment_linear_end(oracle_catalog, item.oracle_segment, item.end))
        candidate_size = max(candidate_size, _segment_linear_end(candidate_catalog, item.candidate_segment, item.end))
    for item in normalizations:
        oracle_size = max(oracle_size, _segment_linear_end(oracle_catalog, item.oracle_segment, item.oracle_offset + 2))
        candidate_size = max(
            candidate_size, _segment_linear_end(candidate_catalog, item.candidate_segment, item.candidate_offset + 2)
        )
    return oracle_size, candidate_size


def _segment_linear_end(catalog: dict[str, Any], segment: str, end_offset: int) -> int:
    return (_segment_para(catalog, segment) << 4) + end_offset


def _segment_linear(catalog: dict[str, Any], segment: str, offset: int) -> int:
    return (_segment_para(catalog, segment) << 4) + offset


def _segment_para(catalog: dict[str, Any], segment_name: str) -> int:
    try:
        return parse_int(segment_name, field=f"segment {segment_name}")
    except DosUnitError:
        pass
    wanted = segment_name.upper()
    for segment in catalog.get("segments", []) or []:
        if not isinstance(segment, dict):
            continue
        if str(segment.get("name", "")).upper() == wanted and "paragraph" in segment:
            return parse_int(segment["paragraph"], field=f"segment {segment_name}.paragraph")
    raise DosUnitError(f"segment is not present in catalog: {segment_name}")


def _evaluate_code_pointer_normalizations(
    *,
    normalizations: list[CodePointerNormalization],
    oracle_catalog: dict[str, Any],
    candidate_catalog: dict[str, Any],
    oracle_image: LoadedMzImage,
    candidate_image: LoadedMzImage,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for item in normalizations:
        oracle_value = _read_u16(
            oracle_image.memory, _segment_linear(oracle_catalog, item.oracle_segment, item.oracle_offset)
        )
        candidate_value = _read_u16(
            candidate_image.memory, _segment_linear(candidate_catalog, item.candidate_segment, item.candidate_offset)
        )
        oracle_symbol = _function_by_name(oracle_catalog, item.symbol)
        candidate_symbol = _function_by_name(candidate_catalog, item.symbol)
        oracle_expected = _function_offset(oracle_symbol)
        candidate_expected = _function_offset(candidate_symbol)
        status = "passed" if oracle_value == oracle_expected and candidate_value == candidate_expected else "failed"
        results.append(
            {
                "status": status,
                "kind": "near_code_pointer",
                "symbol": item.symbol,
                "oracle_location": _location_dict(item.oracle_segment, item.oracle_offset),
                "candidate_location": _location_dict(item.candidate_segment, item.candidate_offset),
                "oracle_value": normalize_hex(oracle_value, width=4),
                "oracle_expected": normalize_hex(oracle_expected, width=4),
                "candidate_value": normalize_hex(candidate_value, width=4),
                "candidate_expected": normalize_hex(candidate_expected, width=4),
            }
        )
    return results


def _compare_ranges(
    *,
    ranges: list[DataRange],
    oracle_catalog: dict[str, Any],
    candidate_catalog: dict[str, Any],
    oracle_image: LoadedMzImage,
    candidate_image: LoadedMzImage,
    skip_pairs: set[tuple[str, int, str, int]],
    max_mismatches: int,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for item in ranges:
        oracle_base = _segment_para(oracle_catalog, item.oracle_segment) << 4
        candidate_base = _segment_para(candidate_catalog, item.candidate_segment) << 4
        mismatches: list[dict[str, Any]] = []
        mismatch_count = 0
        compared = 0
        normalized = 0
        for offset in range(item.start, item.end):
            pair = (item.oracle_segment.upper(), offset, item.candidate_segment.upper(), offset)
            if pair in skip_pairs:
                normalized += 1
                continue
            compared += 1
            oracle_byte = oracle_image.memory[oracle_base + offset]
            candidate_byte = candidate_image.memory[candidate_base + offset]
            if oracle_byte == candidate_byte:
                continue
            mismatch_count += 1
            if len(mismatches) < max_mismatches:
                mismatches.append(
                    {
                        "offset": normalize_hex(offset, width=4),
                        "oracle": normalize_hex(oracle_byte, width=2),
                        "candidate": normalize_hex(candidate_byte, width=2),
                    }
                )
        results.append(
            {
                "status": "passed" if mismatch_count == 0 else "failed",
                "oracle_segment": item.oracle_segment,
                "candidate_segment": item.candidate_segment,
                "start": normalize_hex(item.start, width=4),
                "end": normalize_hex(item.end, width=4),
                "compared_bytes": compared,
                "normalized_bytes": normalized,
                "mismatch_count": mismatch_count,
                "mismatches": mismatches,
            }
        )
    return results


def _normalization_skip_pairs(normalizations: list[CodePointerNormalization]) -> set[tuple[str, int, str, int]]:
    pairs: set[tuple[str, int, str, int]] = set()
    for item in normalizations:
        for delta in range(2):
            pairs.add(
                (
                    item.oracle_segment.upper(),
                    item.oracle_offset + delta,
                    item.candidate_segment.upper(),
                    item.candidate_offset + delta,
                )
            )
    return pairs


def _function_by_name(catalog: dict[str, Any], symbol: str) -> dict[str, Any]:
    for function in catalog.get("functions", []) or []:
        if not isinstance(function, dict):
            continue
        names = {str(name) for name in function.get("names", []) or []}
        if symbol in names:
            return function
    candidates = _symbol_aliases(symbol)
    candidates.discard(symbol)
    for function in catalog.get("functions", []) or []:
        if not isinstance(function, dict):
            continue
        names = {str(name) for name in function.get("names", []) or []}
        if names & candidates:
            return function
    raise DosUnitError(f"code pointer target symbol is not present in catalog: {symbol}")


def _symbol_aliases(symbol: str) -> set[str]:
    aliases = {symbol}
    if symbol.startswith("__"):
        aliases.add(symbol[1:])
        aliases.add(symbol.lstrip("_"))
    elif symbol.startswith("_"):
        aliases.add(symbol[1:])
    else:
        aliases.add(f"_{symbol}")
        aliases.add(f"__{symbol}")
    return aliases


def _function_offset(function: dict[str, Any]) -> int:
    entry = function.get("entry", {})
    if not isinstance(entry, dict):
        raise DosUnitError("code pointer target has no entry object")
    return parse_int(entry.get("offset"), field="function.entry.offset") & 0xFFFF


def _read_u16(memory: bytes, linear: int) -> int:
    if linear < 0 or linear + 2 > len(memory):
        raise DosUnitError("u16 read is outside loaded image")
    return int.from_bytes(memory[linear : linear + 2], "little")


def _location_dict(segment: str, offset: int) -> dict[str, str]:
    return {"segment": segment, "offset": normalize_hex(offset, width=4)}
