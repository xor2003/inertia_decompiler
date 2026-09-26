from __future__ import annotations  # noqa: D100

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from tools.dosunit.model import DosUnitError, normalize_hex, stable_id

_MZRE_SEGMENT_RE = re.compile(r"^([A-Za-z_]\w*)\s+(CODE|DATA|STACK)\s+([0-9A-Fa-f]+)$", re.IGNORECASE)
_MZRE_ROUTINE_RE = re.compile(
    r"^([A-Za-z_]\w*):\s+([A-Za-z_]\w*)\s+(NEAR|FAR)\s+([0-9A-Fa-f]+)-([0-9A-Fa-f]+)",
    re.IGNORECASE,
)
_IDA_SEGMENT_RE = re.compile(
    r"^(?P<seg>[A-Za-z_]\w*):(?P<off>[0-9A-Fa-f]{4,5})\s+"
    r"(?P<name>[A-Za-z_]\w*)\s+segment\b.*'(?P<class>[A-Za-z_]\w*)'",
    re.IGNORECASE,
)
_IDA_PROC_RE = re.compile(
    r"^(?P<seg>[A-Za-z_]\w*):(?P<off>[0-9A-Fa-f]{4,5})\s+"
    r"(?P<name>[A-Za-z_$?@][\w$?@]*)\s+proc\s+(?P<kind>near|far)\b",
    re.IGNORECASE,
)
_IDA_ENDP_RE = re.compile(
    r"^(?P<seg>[A-Za-z_]\w*):(?P<off>[0-9A-Fa-f]{4,5})\s+"
    r"(?P<name>[A-Za-z_$?@][\w$?@]*)\s+endp\b",
    re.IGNORECASE,
)
_IDA_FUNCTION_CHUNK_AT_RE = re.compile(
    r"^(?P<owner_seg>[A-Za-z_]\w*):(?P<owner_off>[0-9A-Fa-f]{4,5})\s+;\s+"
    r"FUNCTION\s+CHUNK\s+AT\s+(?P<seg>[A-Za-z_]\w*):(?P<off>[0-9A-Fa-f]{4,5})\s+"
    r"SIZE\s+(?P<size>[0-9A-Fa-f]{8})\s+BYTES\b",
    re.IGNORECASE,
)
_LINK_SEGMENT_RE = re.compile(
    r"^\s*(?P<start>[0-9A-Fa-f]+)H\s+(?P<stop>[0-9A-Fa-f]+)H\s+"
    r"(?P<length>[0-9A-Fa-f]+)H\s+(?P<name>\S+)\s+(?P<class>\S+)\s*$"
)
_LINK_PUBLIC_RE = re.compile(
    r"^\s*(?P<seg>[0-9A-Fa-f]{4,6}):(?P<off>[0-9A-Fa-f]{4,6})\s+(?P<name>.+?)\s*$"
)
_LINK_GROUP_RE = re.compile(r"^\s*(?P<seg>[0-9A-Fa-f]{4}):(?P<off>[0-9A-Fa-f]+)\s+(?P<name>\S+)\s*$")
_COD_PROC_RE = re.compile(r"^\s*(?P<name>[A-Za-z_$?@][\w$?@]*)\s+PROC\s+(?P<kind>[A-Za-z]+)\b", re.IGNORECASE)
_COD_ENDP_RE = re.compile(r"^\s*(?P<name>[A-Za-z_$?@][\w$?@]*)\s+ENDP\b", re.IGNORECASE)
_COD_ENTRY_RE = re.compile(r"\*\*\*\s+(?P<offset>[0-9A-Fa-f]+)\s+(?P<bytes>(?:[0-9A-Fa-f]{2}\s+)+)(?P<asm>.*)$")


@dataclass(frozen=True)
class _CODInstruction:
    offset: int
    data: bytes
    text: str


@dataclass(frozen=True)
class _CODProcedure:
    name: str
    kind: str
    start: int
    end_exclusive: int
    instructions: tuple[_CODInstruction, ...]


def read_mz_program_info(exe_path: Path | None) -> dict[str, Any]:  # noqa: D103
    if exe_path is None:
        return {"program_kind": "unknown"}
    data = exe_path.read_bytes()
    if exe_path.suffix.lower() == ".com" or data[:2] != b"MZ":
        return {
            "program_kind": "com",
            "entry": {"cs": "auto", "ip": "0x0100", "kind": "near"},
            "image_size": len(data),
        }
    if len(data) < 0x1C:
        raise DosUnitError(f"truncated MZ executable: {exe_path}")
    header_paragraphs = int.from_bytes(data[0x08:0x0A], "little")
    relocation_count = int.from_bytes(data[0x06:0x08], "little")
    relocation_offset = int.from_bytes(data[0x18:0x1A], "little")
    initial_ip = int.from_bytes(data[0x14:0x16], "little")
    initial_cs = int.from_bytes(data[0x16:0x18], "little")
    initial_sp = int.from_bytes(data[0x10:0x12], "little")
    initial_ss = int.from_bytes(data[0x0E:0x10], "little")
    return {
        "program_kind": "mz_exe",
        "mz": {
            "header_paragraphs": header_paragraphs,
            "relocation_count": relocation_count,
            "relocation_offset": relocation_offset,
            "initial_cs": normalize_hex(initial_cs, width=4),
            "initial_ip": normalize_hex(initial_ip, width=4),
            "initial_ss": normalize_hex(initial_ss, width=4),
            "initial_sp": normalize_hex(initial_sp, width=4),
            "image_offset": header_paragraphs * 16,
            "image_size": max(0, len(data) - header_paragraphs * 16),
        },
        "entry": {
            "cs": normalize_hex(initial_cs, width=4),
            "ip": normalize_hex(initial_ip, width=4),
            "kind": "near",
        },
    }


def _function_id(module: str, name: str, segment: str, offset: int) -> str:
    stable_name = name or f"{segment}_{offset:04x}"
    return f"{module}:{stable_name}"


def _normalize_symbol_name(name: str) -> str:
    if name.startswith("__"):
        return name
    if name.startswith("_"):
        return name[1:]
    return name


def _borland_mangling() -> Any:  # noqa: ANN401
    """Load the standalone Borland demangler without the X86_16 package init."""
    import importlib.util
    import sys

    module_name = "_dosunit_borland_mangling"
    module = sys.modules.get(module_name)
    if module is None:
        repo_root = Path(__file__).resolve().parents[2]
        module_path = (
            repo_root / "angr_platforms" / "angr_platforms" / "X86_16" / "borland_mangling.py"
        )
        spec = importlib.util.spec_from_file_location(module_name, module_path)
        if spec is None or spec.loader is None:
            raise DosUnitError(f"failed to load Borland mangling module from {module_path}")
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
    return module


def _symbol_aliases(name: str) -> list[str]:
    """Alias spellings that let name-mode mapping join mangled/demangled links.

    Borland-mangled ``@scope@name$q<types>`` names gain the TDUMP-style
    demangled signature (``scope::name(type far*)``) and the bare
    ``scope::name`` spelling; already-demangled ``name(args)`` names gain
    the bare ``name`` spelling.  Aliases are optional evidence only: a
    demangle parse failure simply yields no extra spellings.
    """
    text = name.strip()
    aliases: list[str] = []
    if text.startswith("@"):
        mangling = _borland_mangling()
        signature = mangling.demangle_borland_name(text)
        if not signature.parse_error:
            rendered = mangling.render_borland_signature(signature)
            if rendered and rendered != text:
                aliases.append(rendered)
                base = rendered.split("(", 1)[0].strip()
                if base and base not in aliases:
                    aliases.append(base)
    elif "(" in text:
        base = text[: text.index("(")].strip()
        if base and base != text:
            aliases.append(base)
    return aliases


def _catalog_entry(
    *,
    module: str,
    name: str,
    segment: str,
    offset: int,
    source: str,
    return_kind: str = "near",
    segment_para: int | None = None,
    end: int | None = None,
    confidence: str = "medium",
) -> dict[str, Any]:
    names = [name] if name else []
    names.extend(alias for alias in _symbol_aliases(name) if alias not in names)
    entry: dict[str, Any] = {
        "id": _function_id(module, name, segment, offset),
        "names": names,
        "entry": {
            "kind": "module_relative",
            "segment": segment,
            "offset": normalize_hex(offset, width=4),
        },
        "return_kind": return_kind.lower(),
        "sources": [source],
        "confidence": confidence,
        "size": None if end is None else max(0, end - offset + 1),
        "safe_traps": [],
    }
    if segment_para is not None:
        entry["entry"]["segment_para"] = normalize_hex(segment_para, width=4)
        entry["entry"]["linear"] = normalize_hex((segment_para << 4) + offset)
    if end is not None:
        entry["end_offset"] = normalize_hex(end, width=4)
    return entry


def _merge_entry(existing: dict[str, Any], incoming: dict[str, Any]) -> None:
    _merge_names_sources(existing, incoming)
    entry = existing.setdefault("entry", {})
    for key, value in incoming.get("entry", {}).items():
        entry.setdefault(key, value)
    _merge_ranges(existing, incoming)


def _merge_names_sources(existing: dict[str, Any], incoming: dict[str, Any]) -> None:
    """Merge name/source inventories and confidence/size fallbacks."""
    for name in incoming.get("names", ()):
        if name not in existing["names"]:
            existing["names"].append(name)
    for source in incoming.get("sources", ()):
        if source not in existing["sources"]:
            existing["sources"].append(source)
    if existing.get("confidence") != "high" and len(existing.get("sources", ())) >= 2:
        existing["confidence"] = "high"
    for key in ("size", "end_offset"):
        if existing.get(key) is None and incoming.get(key) is not None:
            existing[key] = incoming[key]


def _merge_ranges(existing: dict[str, Any], incoming: dict[str, Any]) -> None:
    """Merge unique range entries keyed by kind/segment/offset/size/end."""
    ranges = existing.setdefault("ranges", [])
    if not isinstance(ranges, list):
        ranges = []
        existing["ranges"] = ranges
    seen_ranges = {
        (
            item.get("kind"),
            item.get("segment"),
            item.get("offset"),
            item.get("size"),
            item.get("end_offset"),
        )
        for item in ranges
        if isinstance(item, dict)
    }
    for item in incoming.get("ranges", ()) or ():
        if not isinstance(item, dict):
            continue
        key = (
            item.get("kind"),
            item.get("segment"),
            item.get("offset"),
            item.get("size"),
            item.get("end_offset"),
        )
        if key in seen_ranges:
            continue
        ranges.append(dict(item))
        seen_ranges.add(key)


def parse_mzre_segments(map_path: Path) -> list[dict[str, Any]]:  # noqa: D103
    segments: list[dict[str, Any]] = []
    for line in map_path.read_text(errors="ignore").splitlines():
        segment_match = _MZRE_SEGMENT_RE.match(line.strip())
        if segment_match is None:
            continue
        segments.append(
            {
                "name": segment_match.group(1),
                "class": segment_match.group(2).upper(),
                "paragraph": normalize_hex(int(segment_match.group(3), 16), width=4),
                "source": "mzre_map",
            }
        )
    return segments


def parse_linker_segments(map_path: Path) -> list[dict[str, Any]]:  # noqa: D103
    segments: list[dict[str, Any]] = []
    in_group_section = False
    for line in map_path.read_text(errors="ignore").splitlines():
        segment_match = _LINK_SEGMENT_RE.match(line)
        if segment_match is not None:
            start = int(segment_match.group("start"), 16)
            segments.append(
                {
                    "name": segment_match.group("name"),
                    "class": segment_match.group("class").upper(),
                    "paragraph": normalize_hex(start >> 4, width=4),
                    "linear_start": normalize_hex(start),
                    "linear_stop": normalize_hex(int(segment_match.group("stop"), 16)),
                    "source": "link_map",
                }
            )
            continue
        if line.strip() == "Origin   Group":
            in_group_section = True
            continue
        if in_group_section:
            group_match = _LINK_GROUP_RE.match(line)
            if group_match is not None:
                segments.append(
                    {
                        "name": group_match.group("name"),
                        "class": "DATA",
                        "paragraph": normalize_hex(int(group_match.group("seg"), 16), width=4),
                        "source": "link_map_group",
                    }
                )
                continue
            if line.strip() == "":
                in_group_section = False
    return segments


def parse_mzre_map(map_path: Path, *, module: str) -> list[dict[str, Any]]:  # noqa: D103
    segment_paragraphs: dict[str, int] = {}
    entries: list[dict[str, Any]] = []
    for line in map_path.read_text(errors="ignore").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        segment_match = _MZRE_SEGMENT_RE.match(stripped)
        if segment_match is not None:
            segment_paragraphs[segment_match.group(1)] = int(segment_match.group(3), 16)
            continue
        routine_match = _MZRE_ROUTINE_RE.match(stripped)
        if routine_match is None:
            continue
        name = _normalize_symbol_name(routine_match.group(1))
        segment = routine_match.group(2)
        return_kind = routine_match.group(3).lower()
        start = int(routine_match.group(4), 16)
        end = int(routine_match.group(5), 16)
        entries.append(
            _catalog_entry(
                module=module,
                name=name,
                segment=segment,
                offset=start,
                end=end,
                return_kind=return_kind,
                segment_para=segment_paragraphs.get(segment),
                source="mzre_map",
                confidence="medium",
            )
        )
    return entries


def parse_linker_map(map_path: Path, *, module: str) -> list[dict[str, Any]]:  # noqa: D103
    segments: list[dict[str, Any]] = []
    entries_by_key: dict[tuple[str, int], dict[str, Any]] = {}
    for line in map_path.read_text(errors="ignore").splitlines():
        segment_match = _LINK_SEGMENT_RE.match(line)
        if segment_match is not None:
            start = int(segment_match.group("start"), 16)
            stop = int(segment_match.group("stop"), 16)
            segments.append(
                {
                    "start": start,
                    "stop": stop,
                    "class": segment_match.group("class").upper(),
                    "name": segment_match.group("name"),
                }
            )
            continue
        public_match = _LINK_PUBLIC_RE.match(line)
        if public_match is None:
            continue
        seg = int(public_match.group("seg"), 16)
        off = int(public_match.group("off"), 16)
        linear = (seg << 4) + off
        if not _linear_in_code_segment(linear, segments):
            continue
        raw_name = public_match.group("name")
        name = _normalize_symbol_name(raw_name)
        if not name:
            continue
        key = (name, linear)
        entries_by_key.setdefault(
            key,
            _catalog_entry(
                module=module,
                name=name,
                segment=f"{seg:04x}",
                offset=off,
                return_kind="near",
                segment_para=seg,
                source="link_map",
                confidence="medium",
            ),
        )
    return sorted(entries_by_key.values(), key=lambda item: int(item["entry"].get("linear", "0"), 0))


def _linear_in_code_segment(linear: int, segments: list[dict[str, Any]]) -> bool:
    for segment in segments:
        if segment.get("class") == "CODE" and int(segment["start"]) <= linear <= int(segment["stop"]):
            return True
    return False


def parse_cod_listing(  # noqa: D103
    cod_path: Path,
    *,
    module: str,
    exe_path: Path | None = None,
    map_path: Path | None = None,
) -> list[dict[str, Any]]:
    procedures = _parse_cod_procedures(cod_path)
    if not procedures:
        return []
    code_segments = _linker_code_segments(map_path)
    image = _mz_loaded_image(exe_path) if exe_path is not None else None
    object_delta = _infer_cod_object_delta(procedures, image=image, code_segments=code_segments)
    entries: list[dict[str, Any]] = []
    for procedure in procedures:
        linked_start = procedure.start + object_delta
        linked_end_exclusive = max(linked_start + 1, procedure.end_exclusive + object_delta)
        segment = _code_segment_for_linear(linked_start, code_segments)
        segment_name = str(segment.get("name", "seg000")) if segment is not None else "seg000"
        segment_start = int(segment.get("start", 0)) if segment is not None else 0
        segment_para = segment_start >> 4
        start_offset = linked_start - (segment_para << 4)
        end_offset = max(start_offset, linked_end_exclusive - 1 - (segment_para << 4))
        entries.append(
            _catalog_entry(
                module=module,
                name=_normalize_symbol_name(procedure.name),
                segment=segment_name,
                offset=start_offset,
                end=end_offset,
                return_kind=procedure.kind.lower(),
                segment_para=segment_para,
                source="cod_listing",
                confidence="high" if image is not None else "medium",
            )
        )
    return entries


def _parse_cod_procedures(cod_path: Path) -> list[_CODProcedure]:
    procedures: list[_CODProcedure] = []
    current_name: str | None = None
    current_kind: str | None = None
    instructions: list[_CODInstruction] = []

    def _finish() -> None:
        nonlocal current_name, current_kind, instructions
        if current_name is None or current_kind is None or not instructions:
            current_name = None
            current_kind = None
            instructions = []
            return
        start = min(item.offset for item in instructions)
        end_exclusive = max(item.offset + max(1, len(item.data)) for item in instructions)
        procedures.append(
            _CODProcedure(
                name=current_name,
                kind=current_kind.upper(),
                start=start,
                end_exclusive=end_exclusive,
                instructions=tuple(sorted(instructions, key=lambda item: item.offset)),
            )
        )
        current_name = None
        current_kind = None
        instructions = []

    for line in cod_path.read_text(errors="ignore").splitlines():
        proc_match = _COD_PROC_RE.match(line)
        if proc_match is not None:
            _finish()
            current_name = proc_match.group("name")
            current_kind = proc_match.group("kind")
            continue
        if current_name is None:
            continue
        end_match = _COD_ENDP_RE.match(line)
        if end_match is not None and end_match.group("name") == current_name:
            _finish()
            continue
        entry_match = _COD_ENTRY_RE.search(line)
        if entry_match is None:
            continue
        instructions.append(
            _CODInstruction(
                offset=int(entry_match.group("offset"), 16),
                data=bytes.fromhex("".join(entry_match.group("bytes").split())),
                text=entry_match.group("asm").strip(),
            )
        )
    _finish()
    return procedures


def _linker_code_segments(map_path: Path | None) -> list[dict[str, Any]]:
    if map_path is None or not map_path.exists():
        return []
    segments: list[dict[str, Any]] = []
    for line in map_path.read_text(errors="ignore").splitlines():
        segment_match = _LINK_SEGMENT_RE.match(line)
        if segment_match is None or segment_match.group("class").upper() != "CODE":
            continue
        segments.append(
            {
                "start": int(segment_match.group("start"), 16),
                "stop": int(segment_match.group("stop"), 16),
                "name": segment_match.group("name"),
                "class": "CODE",
            }
        )
    return segments


def _mz_loaded_image(exe_path: Path | None) -> bytes | None:
    if exe_path is None or not exe_path.exists():
        return None
    data = exe_path.read_bytes()
    if exe_path.suffix.lower() == ".com" or data[:2] != b"MZ":
        return data
    if len(data) < 0x1C:
        raise DosUnitError(f"truncated MZ executable: {exe_path}")
    header_size = int.from_bytes(data[0x08:0x0A], "little") * 16
    return data[header_size:]


def _infer_cod_object_delta(
    procedures: list[_CODProcedure],
    *,
    image: bytes | None,
    code_segments: list[dict[str, Any]],
) -> int:
    if image is None:
        first_segment = min((int(segment["start"]) for segment in code_segments), default=0)
        return first_segment
    votes: dict[int, int] = {}
    for procedure in procedures:
        pattern = _cod_procedure_pattern(procedure)
        if pattern is None:
            continue
        pattern_bytes, mask = pattern
        for linked_offset in _find_masked_pattern(image, pattern_bytes, mask, code_segments=code_segments):
            votes[linked_offset - procedure.start] = votes.get(linked_offset - procedure.start, 0) + 1
    if not votes:
        first_segment = min((int(segment["start"]) for segment in code_segments), default=0)
        return first_segment
    return sorted(votes.items(), key=lambda item: (-item[1], item[0]))[0][0]


def _cod_procedure_pattern(procedure: _CODProcedure) -> tuple[bytes, tuple[bool, ...]] | None:
    if not procedure.instructions:
        return None
    pattern = bytearray()
    mask: list[bool] = []
    expected = procedure.instructions[0].offset
    for instruction in procedure.instructions:
        if instruction.offset != expected and pattern:
            break
        data = instruction.data
        if not data:
            break
        instruction_mask = _cod_instruction_mask(data, instruction.text)
        pattern.extend(data)
        mask.extend(instruction_mask)
        expected = instruction.offset + len(data)
        if len(pattern) >= 48:
            break
    if len(pattern) < 4 or sum(1 for keep in mask if keep) < 4:
        return None
    return bytes(pattern), tuple(mask)


def _cod_instruction_mask(data: bytes, text: str) -> list[bool]:
    mask = [True] * len(data)
    if not data:
        return mask
    mnemonic = text.split(None, 1)[0].lower() if text.strip() else ""
    if mnemonic == "call" and data[0] in {0x9A, 0xE8}:
        for idx in range(1, len(mask)):
            mask[idx] = False
    if " offset " in f" {text.lower()} ":
        for idx in range(1, len(mask)):
            mask[idx] = False
    return mask


def _find_masked_pattern(
    image: bytes,
    pattern: bytes,
    mask: tuple[bool, ...],
    *,
    code_segments: list[dict[str, Any]],
) -> list[int]:
    if len(pattern) != len(mask) or not pattern or len(pattern) > len(image):
        return []
    ranges = _search_ranges(len(image), len(pattern), code_segments)
    matches: list[int] = []
    for start, stop in ranges:
        for at in range(start, stop + 1):
            for idx, expected in enumerate(pattern):
                if mask[idx] and image[at + idx] != expected:
                    break
            else:
                matches.append(at)
    return matches


def _search_ranges(image_size: int, pattern_size: int, code_segments: list[dict[str, Any]]) -> list[tuple[int, int]]:
    if not code_segments:
        return [(0, max(0, image_size - pattern_size))]
    ranges: list[tuple[int, int]] = []
    for segment in code_segments:
        start = max(0, int(segment["start"]))
        stop = min(image_size - pattern_size, int(segment["stop"]) - pattern_size + 1)
        if start <= stop:
            ranges.append((start, stop))
    return ranges


def _code_segment_for_linear(linear: int, code_segments: list[dict[str, Any]]) -> dict[str, Any] | None:
    for segment in code_segments:
        if int(segment["start"]) <= linear <= int(segment["stop"]):
            return segment
    return None


def parse_ida_listing(listing_path: Path, *, module: str) -> list[dict[str, Any]]:  # noqa: D103
    segment_classes: dict[str, str] = {}
    entries: list[dict[str, Any]] = []
    current_entry: dict[str, Any] | None = None
    for line in listing_path.read_text(errors="ignore").splitlines():
        stripped = line.strip()
        segment_match = _IDA_SEGMENT_RE.match(stripped)
        if segment_match is not None:
            segment_classes[segment_match.group("name")] = segment_match.group("class").upper()
            continue
        endp_match = _IDA_ENDP_RE.match(stripped)
        if endp_match is not None:
            current_entry = None
            continue
        chunk_match = _IDA_FUNCTION_CHUNK_AT_RE.match(stripped)
        if chunk_match is not None and current_entry is not None:
            chunk_offset = int(chunk_match.group("off"), 16)
            chunk_size = int(chunk_match.group("size"), 16)
            if chunk_size > 0:
                current_entry.setdefault("ranges", []).append(
                    {
                        "kind": "function_chunk",
                        "segment": chunk_match.group("seg"),
                        "offset": normalize_hex(chunk_offset, width=4),
                        "size": chunk_size,
                        "end_offset": normalize_hex(chunk_offset + chunk_size - 1, width=4),
                        "source": "ida_lst",
                    }
                )
            continue
        proc_match = _IDA_PROC_RE.match(stripped)
        if proc_match is None:
            continue
        segment = proc_match.group("seg")
        segment_class = segment_classes.get(segment)
        if segment_class is not None and segment_class != "CODE":
            current_entry = None
            continue
        offset = int(proc_match.group("off"), 16)
        name = _normalize_symbol_name(proc_match.group("name"))
        confidence = "medium" if segment_class == "CODE" else "low"
        current_entry = _catalog_entry(
            module=module,
            name=name,
            segment=segment,
            offset=offset,
            return_kind=proc_match.group("kind").lower(),
            source="ida_lst",
            confidence=confidence,
        )
        entries.append(current_entry)
    return entries


def _resolve_module_name(
    *,
    module: str | None,
    exe_path: Path | None,
    map_path: Path | None,
    ida_listing_path: Path | None,
) -> str:
    """Resolve the catalog module name from the explicit or input paths."""
    module_name = module or (exe_path.name if exe_path is not None else None)
    if module_name is None:
        if map_path is not None:
            module_name = map_path.with_suffix(".exe").name
        elif ida_listing_path is not None:
            module_name = ida_listing_path.with_suffix(".exe").name
        else:
            raise DosUnitError("module name is required when no input paths are provided")
    return module_name


def _map_segments(map_path: Path | None, diagnostics: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Parse segment inventories from a linker map, refusing on failure."""
    segments: list[dict[str, Any]] = []
    if map_path is None:
        return segments
    try:
        segments.extend(parse_mzre_segments(map_path))
        segments.extend(parse_linker_segments(map_path))
    except Exception as ex:
        diagnostics.append(
            {
                "source": str(map_path),
                "status": "refused",
                "reason": "backend_error",
                "message": str(ex),
            }
        )
    return segments


def _collect_source_entries(
    by_id: dict[str, dict[str, Any]],
    diagnostics: list[dict[str, Any]],
    *,
    map_path: Path | None,
    cod_listing_path: Path | None,
    ida_listing_path: Path | None,
    module_name: str,
    exe_path: Path | None,
) -> None:
    """Run each discovery parser and merge entries by function id."""
    parser_specs = (
        (map_path, lambda path: parse_mzre_map(path, module=module_name)),
        (map_path, lambda path: parse_linker_map(path, module=module_name)),
        (
            cod_listing_path,
            lambda path: parse_cod_listing(path, module=module_name, exe_path=exe_path, map_path=map_path),
        ),
        (ida_listing_path, lambda path: parse_ida_listing(path, module=module_name)),
    )
    for source_path, parser in parser_specs:
        if source_path is None:
            continue
        try:
            entries = parser(source_path)
        except Exception as ex:
            diagnostics.append(
                {
                    "source": str(source_path),
                    "status": "refused",
                    "reason": "backend_error",
                    "message": str(ex),
                }
            )
            continue
        for entry in entries:
            key = entry["id"]
            if key in by_id:
                _merge_entry(by_id[key], entry)
            else:
                by_id[key] = entry


def _entry_sort_key(item: dict[str, Any]) -> tuple[int, int, str]:
    """Sort functions by entry linear address, then id."""
    linear = item.get("entry", {}).get("linear")
    if isinstance(linear, str):
        try:
            return (0, int(linear, 0), str(item.get("id", "")))
        except ValueError:
            pass
    return (1, 0, str(item.get("id", "")))




def discover_functions(  # noqa: D103
    *,
    exe_path: Path | None = None,
    map_path: Path | None = None,
    cod_listing_path: Path | None = None,
    ida_listing_path: Path | None = None,
    module: str | None = None,
) -> dict[str, Any]:
    module_name = _resolve_module_name(
        module=module,
        exe_path=exe_path,
        map_path=map_path,
        ida_listing_path=ida_listing_path,
    )

    program_info = read_mz_program_info(exe_path)
    by_id: dict[str, dict[str, Any]] = {}
    diagnostics: list[dict[str, Any]] = []
    segments = _map_segments(map_path, diagnostics)
    _collect_source_entries(
        by_id,
        diagnostics,
        map_path=map_path,
        cod_listing_path=cod_listing_path,
        ida_listing_path=ida_listing_path,
        module_name=module_name,
        exe_path=exe_path,
    )

    functions = sorted(by_id.values(), key=_entry_sort_key)
    catalog_without_id = {
        "schema": "dosunit.functions.v1",
        "module": module_name,
        "program_kind": program_info.get("program_kind", "unknown"),
        "program": program_info,
        "segments": segments,
        "functions": functions,
        "diagnostics": diagnostics,
    }
    catalog = dict(catalog_without_id)
    catalog["id"] = stable_id("functions", catalog_without_id)
    return catalog


def function_for_linear(catalog: dict[str, Any], linear: int) -> dict[str, Any] | None:  # noqa: D103
    best: dict[str, Any] | None = None
    best_start = -1
    for function in catalog.get("functions", ()) or ():
        entry = function.get("entry", {})
        linear_text = entry.get("linear")
        if not isinstance(linear_text, str):
            continue
        try:
            start = int(linear_text, 0)
        except ValueError:
            continue
        size = function.get("size")
        end = start + int(size) if isinstance(size, int) and size > 0 else start + 1
        if start <= linear < end and start > best_start:
            best = function
            best_start = start
    return best
