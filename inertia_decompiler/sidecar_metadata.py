from __future__ import annotations

from pathlib import Path

import angr
from angr_platforms.X86_16.lst_extract import LSTMetadata, extract_lst_metadata
from angr_platforms.X86_16.turbo_debug_tdinfo import parse_tdinfo_exe

from inertia_decompiler.project_loading import _probe_ida_base_linear
from inertia_decompiler.sidecar_parsers import (
    _detect_flair_metadata,
    _parse_cod_sidecar_metadata,
    _parse_codeview_nb00_metadata,
    _parse_ida_lst_proc_metadata,
    _parse_ida_map_metadata,
    _parse_idc_metadata,
    _parse_inc_struct_names,
    _parse_mzre_map_metadata,
    _reconcile_cod_listing_with_codeview,
    _synthesize_code_ranges,
)


def _signature_matched_code_addrs(metadata: LSTMetadata | None) -> frozenset[int]:
    if metadata is None:
        return frozenset()
    addrs = getattr(metadata, "signature_code_addrs", frozenset())
    return addrs if isinstance(addrs, frozenset) else frozenset(addrs)


def _visible_code_labels(metadata: LSTMetadata | None) -> dict[int, str]:
    if metadata is None:
        return {}
    skipped = _signature_matched_code_addrs(metadata)
    if not skipped:
        return dict(metadata.code_labels)
    return {addr: name for addr, name in metadata.code_labels.items() if addr not in skipped}


def _load_lst_metadata(
    binary: Path,
    project: angr.Project,
    *,
    pat_backend: str | None = None,
    signature_catalog: Path | None = None,
) -> LSTMetadata | None:
    load_base_linear = _probe_ida_base_linear(binary, getattr(project.loader.main_object, "linked_base", 0))
    code_labels: dict[int, str] = {}
    data_labels: dict[int, str] = {}
    code_ranges: dict[int, tuple[int, int]] = {}
    signature_code_addrs: set[int] = set()
    cod_proc_kinds: dict[int, str] = {}
    struct_names: list[str] = []
    source_formats: list[str] = []
    cod_path: Path | None = None
    codeview_code: dict[int, str] = {}
    codeview_data: dict[int, str] = {}
    codeview_ranges: dict[int, tuple[int, int]] = {}
    map_path = binary.with_suffix(".map")
    segment_offsets: dict[str, int] = {}

    if map_path.exists():
        try:
            ida_code, ida_data, segment_offsets = _parse_ida_map_metadata(map_path, load_base_linear=load_base_linear)
            if ida_code or ida_data or segment_offsets:
                code_labels.update(ida_code)
                data_labels.update(ida_data)
                source_formats.append("ida_map")
        except Exception as exc:
            print(f"[dbg] failed to parse IDA map {map_path}: {exc}")

    lst_path = binary.with_suffix(".lst")
    if lst_path.exists():
        try:
            metadata = extract_lst_metadata(lst_path)
            if metadata.code_labels or metadata.data_labels:
                if metadata.absolute_addrs:
                    code_labels.update(metadata.code_labels)
                    data_labels.update(metadata.data_labels)
                    code_ranges.update(metadata.code_ranges)
                else:
                    for offset, name in metadata.data_labels.items():
                        data_labels.setdefault(load_base_linear + offset, name)
                    for offset, name in metadata.code_labels.items():
                        code_labels.setdefault(load_base_linear + offset, name)
                    for offset, span in metadata.code_ranges.items():
                        code_ranges.setdefault(
                            load_base_linear + offset,
                            (load_base_linear + span[0], load_base_linear + span[1]),
                        )
                source_formats.append(metadata.source_format)
        except Exception as exc:
            print(f"[dbg] failed to parse source listing {lst_path}: {exc}")
        try:
            ida_proc_labels = _parse_ida_lst_proc_metadata(
                lst_path,
                load_base_linear=load_base_linear,
                segment_offsets=segment_offsets,
            )
            if ida_proc_labels:
                code_labels.update(ida_proc_labels)
                source_formats.append("ida_lst")
        except Exception as exc:
            print(f"[dbg] failed to parse IDA proc listing {lst_path}: {exc}")

    idc_path = binary.with_suffix(".idc")
    if idc_path.exists():
        try:
            idc_code, idc_data = _parse_idc_metadata(idc_path)
            if idc_code or idc_data:
                code_labels.update(idc_code)
                data_labels.update(idc_data)
                source_formats.append("ida_idc")
        except Exception as exc:
            print(f"[dbg] failed to parse IDC file {idc_path}: {exc}")

    inc_path = binary.with_suffix(".inc")
    if inc_path.exists():
        try:
            struct_names.extend(_parse_inc_struct_names(inc_path))
            source_formats.append("ida_inc")
        except Exception as exc:
            print(f"[dbg] failed to parse INC file {inc_path}: {exc}")

    try:
        codeview_code, codeview_data, codeview_ranges = _parse_codeview_nb00_metadata(
            binary,
            load_base_linear=load_base_linear,
        )
    except Exception as exc:
        print(f"[dbg] failed to parse CodeView NB00 metadata from {binary}: {exc}")

    try:
        tdinfo = parse_tdinfo_exe(binary, load_base_linear=load_base_linear)
        if tdinfo is not None and (tdinfo.code_labels or tdinfo.data_labels):
            for addr, name in tdinfo.code_labels.items():
                code_labels.setdefault(addr, name)
            for addr, name in tdinfo.data_labels.items():
                data_labels.setdefault(addr, name)
            source_formats.append("turbo_debug_tdinfo")
    except Exception as exc:
        print(f"[dbg] failed to parse Turbo Debug TDInfo metadata from {binary}: {exc}")

    sibling_cod_path = binary.with_suffix(".COD")
    if sibling_cod_path.exists():
        try:
            cod_anchor_labels = dict(code_labels)
            cod_anchor_labels.update(codeview_code)
            cod_listing = _parse_cod_sidecar_metadata(
                sibling_cod_path,
                load_base_linear=load_base_linear,
                existing_code_labels=cod_anchor_labels,
            )
            cod_listing = _reconcile_cod_listing_with_codeview(cod_listing, codeview_code, codeview_ranges)
            if cod_listing.code_labels or cod_listing.code_ranges or cod_listing.proc_kinds:
                for addr, name in cod_listing.code_labels.items():
                    code_labels.setdefault(addr, name)
                for addr, span in cod_listing.code_ranges.items():
                    code_ranges.setdefault(addr, span)
                cod_proc_kinds.update(cod_listing.proc_kinds)
                cod_path = sibling_cod_path
                source_formats.append("cod_listing")
        except Exception as exc:
            print(f"[dbg] failed to parse COD listing {sibling_cod_path}: {exc}")

    if codeview_code or codeview_data or codeview_ranges:
        for addr, name in codeview_code.items():
            code_labels.setdefault(addr, name)
        for addr, name in codeview_data.items():
            data_labels.setdefault(addr, name)
        for addr, span in codeview_ranges.items():
            code_ranges.setdefault(addr, span)
        source_formats.append("codeview_nb00")

    external_mzre_map = Path("/home/xor/games/f15se2-re/map") / f"{binary.stem}.map"
    if external_mzre_map.exists():
        try:
            mzre_code, mzre_data, mzre_ranges = _parse_mzre_map_metadata(
                external_mzre_map,
                load_base_linear=load_base_linear,
            )
            if mzre_code or mzre_data or mzre_ranges:
                for addr, name in mzre_code.items():
                    code_labels.setdefault(addr, name)
                for addr, name in mzre_data.items():
                    data_labels.setdefault(addr, name)
                for addr, span in mzre_ranges.items():
                    code_ranges.setdefault(addr, span)
                source_formats.append("mzre_map")
        except Exception as exc:
            print(f"[dbg] failed to parse mzretools map {external_mzre_map}: {exc}")

    try:
        flair_code, flair_ranges, flair_formats = _detect_flair_metadata(
            binary,
            project,
            pat_backend=pat_backend,
            signature_catalog=signature_catalog,
        )
        if flair_code or flair_ranges:
            for addr, name in flair_code.items():
                code_labels.setdefault(addr, name)
                signature_code_addrs.add(addr)
            for addr, span in flair_ranges.items():
                code_ranges.setdefault(addr, span)
        source_formats.extend(flair_formats)
    except Exception as exc:
        print(f"[dbg] failed to inspect FLAIR metadata for {binary}: {exc}")

    if not code_labels and not data_labels and not struct_names:
        return None

    for addr, name in data_labels.items():
        project.kb.labels[addr] = name
    for addr, name in code_labels.items():
        project.kb.labels[addr] = name

    image_end = getattr(getattr(project.loader, "main_object", None), "max_addr", None)
    if isinstance(image_end, int):
        image_end += 1
    code_ranges = _synthesize_code_ranges(code_labels, code_ranges, image_end=image_end)

    metadata = LSTMetadata(
        data_labels=data_labels,
        code_labels=code_labels,
        code_ranges=code_ranges,
        signature_code_addrs=frozenset(signature_code_addrs),
        absolute_addrs=True,
        source_format="+".join(dict.fromkeys(source_formats)) or "sidecars",
        struct_names=tuple(dict.fromkeys(struct_names)),
        cod_path=str(cod_path) if cod_path is not None else None,
        cod_proc_kinds=cod_proc_kinds,
    )
    project._inertia_lst_metadata = metadata
    print(
        f"[dbg] loaded sidecar metadata: format={metadata.source_format} "
        f"code_labels={len(metadata.code_labels)} data_labels={len(metadata.data_labels)} structs={len(metadata.struct_names)}"
    )
    flair_titles = getattr(project, "_inertia_flair_sig_titles", ())
    if flair_titles:
        print(f"[dbg] flair signature catalogs: {', '.join(flair_titles[:3])}")
    return metadata


def _lst_data_label(metadata: LSTMetadata | None, offset: int | None) -> str | None:
    if metadata is None or offset is None:
        return None
    return metadata.data_labels.get(offset)


def _lst_code_label(metadata: LSTMetadata | None, addr: int | None, code_base: int | None) -> str | None:
    if metadata is None or addr is None:
        return None
    if metadata.absolute_addrs:
        return metadata.code_labels.get(addr)
    if code_base is None:
        return None
    return metadata.code_labels.get(addr - code_base)


def _lst_code_region(metadata: LSTMetadata | None, addr: int | None) -> tuple[int, int] | None:
    if metadata is None or addr is None:
        return None
    code_ranges = getattr(metadata, "code_ranges", None) or {}
    span = code_ranges.get(addr)
    if span is not None:
        return span
    for start, span in code_ranges.items():
        if start <= addr < span[1]:
            return span
    return None
