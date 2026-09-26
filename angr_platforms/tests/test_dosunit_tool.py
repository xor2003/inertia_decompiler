from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from tools.dosunit import dosunit as dosunit_cli
from tools.dosunit import ir_edges, straightline_ssa
from tools.dosunit.complexity import analyze_function_complexity
from tools.dosunit.data_compare import compare_loaded_data_images
from tools.dosunit.discovery import discover_functions
from tools.dosunit.dosunit import main as dosunit_main
from tools.dosunit.failure_report import render_failure_report
from tools.dosunit.generate import generate_vectors
from tools.dosunit.kvikdos_backend import KvikdosSession, build_harness
from tools.dosunit.libdosbox_import import import_libdosbox_trace
from tools.dosunit.mapping import MappingResolutionError, apply_candidate_mapping, make_mapping_document
from tools.dosunit.region_effects import compare_region_effect_documents, summarize_region_effects
from tools.dosunit.runner import compare_vectors, record_oracle
from tools.dosunit.straightline_ssa import (
    _instruction_text_from_record,
    _ssa_block_successors,
    compare_ssa_abi_documents,
    compare_ssa_documents,
    lower_straightline_ssa_document,
)
from tools.dosunit.vectors import select_vectors


def _write(path: Path, text: str) -> Path:
    path.write_text(text)
    return path


def _mz_exe(image: bytes, *, relocs: tuple[tuple[int, int], ...] = (), minalloc: int = 0x1000) -> bytes:
    reloc_pos = 0x1C
    header_size = max(0x20, ((reloc_pos + len(relocs) * 4 + 15) // 16) * 16)
    file_size = header_size + len(image)
    blocks, lastsize = divmod(file_size, 512)
    if lastsize:
        blocks += 1
    header = bytearray(header_size)
    header[0:2] = b"MZ"
    header[0x02:0x04] = lastsize.to_bytes(2, "little")
    header[0x04:0x06] = blocks.to_bytes(2, "little")
    header[0x06:0x08] = len(relocs).to_bytes(2, "little")
    header[0x08:0x0A] = (header_size // 16).to_bytes(2, "little")
    header[0x0A:0x0C] = minalloc.to_bytes(2, "little")
    header[0x0C:0x0E] = (0xFFFF).to_bytes(2, "little")
    header[0x0E:0x10] = (0x0080).to_bytes(2, "little")
    header[0x10:0x12] = (0xFFFE).to_bytes(2, "little")
    header[0x14:0x16] = (0).to_bytes(2, "little")
    header[0x16:0x18] = (0).to_bytes(2, "little")
    header[0x18:0x1A] = reloc_pos.to_bytes(2, "little")
    for idx, (off, seg) in enumerate(relocs):
        at = reloc_pos + idx * 4
        header[at : at + 2] = off.to_bytes(2, "little")
        header[at + 2 : at + 4] = seg.to_bytes(2, "little")
    return bytes(header) + image


def _leaf_vector() -> dict[str, object]:
    return {
        "schema": "dosunit.vector.v1",
        "module": "demo.exe",
        "function": {"name": "leaf", "entry": {"cs": "0x0000", "ip": "0x0200", "kind": "near"}},
        "source": {"kind": "manual", "origin": "test", "assumptions": []},
        "pre": {
            "regs": {
                "ax": "0x0000",
                "bx": "0x0000",
                "cx": "0x0000",
                "dx": "0x0000",
                "si": "0x0000",
                "di": "0x0000",
                "bp": "0x0000",
                "sp": "0xff00",
                "flags": "0x0202",
            },
            "sregs": {"cs": "auto", "ds": "auto", "es": "auto", "ss": "auto"},
            "memory": [],
        },
        "observe": {
            "regs": ["ax", "sp"],
            "sregs": ["cs", "ds", "ss"],
            "flags_mask": "0xffff",
            "memory": [],
            "calls": True,
            "return": True,
        },
        "expected": None,
    }


def test_dosunit_discovers_mzre_map_and_ida_listing(tmp_path: Path):
    exe = tmp_path / "EGAME.EXE"
    exe.write_bytes(
        b"MZ"
        + b"\x00\x00"
        + b"\x00\x00"
        + b"\x00\x00"
        + b"\x00\x00"
        + b"\x20\x00"
        + b"\x00\x00" * 2
        + b"\x00\x00"
        + b"\x00\x10"
        + b"\x10\x00"
        + b"\x00\x00"
        + b"\x00\x00"
        + b"\x1c\x00"
        + b"\x00" * 96
    )
    mzre_map = _write(
        tmp_path / "egame.map",
        "\n".join(
            [
                "Size 28f70",
                "seg000 CODE 0000",
                "Data1 DATA 228b",
                "main: seg000 NEAR 0010-0146 R0010-0146 complete",
                "lookupSineFar: seg000 FAR 3bc1-3bc4 R3bc1-3bc4 assembly",
            ]
        ),
    )
    ida_lst = _write(
        tmp_path / "egame.lst",
        "\n".join(
            [
                "seg000:0000 ; Base Address: 1000h Range: 10000h-3D0D0h Loaded length: 28F70h",
                "seg000:0000 seg000 segment byte public 'CODE' use16",
                "seg000:0010 _main proc near",
                "seg000:3BC1 _lookupSineFar proc far",
                "seg000:E5BF __exit proc near",
            ]
        ),
    )

    catalog = discover_functions(exe_path=exe, map_path=mzre_map, ida_listing_path=ida_lst, module="egame.exe")

    assert catalog["schema"] == "dosunit.functions.v1"
    assert catalog["program_kind"] == "mz_exe"
    by_id = {item["id"]: item for item in catalog["functions"]}
    assert by_id["egame.exe:main"]["entry"]["offset"] == "0x0010"
    assert by_id["egame.exe:main"]["entry"]["segment_para"] == "0x0000"
    assert by_id["egame.exe:main"]["confidence"] == "high"
    assert by_id["egame.exe:lookupSineFar"]["return_kind"] == "far"
    assert by_id["egame.exe:__exit"]["entry"]["offset"] == "0xe5bf"
    assert catalog["segments"][1]["name"] == "Data1"
    assert catalog["segments"][1]["paragraph"] == "0x228b"


def test_dosunit_discovers_msc_cod_listing_with_linked_object_delta(tmp_path: Path):
    exe = tmp_path / "DEMO.EXE"
    exe.write_bytes(_mz_exe(b"\x00" * 0x10 + bytes.fromhex("55 8b ec e8 34 12 5d c3")))
    link_map = _write(
        tmp_path / "DEMO.MAP",
        "\n".join(
            [
                " Start  Stop   Length Name                   Class",
                " 00000H 000FFH 00100H _TEXT                  CODE",
                "",
                "Program entry point at 0000:0020",
            ]
        ),
    )
    cod = _write(
        tmp_path / "DEMO.COD",
        "\n".join(
            [
                "_TEXT      SEGMENT",
                "    PUBLIC  _foo",
                "_foo PROC NEAR",
                "    *** 000000 55             push    bp",
                "    *** 000001 8b ec          mov     bp,sp",
                "    *** 000003 e8 00 00       call    __aNchkstk",
                "    *** 000006 5d             pop     bp",
                "    *** 000007 c3             ret",
                "_foo ENDP",
            ]
        ),
    )

    catalog = discover_functions(exe_path=exe, map_path=link_map, cod_listing_path=cod, module="demo.exe")

    by_id = {item["id"]: item for item in catalog["functions"]}
    assert by_id["demo.exe:foo"]["entry"]["offset"] == "0x0010"
    assert by_id["demo.exe:foo"]["entry"]["segment_para"] == "0x0000"
    assert by_id["demo.exe:foo"]["entry"]["linear"] == "0x10"
    assert by_id["demo.exe:foo"]["size"] == 8
    assert by_id["demo.exe:foo"]["sources"] == ["cod_listing"]


def test_dosunit_imports_libdosbox_runtime_json_as_priorities(tmp_path: Path):
    functions = {
        "schema": "dosunit.functions.v1",
        "id": "functions:test",
        "module": "egame.exe",
        "program_kind": "mz_exe",
        "functions": [
            {
                "id": "egame.exe:hot_func",
                "names": ["hot_func"],
                "entry": {"kind": "module_relative", "segment": "seg000", "offset": "0x0010", "linear": "0x1a20"},
                "return_kind": "near",
                "sources": ["fixture"],
                "confidence": "medium",
                "size": 0x20,
                "safe_traps": [],
            }
        ],
        "diagnostics": [],
    }
    trace = {
        "Meta": {"DosboxLoadSeg": 0x192, "ImageSizeBytes": 0x100},
        "Code": {
            "0x1a23": {
                "cs": [0x192],
                "ds": [0x200],
                "es": [0x192],
                "ss": [0x192],
                "ExecCount": 5,
                "Accdat": [0x3000],
            }
        },
        "AccessSites": {
            "0x1": {
                "Csip": "0x1a23",
                "MinAddr": "0x3000",
                "MaxAddr": "0x3002",
                "Count": 4,
                "RwMask": 3,
                "SizeMask": 2,
                "ValueClasses": ["data_offset"],
                "Samples": [{"Addr": "0x3000", "Value": 1}],
            }
        },
    }
    functions_path = tmp_path / "functions.json"
    trace_path = tmp_path / "trace.json"
    functions_path.write_text(json.dumps(functions))
    trace_path.write_text(json.dumps(trace))

    imported = import_libdosbox_trace(trace_path=trace_path, functions_path=functions_path)

    assert imported["schema"] == "dosunit.libdosbox_import.v1"
    assert imported["priorities"][0]["function_id"] == "egame.exe:hot_func"
    assert imported["priorities"][0]["module_offset"] == "0x103"
    assert imported["access_ranges"][0]["rw_mask"] == 3
    assert imported["refusals"][0]["reason"] == "oracle_unavailable"


def test_dosunit_generate_entry_vectors_uses_z3_seed(tmp_path: Path):
    catalog = {
        "schema": "dosunit.functions.v1",
        "id": "functions:test",
        "module": "demo.exe",
        "program_kind": "mz_exe",
        "functions": [
            {
                "id": "demo.exe:leaf",
                "names": ["leaf"],
                "entry": {"kind": "module_relative", "segment": "seg000", "segment_para": "0x1000", "offset": "0x0020"},
                "return_kind": "near",
                "sources": ["fixture"],
                "confidence": "medium",
                "size": 4,
                "safe_traps": [],
            }
        ],
        "diagnostics": [],
    }

    generated = generate_vectors(functions_catalog=catalog, strategy="entry")

    vector = generated["vectors"][0]
    assert generated["counters"]["vectors_emitted"] == 1
    assert vector["source"]["kind"] == "z3"
    assert vector["pre"]["regs"]["sp"] == "0xff00"
    assert vector["pre"]["regs"]["flags"] == "0x0202"
    assert vector["function"]["entry"]["cs"] == "0x1000"
    assert vector["id"].startswith("vector:")


def test_dosunit_generate_edge_vectors_for_simple_cmp_ax_jcc(tmp_path: Path):
    image = bytearray(0x240)
    image[0x200:0x206] = b"\x3d\x34\x12\x74\x01\xc3"  # cmp ax, 0x1234; je +1; ret
    exe = tmp_path / "demo.exe"
    exe.write_bytes(_mz_exe(bytes(image)))
    catalog = {
        "schema": "dosunit.functions.v1",
        "id": "functions:test",
        "module": "demo.exe",
        "program_kind": "mz_exe",
        "functions": [
            {
                "id": "demo.exe:branch",
                "names": ["branch"],
                "entry": {"kind": "module_relative", "segment": "seg000", "segment_para": "0x0000", "offset": "0x0200"},
                "return_kind": "near",
                "sources": ["fixture"],
                "confidence": "medium",
                "size": 6,
                "safe_traps": [],
            }
        ],
        "diagnostics": [],
    }

    generated = generate_vectors(functions_catalog=catalog, exe_path=exe, strategy="edge", max_vectors_per_function=2)

    assert generated["counters"]["vectors_emitted"] == 2
    assert generated["counters"]["branches_seen"] == 1
    assert generated["counters"]["edge_sources"] == {"lifter_vex": 1}
    assert generated["counters"]["lifter_blocks_lifted"] > 0
    assert {vector["pre"]["regs"]["ax"] for vector in generated["vectors"]} == {"0x1234", "0x1235"}
    assert generated["vectors"][0]["source"]["origin"] == "original_side_branch_solver"
    assert generated["vectors"][0]["source"]["coverage"]["binary"] == "oracle"
    assert generated["vectors"][0]["source"]["coverage"]["kind"] == "edge"
    assert {vector["source"]["coverage"]["discovery_source"] for vector in generated["vectors"]} == {"lifter_vex"}


def test_dosunit_generate_edge_vectors_for_cmp_reg_reg_jne(tmp_path: Path):
    image = bytearray(0x240)
    image[0x200:0x205] = b"\x39\xcb\x75\x01\xc3"  # cmp bx, cx; jne +1; ret
    exe = tmp_path / "demo.exe"
    exe.write_bytes(_mz_exe(bytes(image)))
    catalog = _edge_catalog("demo.exe:reg_branch", "reg_branch", offset=0x0200, size=5)

    generated = generate_vectors(functions_catalog=catalog, exe_path=exe, strategy="edge", max_vectors_per_function=2)

    assert generated["counters"]["vectors_emitted"] == 2
    predicates = {vector["source"]["coverage"]["predicate"] for vector in generated["vectors"]}
    assert "bx != cx" in predicates
    assert "bx == cx" in predicates
    assert any(vector["pre"]["regs"]["bx"] != vector["pre"]["regs"]["cx"] for vector in generated["vectors"])
    assert any(vector["pre"]["regs"]["bx"] == vector["pre"]["regs"]["cx"] for vector in generated["vectors"])


def test_dosunit_generate_edge_vectors_for_test_reg_jz(tmp_path: Path):
    image = bytearray(0x240)
    image[0x200:0x205] = b"\x85\xc0\x74\x01\xc3"  # test ax, ax; jz +1; ret
    exe = tmp_path / "demo.exe"
    exe.write_bytes(_mz_exe(bytes(image)))
    catalog = _edge_catalog("demo.exe:test_branch", "test_branch", offset=0x0200, size=5)

    generated = generate_vectors(functions_catalog=catalog, exe_path=exe, strategy="edge", max_vectors_per_function=2)

    assert generated["counters"]["vectors_emitted"] == 2
    assert {vector["pre"]["regs"]["ax"] for vector in generated["vectors"]} == {"0x0000", "0x0001"}
    assert {vector["source"]["coverage"]["label"] for vector in generated["vectors"]} == {"taken", "fallthrough"}


def test_tiny_example_or_reg_reg_jz_becomes_zero_test(tmp_path: Path):
    image = bytearray(0x240)
    image[0x200:0x205] = b"\x09\xc0\x74\x01\xc3"  # or ax, ax; jz +1; ret
    exe = tmp_path / "demo.exe"
    exe.write_bytes(_mz_exe(bytes(image)))
    catalog = _edge_catalog("demo.exe:or_zero", "or_zero", offset=0x0200, size=5)

    generated = generate_vectors(functions_catalog=catalog, exe_path=exe, strategy="edge", max_vectors_per_function=2)

    assert generated["counters"]["vectors_emitted"] == 2
    assert {vector["pre"]["regs"]["ax"] for vector in generated["vectors"]} == {"0x0000", "0x0001"}
    assert {vector["source"]["coverage"]["predicate"] for vector in generated["vectors"]} == {
        "(ax & ax) == 0x0000",
        "(ax & ax) != 0x0000",
    }


def test_tiny_example_test_ax_imm_jnz_solves_bit_mask(tmp_path: Path):
    image = bytearray(0x240)
    image[0x200:0x207] = b"\xa9\x08\x00\x75\x01\xc3\xc3"  # test ax, 8; jnz +1; ret
    exe = tmp_path / "demo.exe"
    exe.write_bytes(_mz_exe(bytes(image)))
    catalog = _edge_catalog("demo.exe:bit_test", "bit_test", offset=0x0200, size=7)

    generated = generate_vectors(functions_catalog=catalog, exe_path=exe, strategy="edge", max_vectors_per_function=2)

    assert generated["counters"]["vectors_emitted"] == 2
    assert {vector["pre"]["regs"]["ax"] for vector in generated["vectors"]} == {"0x0000", "0x0008"}
    assert {vector["source"]["coverage"]["label"] for vector in generated["vectors"]} == {"taken", "fallthrough"}


def test_tiny_example_cmp_al_imm_jcc_solves_partial_register(tmp_path: Path):
    image = bytearray(0x240)
    image[0x200:0x205] = b"\x3c\x12\x74\x01\xc3"  # cmp al, 0x12; je +1; ret
    exe = tmp_path / "demo.exe"
    exe.write_bytes(_mz_exe(bytes(image)))
    catalog = _edge_catalog("demo.exe:byte_cmp", "byte_cmp", offset=0x0200, size=5)

    generated = generate_vectors(functions_catalog=catalog, exe_path=exe, strategy="edge", max_vectors_per_function=2)

    assert generated["counters"]["vectors_emitted"] == 2
    assert {vector["pre"]["regs"]["ax"] for vector in generated["vectors"]} == {"0x0012", "0x0013"}
    assert {vector["source"]["coverage"]["predicate"] for vector in generated["vectors"]} == {
        "al == 0x12",
        "al != 0x12",
    }


def test_dosunit_edge_generation_reports_byte_decoder_fallback(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    image = bytearray(0x240)
    image[0x200:0x206] = b"\x3d\x34\x12\x74\x01\xc3"  # cmp ax, 0x1234; je +1; ret
    exe = tmp_path / "demo.exe"
    exe.write_bytes(_mz_exe(bytes(image)))
    catalog = _edge_catalog("demo.exe:fallback_branch", "fallback_branch", offset=0x0200, size=6)

    def _fail_lifter_project(_exe_path: Path):
        raise RuntimeError("forced lifter failure")

    monkeypatch.setattr(ir_edges, "_load_lifter_project", _fail_lifter_project)

    generated = generate_vectors(functions_catalog=catalog, exe_path=exe, strategy="edge", max_vectors_per_function=2)

    assert generated["counters"]["vectors_emitted"] == 2
    assert generated["counters"]["edge_sources"] == {"byte_decoder": 1}
    assert generated["counters"]["edge_fallback_diagnostics"] == 1
    assert generated["counters"]["lifter_blocks_lifted"] == 0
    assert {vector["source"]["coverage"]["discovery_source"] for vector in generated["vectors"]} == {"byte_decoder"}


def test_dosunit_generate_edge_vectors_refuses_unsupported_control_and_memory(tmp_path: Path):
    image = bytearray(0x280)
    image[0x200:0x202] = b"\xff\xe0"  # jmp ax
    image[0x240:0x247] = b"\x83\x3e\x00\x03\x00\x74\x01"  # cmp word [0x0300], 0; je +1
    exe = tmp_path / "demo.exe"
    exe.write_bytes(_mz_exe(bytes(image)))
    catalog = {
        "schema": "dosunit.functions.v1",
        "id": "functions:test",
        "module": "demo.exe",
        "program_kind": "mz_exe",
        "functions": [
            _edge_function("demo.exe:indirect", "indirect", offset=0x0200, size=2),
            _edge_function("demo.exe:memory", "memory", offset=0x0240, size=7),
        ],
        "diagnostics": [],
    }

    generated = generate_vectors(functions_catalog=catalog, exe_path=exe, strategy="edge", max_vectors_per_function=2)

    assert generated["counters"]["vectors_emitted"] == 0
    assert generated["counters"]["refusals_by_reason"]["unbounded_indirect_control"] == 1
    assert generated["counters"]["refusals_by_reason"]["unbounded_memory"] == 1


def test_dosunit_region_effects_capture_instruction_arguments_and_memory_effects(tmp_path: Path):
    image = bytearray(0x240)
    image[0x200:0x20B] = b"\x8b\x5c\x04\x01\xc3\x89\x55\xfe\x75\x01\xc3"
    exe = tmp_path / "demo.exe"
    exe.write_bytes(_mz_exe(bytes(image)))
    catalog = _edge_catalog("demo.exe:region", "region", offset=0x0200, size=0x0B)

    document = summarize_region_effects(exe_path=exe, functions_catalog=catalog, max_regions_per_function=4)

    assert document["schema"] == "dosunit.regions.v1"
    assert document["counters"]["regions_emitted"] >= 1
    assert document["counters"]["lifter_blocks_lifted"] > 0
    region = document["regions"][0]
    assert [instruction["mnemonic"] for instruction in region["instructions"]] == ["mov", "add", "mov", "jne"]
    assert region["instructions"][0]["operands"][1]["memory"] == {
        "space": "DS",
        "explicit_segment": None,
        "base": "si",
        "index": None,
        "scale": 1,
        "disp": "0x0004",
        "width": 16,
        "access": "read",
        "expr": "DS:[si + 0x0004]",
    }
    assert region["instructions"][2]["operands"][0]["memory"] == {
        "space": "DS",
        "explicit_segment": None,
        "base": "di",
        "index": None,
        "scale": 1,
        "disp": "-0x0002",
        "width": 16,
        "access": "write",
        "expr": "DS:[di - 0x0002]",
    }
    assert region["effects"]["memory_read"][0]["expr"] == "DS:[si + 0x0004]"
    assert region["effects"]["memory_written"][0]["expr"] == "DS:[di - 0x0002]"
    assert {exit_["kind"] for exit_ in region["exits"]} == {"taken", "fallthrough"}


def test_dosunit_region_compare_detects_changed_instruction_argument(tmp_path: Path):
    oracle_image = bytearray(0x240)
    candidate_image = bytearray(0x240)
    oracle_image[0x200:0x20B] = b"\x8b\x5c\x04\x01\xc3\x89\x55\xfe\x75\x01\xc3"  # [di-2]
    candidate_image[0x200:0x20B] = b"\x8b\x5c\x04\x01\xc3\x89\x56\xfe\x75\x01\xc3"  # [bp-2]
    oracle_exe = tmp_path / "oracle.exe"
    candidate_exe = tmp_path / "candidate.exe"
    oracle_exe.write_bytes(_mz_exe(bytes(oracle_image)))
    candidate_exe.write_bytes(_mz_exe(bytes(candidate_image)))
    catalog = _edge_catalog("demo.exe:region", "region", offset=0x0200, size=0x0B)
    oracle = summarize_region_effects(exe_path=oracle_exe, functions_catalog=catalog, max_regions_per_function=1)
    candidate = summarize_region_effects(exe_path=candidate_exe, functions_catalog=catalog, max_regions_per_function=1)

    comparison = compare_region_effect_documents(oracle=oracle, candidate=candidate)

    assert comparison["summary"]["failed"] == 1
    mismatches = comparison["results"][0]["mismatches"]
    assert any(item["kind"] == "instruction_operands_changed" for item in mismatches)
    assert any(item["kind"] == "instruction_effects_changed" for item in mismatches)
    operand_mismatch = next(item for item in mismatches if item["kind"] == "instruction_operands_changed")
    assert operand_mismatch["oracle"][0]["base"] == "di"
    assert operand_mismatch["candidate"][0]["base"] == "bp"
    assert operand_mismatch["candidate"][0]["space"] == "SS"
    report = render_failure_report(comparison)
    assert "instruction_operands_changed" in report
    assert "Oracle instruction" in report
    assert "0x0205" in report
    assert "mov word ptr [di - 2], dx" in report
    assert "mov word ptr [bp - 2], dx" in report
    assert '"base":"di"' in report
    assert '"base":"bp"' in report
    assert '"space":"SS"' in report


def test_dosunit_region_compare_normalizes_signed_branch_targets(tmp_path: Path):
    oracle_image = bytearray(0x240)
    candidate_image = bytearray(0x240)
    oracle_image[0x200:0x202] = b"\x7d\x01"  # jge target
    candidate_image[0x200:0x202] = b"\x7d\x03"  # same branch, different layout target
    oracle_exe = tmp_path / "oracle.exe"
    candidate_exe = tmp_path / "candidate.exe"
    oracle_exe.write_bytes(_mz_exe(bytes(oracle_image)))
    candidate_exe.write_bytes(_mz_exe(bytes(candidate_image)))
    catalog = _edge_catalog("demo.exe:branch", "branch", offset=0x0200, size=2)
    oracle = summarize_region_effects(exe_path=oracle_exe, functions_catalog=catalog, max_regions_per_function=1)
    candidate = summarize_region_effects(exe_path=candidate_exe, functions_catalog=catalog, max_regions_per_function=1)

    comparison = compare_region_effect_documents(oracle=oracle, candidate=candidate)

    assert comparison["summary"]["passed"] == 1
    assert comparison["results"][0]["mismatches"] == []


def test_dosunit_complexity_marks_simple_leaf_as_whole_function_part(tmp_path: Path):
    image = bytearray(0x240)
    image[0x200:0x206] = b"\x89\xd8\x83\xc0\x01\xc3"  # mov ax, bx; add ax, 1; ret
    exe = tmp_path / "demo.exe"
    exe.write_bytes(_mz_exe(bytes(image)))
    catalog = _edge_catalog("demo.exe:leaf_math", "leaf_math", offset=0x0200, size=6)

    document = analyze_function_complexity(exe_path=exe, functions_catalog=catalog)

    function = document["functions"][0]
    assert document["schema"] == "dosunit.complexity.v1"
    assert document["counters"]["simple_whole_functions"] == 1
    assert function["classification"] == "simple_whole_function"
    assert function["metrics"]["condition_count"] == 0
    assert function["metrics"]["call_count"] == 0
    assert function["comparison_parts"][0]["kind"] == "whole_function"
    assert function["comparison_parts"][0]["instruction_count"] == 3


def test_dosunit_complexity_blocks_conditional_function_from_whole_function_part(tmp_path: Path):
    image = bytearray(0x240)
    image[0x200:0x207] = b"\x3d\x01\x00\x75\x01\xc3\xc3"  # cmp ax, 1; jne +1; ret; ret
    exe = tmp_path / "demo.exe"
    exe.write_bytes(_mz_exe(bytes(image)))
    catalog = _edge_catalog("demo.exe:branchy", "branchy", offset=0x0200, size=7)

    document = analyze_function_complexity(exe_path=exe, functions_catalog=catalog)

    function = document["functions"][0]
    assert function["classification"] == "complex"
    assert function["metrics"]["condition_count"] == 1
    assert any(blocker["kind"] == "conditions" for blocker in function["blockers"])
    assert function["comparison_parts"] == []
    assert function["risk_points"][0]["kinds"] == ["condition"]
    assert "jne" in function["risk_points"][0]["disassembly"]


def test_dosunit_complexity_counts_symbolic_segmented_memory(tmp_path: Path):
    image = bytearray(0x240)
    image[0x200:0x204] = b"\x8b\x44\x04\xc3"  # mov ax, [si+4]; ret
    exe = tmp_path / "demo.exe"
    exe.write_bytes(_mz_exe(bytes(image)))
    catalog = _edge_catalog("demo.exe:load_indexed", "load_indexed", offset=0x0200, size=4)

    document = analyze_function_complexity(exe_path=exe, functions_catalog=catalog)

    function = document["functions"][0]
    assert function["classification"] == "complex"
    assert function["metrics"]["explicit_symbolic_memory_count"] == 1
    assert any(blocker["kind"] == "symbolic_memory" for blocker in function["blockers"])
    assert any("symbolic_memory" in point["kinds"] for point in function["risk_points"])


def test_dosunit_cli_complexity_writes_report(tmp_path: Path):
    image = bytearray(0x240)
    image[0x200:0x207] = b"\x3d\x01\x00\x75\x01\xc3\xc3"  # cmp ax, 1; jne +1; ret; ret
    exe = tmp_path / "demo.exe"
    exe.write_bytes(_mz_exe(bytes(image)))
    catalog = _edge_catalog("demo.exe:branchy", "branchy", offset=0x0200, size=7)
    functions_path = tmp_path / "functions.json"
    out_path = tmp_path / "complexity.json"
    report_path = tmp_path / "complexity.md"
    functions_path.write_text(json.dumps(catalog))

    rc = dosunit_main(["complexity", "--exe", str(exe), "--functions", str(functions_path), "--out", str(out_path)])

    assert rc == 0
    document = json.loads(out_path.read_text())
    assert document["schema"] == "dosunit.complexity.v1"
    assert document["counters"]["complex_functions"] == 1
    assert dosunit_main(["report-failures", "--results", str(out_path), "--out", str(report_path)]) == 0
    report = report_path.read_text()
    assert "Complex Functions" in report
    assert "branchy" in report
    assert "conditions" in report
    assert "jne" in report
    assert "0x0203" in report


def test_dosunit_straightline_ssa_drops_flag_noise_and_return_ip_load(tmp_path: Path):
    image = bytearray(0x240)
    image[0x200:0x206] = b"\x89\xd8\x83\xc0\x01\xc3"  # mov ax, bx; add ax, 1; ret
    exe = tmp_path / "demo.exe"
    exe.write_bytes(_mz_exe(bytes(image)))
    catalog = _edge_catalog("demo.exe:leaf_math", "leaf_math", offset=0x0200, size=6)

    document = lower_straightline_ssa_document(exe_path=exe, functions_catalog=catalog, output_regs=("ax", "bx"))

    assert document["schema"] == "dosunit.ssa.v1"
    assert document["counters"]["functions_lowered"] == 1
    function = document["functions"][0]
    assert set(function["outputs"]) == {"ax", "bx"}
    assert function["outputs"]["bx"] == {"op": "input", "name": "bx", "width": 16}
    serialized = json.dumps(function["assignments"], sort_keys=True)
    assert "add" in serialized
    assert "flags" not in serialized
    assert "load" not in serialized.lower()


def test_dosunit_straightline_ssa_follows_short_boring_vex_fallthrough(tmp_path: Path):
    image = bytearray(0x240)
    image[0x200:0x205] = b"\x55\x8b\xec\x5d\xc3"  # push bp; mov bp, sp; pop bp; ret
    exe = tmp_path / "demo.exe"
    exe.write_bytes(_mz_exe(bytes(image)))
    catalog = _edge_catalog("demo.exe:frame", "frame", offset=0x0200, size=5)

    document = lower_straightline_ssa_document(
        exe_path=exe,
        functions_catalog=catalog,
        output_regs=("sp", "bp", "ip"),
        max_blocks_per_function=8,
    )

    assert document["counters"]["functions_lowered"] == 1
    assert document["refusals"] == []
    lowered_ips = {part["entry"]["ip"] for part in document["functions"]}
    assert "0x0200" in lowered_ips
    assert any(part["source"]["jumpkind"] == "Ijk_Ret" for part in document["functions"])


def test_dosunit_straightline_ssa_extends_no_decode_at_range_end(tmp_path: Path):
    image = bytearray(0x240)
    image[0x200:0x203] = b"\xd1\xd2\xc3"  # rcl dx, 1; ret
    exe = tmp_path / "demo.exe"
    exe.write_bytes(_mz_exe(bytes(image)))
    catalog = _edge_catalog("demo.exe:split_instruction", "split_instruction", offset=0x0200, size=1)

    document = lower_straightline_ssa_document(
        exe_path=exe,
        functions_catalog=catalog,
        output_regs=("dx",),
        max_blocks_per_function=4,
        scan_limit=2,
    )

    assert document["counters"]["functions_lowered"] == 1
    assert document["refusals"] == []
    assert document["functions"][0]["source"]["instructions"][0]["disassembly"] == "rcl dx, 1"


def test_dosunit_straightline_ssa_relifts_epilogue_when_ret_is_just_past_range(tmp_path: Path):
    image = bytearray(0x240)
    image[0x200:0x205] = b"\x83\xc4\x04\x5d\xc3"  # add sp, 4; pop bp; ret
    exe = tmp_path / "demo.exe"
    exe.write_bytes(_mz_exe(bytes(image)))
    catalog = _edge_catalog("demo.exe:epilogue", "epilogue", offset=0x0200, size=4)

    document = lower_straightline_ssa_document(
        exe_path=exe,
        functions_catalog=catalog,
        output_regs=("sp", "bp"),
        max_blocks_per_function=4,
        scan_limit=8,
    )

    assert document["counters"]["functions_lowered"] == 1
    assert document["refusals"] == []
    assert len(document["functions"]) == 1
    function = document["functions"][0]
    assert function["source"]["jumpkind"] == "Ijk_Ret"
    assert [item["disassembly"] for item in function["source"]["instructions"]] == ["add sp, 4", "pop bp", "ret"]


def test_dosunit_straightline_ssa_drops_dead_vex_register_slice(tmp_path: Path):
    image = bytearray(0x240)
    image[0x200:0x205] = b"\xd1\xd0\x89\xcb\xc3"  # rcl ax, 1; mov bx, cx; ret
    exe = tmp_path / "demo.exe"
    exe.write_bytes(_mz_exe(bytes(image)))
    catalog = _edge_catalog("demo.exe:dead_rotate", "dead_rotate", offset=0x0200, size=5)

    document = lower_straightline_ssa_document(
        exe_path=exe,
        functions_catalog=catalog,
        output_regs=("bx",),
        max_assignments_per_function=4,
    )

    assert document["counters"]["functions_lowered"] == 1
    function = document["functions"][0]
    assert function["outputs"]["bx"] == {"op": "input", "name": "cx", "width": 16}
    serialized = json.dumps(function["assignments"], sort_keys=True)
    assert "rcl" not in serialized
    assert "flags" not in serialized


def test_dosunit_straightline_ssa_lifts_neg_rm8_flags(tmp_path: Path):
    image = bytearray(0x240)
    image[0x200:0x205] = b"\xb1\x02\xf6\xd9\xc3"  # mov cl, 2; neg cl; ret
    exe = tmp_path / "demo.exe"
    exe.write_bytes(_mz_exe(bytes(image)))
    catalog = _edge_catalog("demo.exe:neg8", "neg8", offset=0x0200, size=5)

    document = lower_straightline_ssa_document(exe_path=exe, functions_catalog=catalog, output_regs=("cx",))

    assert document["counters"]["functions_lowered"] == 1
    assert document["counters"]["functions_refused"] == 0
    assert document["refusals"] == []
    function = document["functions"][0]
    assert "cx" in function["outputs"]
    assert "sub" in json.dumps(function["assignments"], sort_keys=True)


def test_dosunit_straightline_ssa_summarizes_rep_stosw(tmp_path: Path):
    image = bytearray(0x240)
    image[0x200:0x203] = b"\xf3\xab\xc3"  # rep stosw; ret
    exe = tmp_path / "demo.exe"
    exe.write_bytes(_mz_exe(bytes(image)))
    catalog = _edge_catalog("demo.exe:fill", "fill", offset=0x0200, size=3)

    document = lower_straightline_ssa_document(
        exe_path=exe,
        functions_catalog=catalog,
        output_regs=("cx", "di", "ip"),
        max_blocks_per_function=4,
        follow_call_fallthrough=True,
    )

    assert document["counters"]["ssa_parts_refused"] == 0
    assert document["counters"]["ssa_parts_lowered"] >= 1
    repeat_block = document["functions"][0]
    assert repeat_block["summary"]["kind"] == "repeat_string"
    assert repeat_block["summary"]["family"] == "stos"
    assert repeat_block["source"]["transfer"]["summary"] == "repeat_string"
    assert "memory" in repeat_block["outputs"]
    assert "summary_rep_stos16_memory" in json.dumps(repeat_block["assignments"], sort_keys=True)
    lowered_ips = {part["entry"]["ip"] for part in document["functions"]}
    assert lowered_ips == {"0x0200", "0x0202"}


def test_dosunit_straightline_ssa_does_not_follow_dos_terminate_interrupt(tmp_path: Path):
    image = bytearray(0x240)
    image[0x200:0x209] = bytes.fromhex("b8 00 4c cd 21 b8 34 12 c3")
    exe = tmp_path / "demo.exe"
    exe.write_bytes(_mz_exe(bytes(image)))
    catalog = _edge_catalog("demo.exe:terminate", "terminate", offset=0x0200, size=9)

    document = lower_straightline_ssa_document(
        exe_path=exe,
        functions_catalog=catalog,
        output_regs=("ax",),
        max_blocks_per_function=4,
        follow_call_fallthrough=True,
    )

    assert document["counters"]["ssa_parts_refused"] == 0
    assert document["counters"]["ssa_parts_lowered"] == 1
    block = document["functions"][0]
    assert block["entry"]["ip"] == "0x0200"
    assert block["source"]["transfer"] == {
        "kind": "nonreturning_interrupt",
        "jumpkind": "Ijk_Call",
        "interrupt": "0x21",
        "dos_function": "0x4c",
        "effect": "process_terminate",
    }


def test_dosunit_straightline_ssa_summarizes_rep_movsb(tmp_path: Path):
    image = bytearray(0x240)
    image[0x200:0x203] = b"\xf3\xa4\xc3"  # rep movsb; ret
    exe = tmp_path / "demo.exe"
    exe.write_bytes(_mz_exe(bytes(image)))
    catalog = _edge_catalog("demo.exe:copy", "copy", offset=0x0200, size=3)

    document = lower_straightline_ssa_document(
        exe_path=exe,
        functions_catalog=catalog,
        output_regs=("cx", "si", "di", "ip"),
        max_blocks_per_function=4,
        follow_call_fallthrough=True,
    )

    assert document["counters"]["ssa_parts_refused"] == 0
    repeat_block = document["functions"][0]
    assert repeat_block["summary"]["kind"] == "repeat_string"
    assert repeat_block["summary"]["family"] == "movs"
    assert "memory" in repeat_block["outputs"]
    assert "summary_rep_movs8_memory" in json.dumps(repeat_block["assignments"], sort_keys=True)
    lowered_ips = {part["entry"]["ip"] for part in document["functions"]}
    assert lowered_ips == {"0x0200", "0x0202"}


def test_dosunit_straightline_ssa_summarizes_repne_scasb(tmp_path: Path):
    image = bytearray(0x240)
    image[0x200:0x203] = b"\xf2\xae\xc3"  # repne scasb; ret
    exe = tmp_path / "demo.exe"
    exe.write_bytes(_mz_exe(bytes(image)))
    catalog = _edge_catalog("demo.exe:scan", "scan", offset=0x0200, size=3)

    document = lower_straightline_ssa_document(
        exe_path=exe,
        functions_catalog=catalog,
        output_regs=("cx", "di", "ip"),
        max_blocks_per_function=4,
        follow_call_fallthrough=True,
    )

    assert document["counters"]["ssa_parts_refused"] == 0
    repeat_block = document["functions"][0]
    assert repeat_block["summary"]["kind"] == "repeat_string"
    assert repeat_block["summary"]["family"] == "scas"
    assert "flags" in repeat_block["outputs"]
    assert "memory" not in repeat_block["outputs"]
    assert "summary_repne_scas8_flags" in json.dumps(repeat_block["assignments"], sort_keys=True)
    lowered_ips = {part["entry"]["ip"] for part in document["functions"]}
    assert lowered_ips == {"0x0200", "0x0202"}


def test_dosunit_straightline_ssa_defaults_module_relative_missing_segment_para(tmp_path: Path):
    image = bytearray(0x240)
    image[0x200:0x204] = b"\xb8\x34\x12\xc3"  # mov ax, 0x1234; ret
    exe = tmp_path / "demo.exe"
    exe.write_bytes(_mz_exe(bytes(image)))
    catalog = _edge_catalog("demo.exe:segless", "segless", offset=0x0200, size=4)
    del catalog["functions"][0]["entry"]["segment_para"]

    document = lower_straightline_ssa_document(exe_path=exe, functions_catalog=catalog, output_regs=("ax",))

    assert document["counters"]["functions_lowered"] == 1
    assert document["refusals"] == []
    assert document["functions"][0]["entry"]["cs"] == "0x0000"


def test_dosunit_straightline_ssa_resolves_named_segment_from_catalog_table(tmp_path: Path):
    image = bytearray(0x420)
    image[0x300:0x304] = b"\xb8\x34\x12\xc3"  # mov ax, 0x1234; ret at linked 0x1300
    exe = tmp_path / "demo.exe"
    exe.write_bytes(_mz_exe(bytes(image)))
    catalog = {
        "schema": "dosunit.functions.v1",
        "module": "demo.exe",
        "program_kind": "mz_exe",
        "segments": [{"name": "seg001", "class": "CODE", "paragraph": "0x0010"}],
        "functions": [
            {
                "id": "demo.exe:segmented",
                "names": ["segmented"],
                "entry": {"kind": "module_relative", "segment": "seg001", "offset": "0x0200"},
                "return_kind": "near",
                "sources": ["fixture"],
                "confidence": "medium",
                "size": 4,
                "safe_traps": [],
            }
        ],
    }

    document = lower_straightline_ssa_document(exe_path=exe, functions_catalog=catalog, output_regs=("ax",))

    assert document["counters"]["functions_lowered"] == 1
    assert document["refusals"] == []
    function = document["functions"][0]
    assert function["entry"]["cs"] == "0x0010"
    assert function["entry"]["linear"] == "0x1300"


def test_dosunit_straightline_ssa_models_port_output_as_io_observable(tmp_path: Path):
    image = bytearray(0x240)
    image[0x200:0x205] = b"\xb0\x36\xe6\x43\xc3"  # mov al, 0x36; out 0x43, al; ret
    exe = tmp_path / "demo.exe"
    exe.write_bytes(_mz_exe(bytes(image)))
    catalog = _edge_catalog("demo.exe:timer", "timer", offset=0x0200, size=5)

    document = lower_straightline_ssa_document(exe_path=exe, functions_catalog=catalog, output_regs=("sp",))

    assert document["counters"]["functions_lowered"] == 1
    assert document["refusals"] == []
    function = document["functions"][0]
    assert "io" in function["outputs"]
    assert {"kind": "memory", "name": "io", "addr_width": 32, "value_width": 8} in function["inputs"]
    assert "summary_io_out" in json.dumps(function["assignments"], sort_keys=True)


def test_dosunit_straightline_ssa_models_port_input_as_symbolic_io_value(tmp_path: Path):
    image = bytearray(0x240)
    image[0x200:0x205] = b"\xba\xda\x03\xec\xc3"  # mov dx, 0x03da; in al, dx; ret
    exe = tmp_path / "demo.exe"
    exe.write_bytes(_mz_exe(bytes(image)))
    catalog = _edge_catalog("demo.exe:status", "status", offset=0x0200, size=5)

    document = lower_straightline_ssa_document(exe_path=exe, functions_catalog=catalog, output_regs=("ax",))

    assert document["counters"]["functions_lowered"] == 1
    assert document["refusals"] == []
    function = document["functions"][0]
    assert "ax" in function["outputs"]
    assert {"kind": "memory", "name": "io", "addr_width": 32, "value_width": 8} in function["inputs"]
    assert "summary_io_in" in json.dumps(function["assignments"], sort_keys=True)


def test_dosunit_straightline_ssa_models_arch_dflag_register_offset():
    expr = straightline_ssa._read_register({}, 52, 32, source="AIL")

    assert not isinstance(expr, straightline_ssa.LowerFailure)
    assert expr.op == "input"
    assert expr.name == "dflag"
    assert expr.width == 32


def test_dosunit_compare_ssa_fails_changed_port_output_value(tmp_path: Path):
    oracle_image = bytearray(0x240)
    candidate_image = bytearray(0x240)
    oracle_image[0x200:0x205] = b"\xb0\x36\xe6\x43\xc3"  # mov al, 0x36; out 0x43, al; ret
    candidate_image[0x200:0x205] = b"\xb0\x37\xe6\x43\xc3"  # mov al, 0x37; out 0x43, al; ret
    oracle_exe = tmp_path / "oracle.exe"
    candidate_exe = tmp_path / "candidate.exe"
    oracle_exe.write_bytes(_mz_exe(bytes(oracle_image)))
    candidate_exe.write_bytes(_mz_exe(bytes(candidate_image)))
    catalog = _edge_catalog("demo.exe:timer", "timer", offset=0x0200, size=5)
    oracle = lower_straightline_ssa_document(exe_path=oracle_exe, functions_catalog=catalog, output_regs=("sp",))
    candidate = lower_straightline_ssa_document(exe_path=candidate_exe, functions_catalog=catalog, output_regs=("sp",))

    compared = compare_ssa_documents(oracle=oracle, candidate=candidate)

    assert compared["summary"]["failed"] == 1
    mismatch_kinds = {
        mismatch.get("kind")
        for result in compared["results"]
        for mismatch in result.get("mismatches", []) or []
    }
    assert "memory_expr_changed" in mismatch_kinds


def test_dosunit_straightline_ssa_follows_declared_function_chunk(tmp_path: Path):
    image = bytearray(0x240)
    image[0x200:0x204] = b"\xb8\x34\x12\xc3"  # mov ax, 0x1234; ret
    image[0x220:0x223] = b"\xe9\xdd\xff"  # jmp 0x0200
    exe = tmp_path / "demo.exe"
    exe.write_bytes(_mz_exe(bytes(image)))
    catalog = _edge_catalog("demo.exe:chunked", "chunked", offset=0x0220, size=3)
    catalog["functions"][0]["ranges"] = [
        {
            "kind": "function_chunk",
            "segment": "seg000",
            "offset": "0x0200",
            "size": 4,
            "end_offset": "0x0203",
            "source": "fixture",
        }
    ]

    document = lower_straightline_ssa_document(
        exe_path=exe,
        functions_catalog=catalog,
        output_regs=("ax",),
        max_blocks_per_function=4,
    )

    assert document["refusals"] == []
    lowered_ips = {part["entry"]["ip"] for part in document["functions"]}
    assert lowered_ips == {"0x0200", "0x0220"}


def test_dosunit_straightline_ssa_follows_sizeless_tail_jump(tmp_path: Path):
    image = bytearray(0x240)
    image[0x200:0x204] = b"\xb8\x34\x12\xc3"  # mov ax, 0x1234; ret
    image[0x220:0x223] = b"\xe9\xdd\xff"  # jmp 0x0200
    exe = tmp_path / "demo.exe"
    exe.write_bytes(_mz_exe(bytes(image)))
    catalog = _edge_catalog("demo.exe:tail_jumper", "tail_jumper", offset=0x0220, size=3)
    catalog["functions"][0]["size"] = None

    document = lower_straightline_ssa_document(
        exe_path=exe,
        functions_catalog=catalog,
        output_regs=("ax",),
        max_blocks_per_function=4,
        scan_limit=0x40,
    )

    assert document["refusals"] == []
    lowered_ips = {part["entry"]["ip"] for part in document["functions"]}
    assert lowered_ips == {"0x0200", "0x0220"}


def test_dosunit_straightline_ssa_follows_sized_external_tail_jump(tmp_path: Path):
    image = bytearray(0x240)
    image[0x200:0x204] = b"\xb8\x34\x12\xc3"  # mov ax, 0x1234; ret
    image[0x220:0x223] = b"\xe9\xdd\xff"  # jmp 0x0200
    exe = tmp_path / "demo.exe"
    exe.write_bytes(_mz_exe(bytes(image)))
    catalog = _edge_catalog("demo.exe:sized_tail_jumper", "sized_tail_jumper", offset=0x0220, size=3)

    document = lower_straightline_ssa_document(
        exe_path=exe,
        functions_catalog=catalog,
        output_regs=("ax",),
        max_blocks_per_function=4,
        scan_limit=0x40,
    )

    assert document["refusals"] == []
    lowered_ips = {part["entry"]["ip"] for part in document["functions"]}
    assert lowered_ips == {"0x0200", "0x0220"}


def test_dosunit_straightline_ssa_extends_boundary_epilogue_block(tmp_path: Path):
    image = bytearray(0x240)
    image[0x200:0x205] = b"\xeb\x01\x90\x5d\xc3"  # jmp 0x0203; nop; pop bp; ret
    exe = tmp_path / "demo.exe"
    exe.write_bytes(_mz_exe(bytes(image)))
    catalog = _edge_catalog("demo.exe:short_epilogue", "short_epilogue", offset=0x0200, size=4)

    document = lower_straightline_ssa_document(
        exe_path=exe,
        functions_catalog=catalog,
        output_regs=("sp", "bp"),
        max_blocks_per_function=4,
        scan_limit=0x20,
    )

    assert document["refusals"] == []
    lowered_ips = {part["entry"]["ip"] for part in document["functions"]}
    assert lowered_ips == {"0x0200", "0x0203"}
    assert any(part["source"]["jumpkind"] == "Ijk_Ret" for part in document["functions"])


def test_dosunit_straightline_ssa_reports_block_lift_timeout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    image = bytearray(0x240)
    image[0x200:0x204] = b"\xb8\x34\x12\xc3"  # mov ax, 0x1234; ret
    exe = tmp_path / "demo.exe"
    exe.write_bytes(_mz_exe(bytes(image)))
    catalog = _edge_catalog("demo.exe:timeout_leaf", "timeout_leaf", offset=0x0200, size=4)

    def _timeout_lift(**_kwargs: object) -> object:
        raise TimeoutError("fixture timeout")

    monkeypatch.setattr(straightline_ssa, "_lift_vex_block_cached", _timeout_lift)

    document = lower_straightline_ssa_document(exe_path=exe, functions_catalog=catalog, output_regs=("ax",), max_lift_block_ms=1)

    assert document["counters"]["functions_refused"] == 1
    assert document["refusals"][0]["reason"] == "timeout"
    assert "lifter block timed out" in document["refusals"][0]["detail"]["message"]


def test_dosunit_straightline_ssa_reports_block_lower_timeout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    image = bytearray(0x240)
    image[0x200:0x204] = b"\xb8\x34\x12\xc3"  # mov ax, 0x1234; ret
    exe = tmp_path / "demo.exe"
    exe.write_bytes(_mz_exe(bytes(image)))
    catalog = _edge_catalog("demo.exe:timeout_leaf", "timeout_leaf", offset=0x0200, size=4)
    cache_dir = tmp_path / "cache"
    warm = lower_straightline_ssa_document(
        exe_path=exe,
        functions_catalog=catalog,
        output_regs=("ax",),
        cache_dir=cache_dir,
        max_lift_block_ms=0,
    )
    assert warm["counters"]["functions_refused"] == 0

    def _timeout_lower(*_args: object, **_kwargs: object) -> object:
        time.sleep(1)
        return {}

    monkeypatch.setattr(straightline_ssa, "_lower_irsb", _timeout_lower)

    document = lower_straightline_ssa_document(
        exe_path=exe,
        functions_catalog=catalog,
        output_regs=("ax",),
        cache_dir=cache_dir,
        max_lift_block_ms=1,
    )

    assert document["counters"]["functions_refused"] == 1
    assert document["refusals"][0]["reason"] == "timeout"
    assert "SSA block lowering timed out" in document["refusals"][0]["detail"]["message"]
    assert document["refusals"][0]["detail"]["address"]["linear"] == "0x1200"


def test_dosunit_straightline_ssa_reports_function_timeout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    image = bytearray(0x240)
    image[0x200:0x204] = b"\xb8\x34\x12\xc3"  # mov ax, 0x1234; ret
    exe = tmp_path / "demo.exe"
    exe.write_bytes(_mz_exe(bytes(image)))
    catalog = _edge_catalog("demo.exe:slow_leaf", "slow_leaf", offset=0x0200, size=4)

    def _slow_lower(**_kwargs: object) -> object:
        time.sleep(1)
        return [], [], 0

    monkeypatch.setattr(straightline_ssa, "_lower_function", _slow_lower)

    document = lower_straightline_ssa_document(exe_path=exe, functions_catalog=catalog, output_regs=("ax",), max_function_ms=1)

    assert document["counters"]["functions_refused"] == 1
    assert document["refusals"][0]["reason"] == "timeout"
    assert "SSA function lowering exceeded timeout" in document["refusals"][0]["detail"]["message"]


def test_dosunit_compare_ssa_proves_equivalent_and_finds_counterexample(tmp_path: Path):
    original_image = bytearray(0x240)
    equivalent_image = bytearray(0x240)
    changed_image = bytearray(0x240)
    original_image[0x200:0x206] = b"\x89\xd8\x83\xc0\x01\xc3"  # mov ax, bx; add ax, 1; ret
    equivalent_image[0x200:0x204] = b"\x89\xd8\x40\xc3"  # mov ax, bx; inc ax; ret
    changed_image[0x200:0x206] = b"\x89\xd8\x83\xc0\x02\xc3"  # mov ax, bx; add ax, 2; ret
    original = tmp_path / "original.exe"
    equivalent = tmp_path / "equivalent.exe"
    changed = tmp_path / "changed.exe"
    original.write_bytes(_mz_exe(bytes(original_image)))
    equivalent.write_bytes(_mz_exe(bytes(equivalent_image)))
    changed.write_bytes(_mz_exe(bytes(changed_image)))
    original_catalog = _edge_catalog("demo.exe:leaf_math", "leaf_math", offset=0x0200, size=6)
    equivalent_catalog = _edge_catalog("demo.exe:leaf_math", "leaf_math", offset=0x0200, size=4)

    oracle = lower_straightline_ssa_document(
        exe_path=original, functions_catalog=original_catalog, output_regs=("ax", "bx")
    )
    equivalent_ssa = lower_straightline_ssa_document(
        exe_path=equivalent, functions_catalog=equivalent_catalog, output_regs=("ax", "bx")
    )
    changed_ssa = lower_straightline_ssa_document(
        exe_path=changed, functions_catalog=original_catalog, output_regs=("ax", "bx")
    )

    passed = compare_ssa_documents(oracle=oracle, candidate=equivalent_ssa)
    failed = compare_ssa_documents(oracle=oracle, candidate=changed_ssa)

    assert passed["summary"]["passed"] == 1
    assert failed["summary"]["failed"] == 1
    mismatch = failed["results"][0]["mismatches"][0]
    assert mismatch["kind"] == "output_expr_changed"
    assert mismatch["reg"] == "ax"
    assert mismatch["counterexample"]["bx"] == "0x0000"


def test_dosunit_compare_ssa_shortcuts_binary_equal_functions(tmp_path: Path):
    image = bytearray(0x240)
    image[0x200:0x204] = b"\xb8\x34\x12\xc3"  # mov ax, 0x1234; ret
    original = tmp_path / "original.exe"
    candidate = tmp_path / "candidate.exe"
    original.write_bytes(_mz_exe(bytes(image)))
    candidate.write_bytes(_mz_exe(bytes(image)))
    catalog = _edge_catalog("demo.exe:imm_leaf", "imm_leaf", offset=0x0200, size=4)

    oracle = lower_straightline_ssa_document(exe_path=original, functions_catalog=catalog, output_regs=("ax",))
    candidate_ssa = lower_straightline_ssa_document(exe_path=candidate, functions_catalog=catalog, output_regs=("ax",))
    compared = compare_ssa_documents(oracle=oracle, candidate=candidate_ssa)

    assert compared["summary"]["passed"] == 1
    assert compared["results"][0]["reason"] == "binary_equal"


def test_dosunit_compare_ssa_shortcuts_ssa_equal_when_bytes_differ():
    oracle_function = _ssa_stub("demo.exe:leaf", "leaf", ip="0x0200", linear="0x1200")
    candidate_function = _ssa_stub("demo.exe:leaf", "leaf", ip="0x0200", linear="0x1200")
    oracle_function["source"]["function_machine_code_sha256"] = "a" * 64
    oracle_function["source"]["function_machine_code_size"] = 4
    candidate_function["source"]["function_machine_code_sha256"] = "b" * 64
    candidate_function["source"]["function_machine_code_size"] = 4
    oracle = {"schema": "dosunit.ssa.v1", "exe": "oracle.exe", "functions": [oracle_function]}
    candidate = {"schema": "dosunit.ssa.v1", "exe": "candidate.exe", "functions": [candidate_function]}

    compared = compare_ssa_documents(oracle=oracle, candidate=candidate)

    assert compared["summary"]["passed"] == 1
    assert compared["results"][0]["reason"] == "ssa_equal"


def test_dosunit_compare_ssa_uses_full_index_document_for_batched_call_targets():
    oracle_caller = _ssa_call_boundary_function("demo.exe:caller", "caller")
    oracle_caller["source"]["transfer"]["target"] = {"raw": "0x1500", "low16": "0x1500"}
    oracle_caller["source"]["instructions"][0] = {
        "address": {"ip": "0x0200", "linear": "0x1200"},
        "disassembly": "call 0x1500",
        "mnemonic": "call",
        "op_str": "0x1500",
        "size": 3,
    }
    oracle_caller["outputs"]["call_target"] = {"op": "const", "value": "0x00001500", "width": 32}
    candidate_caller = _ssa_call_boundary_function("demo.exe:caller", "caller")
    candidate_caller["source"]["transfer"]["target"] = {"raw": "0x2500", "low16": "0x2500"}
    candidate_caller["source"]["instructions"][0] = {
        "address": {"ip": "0x0200", "linear": "0x1200"},
        "disassembly": "call 0x2500",
        "mnemonic": "call",
        "op_str": "0x2500",
        "size": 3,
    }
    candidate_caller["outputs"]["call_target"] = {"op": "const", "value": "0x00002500", "width": 32}
    oracle_callee = _ssa_stub("demo.exe:helper", "helper", ip="0x0500", linear="0x1500")
    candidate_callee = _ssa_stub("demo.exe:helper_rebuilt", "helper", ip="0x1500", linear="0x2500")
    oracle_callee["source"]["instructions"] = [
        {
            "address": {"ip": "0x0500", "linear": "0x1500"},
            "bytes": "e81200",
            "disassembly": "call 0x1515",
            "mnemonic": "call",
            "op_str": "0x1515",
            "size": 3,
        }
    ]
    oracle_callee["source"]["machine_code_sha256"] = "a" * 64
    oracle_callee["source"]["machine_code_size"] = 3
    candidate_callee["source"]["instructions"] = [
        {
            "address": {"ip": "0x1500", "linear": "0x2500"},
            "bytes": "e83412",
            "disassembly": "call 0x3737",
            "mnemonic": "call",
            "op_str": "0x3737",
            "size": 3,
        }
    ]
    candidate_callee["source"]["machine_code_sha256"] = "b" * 64
    candidate_callee["source"]["machine_code_size"] = 3
    oracle = {"schema": "dosunit.ssa.v1", "exe": "oracle.exe", "functions": [oracle_caller]}
    candidate = {"schema": "dosunit.ssa.v1", "exe": "candidate.exe", "functions": [candidate_caller, candidate_callee]}
    oracle_index = {"schema": "dosunit.ssa.v1", "exe": "oracle.exe", "functions": [oracle_caller, oracle_callee]}
    mapping = {
        "schema": "dosunit.mapping.v1",
        "functions": [
            {
                "oracle_id": "demo.exe:caller",
                "oracle_name": "caller",
                "candidate_id": "demo.exe:caller",
                "candidate_name": "caller",
            },
            {
                "oracle_id": "demo.exe:helper",
                "oracle_name": "helper",
                "candidate_id": "demo.exe:helper_rebuilt",
                "candidate_name": "helper",
            },
        ],
    }

    without_index = compare_ssa_documents(oracle=oracle, candidate=candidate, mapping_document=mapping)
    with_index = compare_ssa_documents(
        oracle=oracle,
        candidate=candidate,
        oracle_index_document=oracle_index,
        mapping_document=mapping,
    )

    assert without_index["summary"]["failed"] == 1
    assert with_index["summary"]["passed"] == 1
    assert with_index["results"][0]["call_compare"]["equivalent"] is True


def test_dosunit_compare_ssa_checks_all_same_entry_call_aliases_before_rejecting():
    oracle_caller = _ssa_call_boundary_function("demo.exe:caller", "caller")
    oracle_caller["source"]["transfer"]["target"] = {"raw": "0x1500", "low16": "0x1500"}
    oracle_caller["outputs"]["call_target"] = {"op": "const", "value": "0x00001500", "width": 32}
    candidate_caller = _ssa_call_boundary_function("demo.exe:caller", "caller")
    candidate_caller["source"]["transfer"]["target"] = {"raw": "0x2500", "low16": "0x2500"}
    candidate_caller["source"]["instructions"][0]["op_str"] = "0x2500"
    candidate_caller["source"]["instructions"][0]["disassembly"] = "call 0x2500"
    candidate_caller["outputs"]["call_target"] = {"op": "const", "value": "0x00002500", "width": 32}

    oracle_close_alias = _ssa_stub("demo.exe:closeFile", "closeFile", ip="0x0500", linear="0x1500")
    oracle_open_alias = _ssa_stub("demo.exe:openBlitClosePic", "openBlitClosePic", ip="0x0500", linear="0x1500")
    candidate_open = _ssa_stub("demo.exe:openBlitClosePic", "openBlitClosePic", ip="0x1500", linear="0x2500")
    for function, linear, target in (
        (oracle_close_alias, "0x1500", "0x1515"),
        (oracle_open_alias, "0x1500", "0x1515"),
        (candidate_open, "0x2500", "0x3737"),
    ):
        function["source"]["instructions"] = [
            {
                "address": {"ip": function["entry"]["ip"], "linear": linear},
                "bytes": "e81200" if target == "0x1515" else "e83412",
                "disassembly": f"call {target}",
                "mnemonic": "call",
                "op_str": target,
                "size": 3,
            }
        ]
        function["source"]["machine_code_sha256"] = str(function["function"]["name"])[0] * 64
        function["source"]["machine_code_size"] = 3
    oracle = {"schema": "dosunit.ssa.v1", "exe": "oracle.exe", "functions": [oracle_caller]}
    candidate = {"schema": "dosunit.ssa.v1", "exe": "candidate.exe", "functions": [candidate_caller, candidate_open]}
    oracle_index = {
        "schema": "dosunit.ssa.v1",
        "exe": "oracle.exe",
        "functions": [oracle_caller, oracle_close_alias, oracle_open_alias],
    }
    mapping = {
        "schema": "dosunit.mapping.v1",
        "functions": [
            {
                "oracle_id": "demo.exe:caller",
                "oracle_name": "caller",
                "candidate_id": "demo.exe:caller",
                "candidate_name": "caller",
            },
            {
                "oracle_id": "demo.exe:closeFile",
                "oracle_name": "closeFile",
                "candidate_id": "demo.exe:closeFile",
                "candidate_name": "closeFile",
            },
            {
                "oracle_id": "demo.exe:openBlitClosePic",
                "oracle_name": "openBlitClosePic",
                "candidate_id": "demo.exe:openBlitClosePic",
                "candidate_name": "openBlitClosePic",
            },
        ],
    }

    compared = compare_ssa_documents(
        oracle=oracle,
        candidate=candidate,
        oracle_index_document=oracle_index,
        mapping_document=mapping,
    )

    assert compared["summary"]["passed"] == 1
    assert compared["results"][0]["call_compare"]["reason"] in {
        "direct call targets are equivalent through function mapping",
        "direct call target entry blocks have identical layout-normalized block signatures",
    }


def test_dosunit_compare_ssa_normalizes_explicit_cs_relative_memory_operands():
    oracle_function = _ssa_stub("demo.exe:set_irq", "set_irq", ip="0x3c99", linear="0x4c99")
    candidate_function = _ssa_stub("demo.exe:set_irq", "set_irq", ip="0xc8e9", linear="0xd8e9")
    oracle_function["source"]["instructions"] = [
        {
            "address": {"ip": "0x3c99", "linear": "0x4c99"},
            "disassembly": "mov word ptr cs:[0x3d67], bx",
            "mnemonic": "mov",
            "op_str": "word ptr cs:[0x3d67], bx",
            "size": 5,
        },
        {
            "address": {"ip": "0x3c9e", "linear": "0x4c9e"},
            "disassembly": "mov word ptr cs:[0x3d69], es",
            "mnemonic": "mov",
            "op_str": "word ptr cs:[0x3d69], es",
            "size": 5,
        },
    ]
    candidate_function["source"]["instructions"] = [
        {
            "address": {"ip": "0xc8e9", "linear": "0xd8e9"},
            "disassembly": "mov word ptr cs:[0xc9bb], bx",
            "mnemonic": "mov",
            "op_str": "word ptr cs:[0xc9bb], bx",
            "size": 5,
        },
        {
            "address": {"ip": "0xc8ee", "linear": "0xd8ee"},
            "disassembly": "mov word ptr cs:[0xc9bd], es",
            "mnemonic": "mov",
            "op_str": "word ptr cs:[0xc9bd], es",
            "size": 5,
        },
    ]
    for function, first_addr, second_addr in (
        (oracle_function, "0x3d67", "0x3d69"),
        (candidate_function, "0xc9bb", "0xc9bd"),
    ):
        function["inputs"] = [
            {"kind": "memory", "name": "memory"},
            {"name": "bx", "width": 16},
            {"name": "es", "width": 16},
        ]
        function["assignments"] = [
            {
                "id": "v0",
                "op": "storele",
                "width": 0,
                "args": [
                    {"op": "mem_input", "name": "memory", "addr_width": 32, "value_width": 8},
                    {"op": "const", "value": first_addr, "width": 16},
                    {"op": "input", "name": "bx", "width": 16},
                ],
            },
            {
                "id": "v1",
                "op": "storele",
                "width": 0,
                "args": [
                    {"ref": "v0"},
                    {"op": "const", "value": second_addr, "width": 16},
                    {"op": "input", "name": "es", "width": 16},
                ],
            },
        ]
        function["outputs"] = {"memory": {"ref": "v1"}}

    compared = compare_ssa_documents(
        oracle=_ssa_doc(oracle_function),
        candidate=_ssa_doc(candidate_function),
        skip_binary_equal=False,
    )

    assert compared["summary"]["passed"] == 1
    assert compared["results"][0]["layout_normalization"]["pairs"][0]["reason"] == "code_segment_memory_operand"


def test_dosunit_compare_ssa_reports_passed_direct_successor_connectivity():
    oracle = {
        "schema": "dosunit.ssa.v1",
        "exe": "oracle.exe",
        "functions": [
            _ssa_block_stub("demo.exe:flow", "flow", base=0x1000, delta=0x0000, index=0, successors=[0x0004]),
            _ssa_block_stub("demo.exe:flow", "flow", base=0x1000, delta=0x0004, index=1),
        ],
    }
    candidate = {
        "schema": "dosunit.ssa.v1",
        "exe": "candidate.exe",
        "functions": [
            _ssa_block_stub("demo.exe:flow", "flow", base=0x2000, delta=0x0000, index=0, successors=[0x0004]),
            _ssa_block_stub("demo.exe:flow", "flow", base=0x2000, delta=0x0004, index=1),
        ],
    }

    compared = compare_ssa_documents(oracle=oracle, candidate=candidate)

    assert compared["summary"]["passed"] == 2
    assert compared["connectivity"]["status"] == "passed"
    assert compared["connectivity"]["edges_checked"] == 1


def test_dosunit_compare_ssa_fails_direct_successor_connectivity_mismatch():
    oracle = {
        "schema": "dosunit.ssa.v1",
        "exe": "oracle.exe",
        "functions": [
            _ssa_block_stub("demo.exe:flow", "flow", base=0x1000, delta=0x0000, index=0, successors=[0x0004]),
            _ssa_block_stub("demo.exe:flow", "flow", base=0x1000, delta=0x0004, index=1),
        ],
    }
    candidate = {
        "schema": "dosunit.ssa.v1",
        "exe": "candidate.exe",
        "functions": [
            _ssa_block_stub("demo.exe:flow", "flow", base=0x2000, delta=0x0000, index=0, successors=[0x0008]),
            _ssa_block_stub("demo.exe:flow", "flow", base=0x2000, delta=0x0004, index=1),
        ],
    }

    compared = compare_ssa_documents(oracle=oracle, candidate=candidate)

    assert compared["summary"]["passed"] == 1
    assert compared["summary"]["failed"] == 1
    assert compared["connectivity"]["status"] == "failed"
    failed = next(
        result
        for result in compared["results"]
        if result["function"]["name"] == "flow" and result["reason"] == "connectivity_mismatch"
    )
    assert failed["mismatches"][0]["kind"] == "connectivity_successor_mismatch"
    assert failed["mismatches"][0]["expected_candidate_successor_delta"] == "0x0004"
    assert failed["mismatches"][0]["candidate_successor_deltas"] == ["0x0008"]
    report = render_failure_report(compared)
    assert "Expected candidate successor delta: `0x0004`" in report
    assert "Candidate successor deltas: `0x0008`" in report


def test_dosunit_compare_ssa_reports_negative_successor_delta_without_crashing():
    oracle = {
        "schema": "dosunit.ssa.v1",
        "exe": "oracle.exe",
        "functions": [
            _ssa_block_stub("demo.exe:flow", "flow", base=0x1000, delta=0x0000, index=0, successors=[-0x0004]),
        ],
    }
    candidate = {
        "schema": "dosunit.ssa.v1",
        "exe": "candidate.exe",
        "functions": [
            _ssa_block_stub("demo.exe:flow", "flow", base=0x2000, delta=0x0000, index=0, successors=[-0x0004]),
        ],
    }

    compared = compare_ssa_documents(oracle=oracle, candidate=candidate, enable_region_equality=False)

    assert compared["connectivity"]["status"] == "refused"
    assert compared["connectivity"]["refusals"][0]["successor_delta"] == "-0x0004"


def test_dosunit_ssa_normalizes_16bit_vex_targets_to_loaded_linear_addresses():
    instructions = [
        {
            "address": {"ip": "0xf757", "linear": "0x10757"},
            "size": 2,
            "mnemonic": "jbe",
            "op_str": "0x1075d",
            "disassembly": "jbe 0xf75d (0x1075d)",
        }
    ]
    irsb = SimpleNamespace(
        jumpkind="Ijk_Boring",
        statements=[
            SimpleNamespace(tag="Ist_Exit", dst=SimpleNamespace(tag="Iex_Const", con=SimpleNamespace(value=0x075D)))
        ],
        next=SimpleNamespace(tag="Iex_Const", con=SimpleNamespace(value=0x0759)),
    )

    assert _ssa_block_successors(irsb, instructions) == [0x1075D, 0x10759]


def test_dosunit_ssa_disassembly_renders_jump_target_ip_and_linear():
    low_page = _instruction_text_from_record(
        {"linear": 0x6FE3, "size": 2, "mnemonic": "jne", "op_str": "0x6fe8"},
        function_base=0x1000,
    )
    high_page = _instruction_text_from_record(
        {"linear": 0x10757, "size": 2, "mnemonic": "jbe", "op_str": "0x1075d"},
        function_base=0x1000,
    )

    assert low_page["op_str"] == "0x6fe8"
    assert low_page["disassembly"] == "jne 0x5fe8 (0x6fe8)"
    assert high_page["op_str"] == "0x1075d"
    assert high_page["disassembly"] == "jbe 0xf75d (0x1075d)"


def test_dosunit_compare_ssa_normalizes_control_target_constants_by_successor_delta():
    oracle = _ssa_block_stub(
        "demo.exe:branch", "branch", base=0x10742, delta=0x000B, index=0, successors=[0x001B, 0x0017]
    )
    candidate = _ssa_block_stub(
        "demo.exe:branch", "branch", base=0x101CA, delta=0x000B, index=0, successors=[0x001B, 0x0017]
    )
    oracle["inputs"] = [{"name": "flags", "width": 16}]
    candidate["inputs"] = [{"name": "flags", "width": 16}]
    oracle["outputs"]["ip"] = {"ref": "v0"}
    oracle["assignments"] = [
        {
            "id": "v0",
            "op": "ite",
            "width": 16,
            "args": [
                {"op": "input", "name": "flags", "width": 16},
                {"op": "const", "value": "0x075d", "width": 16},
                {"op": "const", "value": "0x0759", "width": 16},
            ],
        }
    ]
    candidate["outputs"]["ip"] = {"ref": "v0"}
    candidate["assignments"] = [
        {
            "id": "v0",
            "op": "ite",
            "width": 16,
            "args": [
                {"op": "input", "name": "flags", "width": 16},
                {"op": "const", "value": "0x01e5", "width": 16},
                {"op": "const", "value": "0x01e1", "width": 16},
            ],
        }
    ]

    compared = compare_ssa_documents(
        oracle=_ssa_doc(oracle), candidate=_ssa_doc(candidate), enable_region_equality=False
    )

    assert compared["summary"]["failed"] == 0
    assert compared["summary"]["passed"] == 1
    assert compared["results"][0]["layout_normalization"]["kind"] == "layout_constants"


def test_dosunit_compare_ssa_region_equality_proves_cyclic_block_graph_with_layout_targets():
    oracle_blocks = [
        _ssa_block_stub("demo.exe:loop", "loop", base=0x10740, delta=0x0000, index=0, successors=[0x0004]),
        _ssa_block_stub("demo.exe:loop", "loop", base=0x10740, delta=0x0004, index=1, successors=[0x0004, 0x0008]),
        _ssa_block_stub("demo.exe:loop", "loop", base=0x10740, delta=0x0008, index=2),
    ]
    candidate_blocks = [
        _ssa_block_stub("demo.exe:loop", "loop", base=0x101C0, delta=0x0000, index=0, successors=[0x0004]),
        _ssa_block_stub("demo.exe:loop", "loop", base=0x101C0, delta=0x0004, index=1, successors=[0x0004, 0x0008]),
        _ssa_block_stub("demo.exe:loop", "loop", base=0x101C0, delta=0x0008, index=2),
    ]
    for block in [*oracle_blocks, *candidate_blocks]:
        block["source"]["machine_code_size"] = 1
        block["source"]["machine_code_sha256"] = "0" * 64
    oracle_blocks[1]["inputs"] = [{"name": "cx", "width": 16}]
    candidate_blocks[1]["inputs"] = [{"name": "cx", "width": 16}]
    oracle_blocks[1]["outputs"]["ip"] = {"ref": "v0"}
    candidate_blocks[1]["outputs"]["ip"] = {"ref": "v0"}
    oracle_blocks[1]["assignments"] = [
        {
            "id": "v0",
            "op": "ite",
            "width": 16,
            "args": [
                {"op": "input", "name": "cx", "width": 16},
                {"op": "const", "value": "0x0744", "width": 16},
                {"op": "const", "value": "0x0748", "width": 16},
            ],
        }
    ]
    candidate_blocks[1]["assignments"] = [
        {
            "id": "v0",
            "op": "ite",
            "width": 16,
            "args": [
                {"op": "input", "name": "cx", "width": 16},
                {"op": "const", "value": "0x01c4", "width": 16},
                {"op": "const", "value": "0x01c8", "width": 16},
            ],
        }
    ]

    compared = compare_ssa_documents(
        oracle={
            "schema": "dosunit.ssa.v1",
            "exe": "oracle.exe",
            "functions": oracle_blocks,
            "refusals": [
                {
                    "status": "refused",
                    "reason": "slice_too_large",
                    "detail": {
                        "message": "VEX statement limit reached at 0x1008: 641 > 512",
                        "address": {"linear": "0x1008"},
                        "metrics": {"vex_statements": 641, "limit": 512},
                    },
                }
            ],
        },
        candidate={"schema": "dosunit.ssa.v1", "exe": "candidate.exe", "functions": candidate_blocks},
    )

    assert compared["region_equality"]["status"] == "passed"
    assert compared["region_equality"]["results"][0]["reason"] == "transition_system_equal"
    assert compared["summary"]["failed"] == 0


def test_dosunit_connectivity_uses_signature_matched_shifted_successors():
    oracle_blocks = [
        _ssa_block_stub("oracle.exe:chunked", "chunked", base=0x1000, delta=0x0000, index=0, successors=[0x0100]),
        _ssa_block_stub("oracle.exe:chunked", "chunked", base=0x1000, delta=0x0100, index=1),
    ]
    candidate_blocks = [
        _ssa_block_stub("candidate.exe:chunked", "chunked", base=0x2000, delta=0x0000, index=0, successors=[0x0300]),
        _ssa_block_stub("candidate.exe:chunked", "chunked", base=0x2000, delta=0x0300, index=3),
    ]
    for block, byte in [
        (oracle_blocks[0], "90"),
        (candidate_blocks[0], "90"),
        (oracle_blocks[1], "c3"),
        (candidate_blocks[1], "c3"),
    ]:
        block["source"]["instructions"][0]["bytes"] = byte
    mapping = {
        "schema": "dosunit.mapping.v1",
        "id": "mapping:test",
        "functions": [
            {
                "oracle_id": "oracle.exe:chunked",
                "oracle_name": "chunked",
                "candidate_id": "candidate.exe:chunked",
                "candidate_name": "chunked",
            }
        ],
    }

    compared = compare_ssa_documents(
        oracle={"schema": "dosunit.ssa.v1", "exe": "oracle.exe", "functions": oracle_blocks},
        candidate={"schema": "dosunit.ssa.v1", "exe": "candidate.exe", "functions": candidate_blocks},
        mapping_document=mapping,
        enable_region_equality=False,
    )

    assert compared["summary"]["passed"] == 2
    assert compared["connectivity"]["status"] == "passed"
    assert compared["connectivity"]["refusals"] == []


def test_dosunit_compare_ssa_region_reports_incomplete_successor_blocks():
    oracle_blocks = [
        _ssa_block_stub(
            "demo.exe:truncated_loop", "truncated_loop", base=0x1000, delta=0x0000, index=0, successors=[0x0004]
        ),
        _ssa_block_stub(
            "demo.exe:truncated_loop", "truncated_loop", base=0x1000, delta=0x0004, index=1, successors=[0x0004, 0x0008]
        ),
    ]
    candidate_blocks = [
        _ssa_block_stub(
            "demo.exe:truncated_loop", "truncated_loop", base=0x2000, delta=0x0000, index=0, successors=[0x0004]
        ),
        _ssa_block_stub(
            "demo.exe:truncated_loop", "truncated_loop", base=0x2000, delta=0x0004, index=1, successors=[0x0004, 0x0008]
        ),
    ]

    compared = compare_ssa_documents(
        oracle={
            "schema": "dosunit.ssa.v1",
            "exe": "oracle.exe",
            "functions": oracle_blocks,
            "refusals": [
                {
                    "status": "refused",
                    "reason": "slice_too_large",
                    "detail": {
                        "message": "VEX statement limit reached at 0x1008: 641 > 512",
                        "address": {"linear": "0x1008"},
                        "metrics": {"vex_statements": 641, "limit": 512},
                    },
                }
            ],
        },
        candidate={"schema": "dosunit.ssa.v1", "exe": "candidate.exe", "functions": candidate_blocks},
    )

    result = compared["region_equality"]["results"][0]
    assert result["status"] == "refused"
    assert result["reason"] == "region_incomplete"
    mismatch = result["mismatches"][0]
    assert mismatch["kind"] == "region_incomplete"
    assert mismatch["oracle_missing_successors"][0]["from_delta"] == "0x0004"
    assert mismatch["oracle_missing_successors"][0]["missing_successor_delta"] == "0x0008"
    assert mismatch["oracle_missing_successors"][0]["lowering_refusal"]["reason"] == "slice_too_large"
    report = render_failure_report(compared)
    assert "Lowering refusal: `slice_too_large`" in report
    assert 'Metrics: `{"limit":512,"vex_statements":641}`' in report


def test_dosunit_compare_ssa_region_normalizes_equivalent_direct_call_return_store():
    oracle_blocks = _call_region_blocks(
        base=0x1000, caller_id="demo.exe:caller", target=0x1500, callee_id="demo.exe:setDrawColor"
    )
    candidate_blocks = _call_region_blocks(
        base=0x2000, caller_id="demo.exe:caller", target=0x2500, callee_id="demo.exe:setDrawColor"
    )

    compared = compare_ssa_documents(
        oracle={"schema": "dosunit.ssa.v1", "exe": "oracle.exe", "functions": oracle_blocks},
        candidate={"schema": "dosunit.ssa.v1", "exe": "candidate.exe", "functions": candidate_blocks},
        max_solver_assignments=0,
    )

    result = next(
        item for item in compared["region_equality"]["results"] if item["function"]["id"] == "demo.exe:caller"
    )
    assert result["status"] == "passed"
    assert result["reason"] == "region_ssa_equal"
    assert result["call_normalizations"][0]["call_compare"]["equivalent"] is True
    assert compared["summary"]["failed"] == 0


def test_dosunit_compare_ssa_region_normalizes_equivalent_far_call_return_bytes():
    oracle_blocks = _far_call_region_blocks(base=0x1000, caller_id="demo.exe:far_caller")
    candidate_blocks = _far_call_region_blocks(base=0x2000, caller_id="demo.exe:far_caller")

    compared = compare_ssa_documents(
        oracle={"schema": "dosunit.ssa.v1", "exe": "oracle.exe", "functions": oracle_blocks},
        candidate={"schema": "dosunit.ssa.v1", "exe": "candidate.exe", "functions": candidate_blocks},
        max_solver_assignments=0,
        max_solver_memory_stores=0,
    )

    result = next(
        item for item in compared["region_equality"]["results"] if item["function"]["id"] == "demo.exe:far_caller"
    )
    assert result["status"] == "passed"
    normalizations = result["call_normalizations"][0]["call_compare"]["normalizations"]
    assert normalizations[0]["reason"] == "normalized layout-dependent far-call return address byte stores"
    assert normalizations[0]["store_count"] == 2
    assert compared["summary"]["failed"] == 0


def test_dosunit_compare_ssa_refuses_unobserved_successor_state_connectivity():
    oracle_pred = _ssa_block_stub("demo.exe:flow", "flow", base=0x1000, delta=0x0000, index=0, successors=[0x0004])
    oracle_succ = _ssa_block_stub("demo.exe:flow", "flow", base=0x1000, delta=0x0004, index=1)
    candidate_pred = _ssa_block_stub("demo.exe:flow", "flow", base=0x2000, delta=0x0000, index=0, successors=[0x0004])
    candidate_succ = _ssa_block_stub("demo.exe:flow", "flow", base=0x2000, delta=0x0004, index=1)
    oracle_succ["inputs"] = [{"name": "bx", "width": 16}]
    candidate_succ["inputs"] = [{"name": "bx", "width": 16}]
    oracle_succ["outputs"]["bx"] = {"op": "input", "name": "bx", "width": 16}
    candidate_succ["outputs"]["bx"] = {"op": "input", "name": "bx", "width": 16}
    oracle = {"schema": "dosunit.ssa.v1", "exe": "oracle.exe", "functions": [oracle_pred, oracle_succ]}
    candidate = {"schema": "dosunit.ssa.v1", "exe": "candidate.exe", "functions": [candidate_pred, candidate_succ]}

    compared = compare_ssa_documents(oracle=oracle, candidate=candidate, enable_region_equality=False)

    assert compared["summary"]["passed"] == 1
    assert compared["summary"]["refused"] == 1
    assert compared["connectivity"]["status"] == "refused"
    refused = next(result for result in compared["results"] if result["reason"] == "successor_state_unobserved")
    mismatch = refused["mismatches"][0]
    assert mismatch["kind"] == "connectivity_state_unobserved"
    assert mismatch["oracle_missing_inputs"] == ["bx"]
    assert mismatch["candidate_missing_inputs"] == ["bx"]
    report = render_failure_report(compared)
    assert "Oracle missing successor inputs: `bx`" in report
    assert "Candidate missing successor inputs: `bx`" in report


def test_dosunit_compare_ssa_skips_external_oracle_parts_missing_candidate():
    oracle_entry = _ssa_block_stub("oracle.exe:chunky", "chunky", base=0x1000, delta=0x0000, index=0)
    oracle_external = _ssa_block_stub("oracle.exe:chunky", "chunky", base=0x1000, delta=0x0020, index=1)
    oracle_entry["source"]["function_machine_code_size"] = 4
    oracle_external["source"]["function_machine_code_size"] = 4
    candidate_entry = _ssa_block_stub("candidate.exe:chunky", "chunky", base=0x2000, delta=0x0000, index=0)
    mapping = {
        "schema": "dosunit.mapping.v1",
        "functions": [
            {
                "oracle_id": "oracle.exe:chunky",
                "oracle_name": "chunky",
                "candidate_id": "candidate.exe:chunky",
                "candidate_name": "chunky",
            }
        ],
    }

    compared = compare_ssa_documents(
        oracle={"schema": "dosunit.ssa.v1", "exe": "oracle.exe", "functions": [oracle_entry, oracle_external]},
        candidate={"schema": "dosunit.ssa.v1", "exe": "candidate.exe", "functions": [candidate_entry]},
        mapping_document=mapping,
        enable_region_equality=False,
        enable_connectivity=False,
    )

    assert compared["summary"]["passed"] == 1
    assert compared["summary"]["refused"] == 0
    assert compared["summary"]["external_oracle_parts_total"] == 1
    assert compared["summary"]["external_oracle_parts_checked"] == 1
    assert compared["external_parts"]["status"] == "refused"
    assert compared["external_parts"]["refused"] == 1
    assert compared["summary"]["skipped_external_oracle_parts"] == 1


def test_dosunit_external_block_signatures_ignore_leading_nop():
    oracle = _ssa_block_stub("demo.exe:tail", "tail", base=0x1000, delta=0x0020, index=1)
    candidate = _ssa_block_stub("demo.exe:tail", "tail", base=0x2000, delta=0x0020, index=1)
    oracle["source"]["instructions"] = [
        {"address": {"linear": "0x1020"}, "bytes": "55", "mnemonic": "push", "op_str": "bp", "disassembly": "push bp", "size": 1},
        {"address": {"linear": "0x1021"}, "bytes": "8bec", "mnemonic": "mov", "op_str": "bp, sp", "disassembly": "mov bp, sp", "size": 2},
    ]
    candidate["source"]["instructions"] = [
        {"address": {"linear": "0x2020"}, "bytes": "90", "mnemonic": "nop", "op_str": "", "disassembly": "nop", "size": 1},
        {"address": {"linear": "0x2021"}, "bytes": "55", "mnemonic": "push", "op_str": "bp", "disassembly": "push bp", "size": 1},
        {"address": {"linear": "0x2022"}, "bytes": "8bec", "mnemonic": "mov", "op_str": "bp, sp", "disassembly": "mov bp, sp", "size": 2},
    ]

    assert straightline_ssa._ssa_exact_block_signature(oracle) == straightline_ssa._ssa_exact_block_signature(candidate)
    assert straightline_ssa._ssa_block_signatures_match(oracle, candidate)


def test_dosunit_external_predecessor_chain_requires_signature_after_leading_nop():
    oracle_pred = _ssa_block_stub("demo.exe:tail", "tail", base=0x1000, delta=0x0000, index=0, successors=[0x0020])
    oracle_target = _ssa_block_stub("demo.exe:tail", "tail", base=0x1000, delta=0x0020, index=1)
    candidate_pred = _ssa_block_stub("demo.exe:tail", "tail", base=0x2000, delta=0x0000, index=0, successors=[0x0020])
    candidate_target = _ssa_block_stub("demo.exe:tail", "tail", base=0x2000, delta=0x0020, index=1)
    oracle_target["source"]["instructions"] = [
        {"address": {"linear": "0x1020"}, "bytes": "55", "mnemonic": "push", "op_str": "bp", "disassembly": "push bp", "size": 1}
    ]
    candidate_target["source"]["instructions"] = [
        {"address": {"linear": "0x2020"}, "bytes": "90", "mnemonic": "nop", "op_str": "", "disassembly": "nop", "size": 1},
        {"address": {"linear": "0x2021"}, "bytes": "56", "mnemonic": "push", "op_str": "si", "disassembly": "push si", "size": 1},
    ]
    candidate_by_delta = {("demo.exe:tail", "0x0020"): candidate_target}

    matched = straightline_ssa._candidate_for_external_part_by_matched_predecessor(
        oracle_target,
        prior_matches={str(oracle_pred["id"]): candidate_pred},
        oracle_external_functions=[oracle_pred],
        candidate_by_id_delta=candidate_by_delta,
        candidate_by_key_delta=candidate_by_delta,
    )

    assert matched is None


def test_dosunit_external_same_delta_requires_signature_after_leading_nop():
    oracle = _ssa_block_stub("demo.exe:tail", "tail", base=0x1000, delta=0x0020, index=1)
    candidate = _ssa_block_stub("demo.exe:tail", "tail", base=0x2000, delta=0x0020, index=1)
    oracle["source"]["instructions"] = [
        {"address": {"linear": "0x1020"}, "bytes": "55", "mnemonic": "push", "op_str": "bp", "disassembly": "push bp", "size": 1}
    ]
    candidate["source"]["instructions"] = [
        {"address": {"linear": "0x2020"}, "bytes": "90", "mnemonic": "nop", "op_str": "", "disassembly": "nop", "size": 1},
        {"address": {"linear": "0x2021"}, "bytes": "56", "mnemonic": "push", "op_str": "si", "disassembly": "push si", "size": 1},
    ]
    candidate_by_delta = {("demo.exe:tail", "0x0020"): candidate}

    matched, reason = straightline_ssa._candidate_for_external_part(
        oracle,
        mapped={"candidate_id": "demo.exe:tail", "candidate_name": "tail"},
        candidate_by_id_delta=candidate_by_delta,
        candidate_by_key_delta={("tail", "0x0020"): candidate},
        candidate_by_id_part={},
        candidate_by_key_part={},
        candidate_by_id_exact_signature={},
        candidate_by_key_exact_signature={},
        candidate_by_id_signature={},
        candidate_by_key_signature={},
        candidate_by_exact_signature={},
        candidate_by_signature={},
        prior_matches={},
        oracle_external_functions=[],
        candidate_by_id_delta_any=candidate_by_delta,
        candidate_by_key_delta_any={("tail", "0x0020"): candidate},
    )

    assert matched is None
    assert reason == "no_unique_candidate_by_delta_or_signature"


def test_dosunit_external_duplicate_blocks_match_by_shape_ordinal():
    def duplicate(function_id: str, name: str, *, base: int, delta: int, index: int, imm: int) -> dict[str, object]:
        block = _ssa_block_stub(function_id, name, base=base, delta=delta, index=index)
        linear = base + delta
        block["source"]["function_machine_code_size"] = 1
        block["source"]["instructions"] = [
            {
                "address": {"linear": f"0x{linear:04x}"},
                "bytes": f"b8{imm & 0xff:02x}{(imm >> 8) & 0xff:02x}",
                "mnemonic": "mov",
                "op_str": f"ax, 0x{imm:04x}",
                "disassembly": f"mov ax, 0x{imm:04x}",
                "size": 3,
            }
        ]
        return block

    oracle_first = duplicate("demo.exe:tail", "tail", base=0x1000, delta=0x0020, index=1, imm=0x1111)
    oracle_second = duplicate("demo.exe:tail", "tail", base=0x1000, delta=0x0040, index=2, imm=0x2222)
    candidate_first = duplicate("demo.exe:tail", "tail", base=0x2000, delta=0x0120, index=10, imm=0xAAAA)
    candidate_second = duplicate("demo.exe:tail", "tail", base=0x2000, delta=0x0140, index=11, imm=0xBBBB)

    matched, reason = straightline_ssa._candidate_for_external_part(
        oracle_second,
        mapped={"candidate_id": "demo.exe:tail", "candidate_name": "tail"},
        candidate_by_id_delta={},
        candidate_by_key_delta={},
        candidate_by_id_part={},
        candidate_by_key_part={},
        candidate_by_id_exact_signature={},
        candidate_by_key_exact_signature={},
        candidate_by_id_signature={},
        candidate_by_key_signature={},
        candidate_by_exact_signature={},
        candidate_by_signature={},
        prior_matches={},
        oracle_external_functions=[oracle_first, oracle_second],
        candidate_by_id_delta_any={},
        candidate_by_key_delta_any={},
        candidate_functions=[candidate_first, candidate_second],
    )

    assert matched is candidate_second
    assert reason == "same_function_signature_ordinal"


def test_dosunit_region_solver_gate_can_be_covered_by_connectivity():
    results = [
        {
            "status": "passed",
            "reason": "ssa_equal",
            "function": {"id": "demo.exe:big", "name": "big"},
            "mismatches": [],
        }
    ]
    region_equality = {
        "enabled": True,
        "status": "refused",
        "total": 1,
        "passed": 0,
        "failed": 0,
        "refused": 1,
        "results": [
            {
                "status": "refused",
                "reason": "slice_too_large",
                "function": {"id": "demo.exe:big", "name": "big"},
                "mismatches": [{"kind": "solver_gate", "metric": "memory_stores"}],
            }
        ],
    }
    connectivity = {
        "status": "passed",
        "edges_checked": 3,
        "state_edges_checked": 3,
        "state_inputs_checked": 9,
        "external_successor_edges_skipped": 0,
    }

    straightline_ssa._apply_connectivity_region_coverage(region_equality, results, connectivity)

    assert region_equality["status"] == "passed"
    assert region_equality["passed"] == 1
    assert region_equality["refused"] == 0
    assert region_equality["connectivity_covered_regions"] == 1
    region_result = region_equality["results"][0]
    assert region_result["reason"] == "covered_by_block_connectivity"
    assert region_result["mismatches"] == []
    assert region_result["connectivity_coverage"]["previous"]["reason"] == "slice_too_large"


def test_dosunit_region_solver_gate_not_covered_when_connectivity_refused():
    results = [
        {
            "status": "passed",
            "reason": "ssa_equal",
            "function": {"id": "demo.exe:big", "name": "big"},
            "mismatches": [],
        }
    ]
    region_equality = {
        "enabled": True,
        "status": "refused",
        "total": 1,
        "passed": 0,
        "failed": 0,
        "refused": 1,
        "results": [
            {
                "status": "refused",
                "reason": "slice_too_large",
                "function": {"id": "demo.exe:big", "name": "big"},
                "mismatches": [{"kind": "solver_gate", "metric": "memory_stores"}],
            }
        ],
    }

    straightline_ssa._apply_connectivity_region_coverage(
        region_equality,
        results,
        {"status": "refused", "refusals": [{"kind": "connectivity_refused"}]},
    )

    assert region_equality["status"] == "refused"
    assert region_equality["results"][0]["reason"] == "slice_too_large"


def test_dosunit_control_blocks_request_raw_state_outputs():
    outputs = straightline_ssa._with_control_output_regs(
        ("ax", "dx", "sp"),
        {"kind": "direct_successors", "targets": ["0x0004"]},
    )

    assert outputs == ("ax", "dx", "sp", "bx", "cx", "si", "di", "bp", "ip")


def test_dosunit_project_ssa_outputs_preserves_input_identity():
    function = {
        "id": "ssa-function:test",
        "assignments": [
            {
                "id": "v0",
                "op": "sub",
                "width": 16,
                "args": [
                    {"op": "input", "name": "sp", "width": 16},
                    {"op": "const", "value": "0x0002", "width": 16},
                ],
            }
        ],
        "outputs": {
            "dx": {"op": "input", "name": "dx", "width": 16},
            "sp": {"ref": "v0"},
        },
    }

    projected = straightline_ssa._project_ssa_outputs(function, ["dx", "sp"])

    assert projected["outputs"]["dx"] == {"op": "input", "name": "dx", "width": 16}
    sp_assignment = projected["assignments"][0]
    assert sp_assignment["op"] == "sub"
    assert sp_assignment["args"][0] == {"op": "input", "name": "sp", "width": 16}


def test_dosunit_compare_ssa_normalizes_direct_control_target_constants():
    def block(*, linear: int, target: int) -> dict[str, object]:
        return {
            "id": f"ssa-function:demo.exe:jump:{linear:x}",
            "function": {"id": "demo.exe:jump", "name": "jump"},
            "part": {"kind": "block", "index": 0, "entry_delta": "0x0000"},
            "function_entry": {"cs": "0x0000", "ip": f"0x{linear & 0xffff:04x}", "linear": f"0x{linear:04x}"},
            "entry": {"cs": "0x0000", "ip": f"0x{linear & 0xffff:04x}", "linear": f"0x{linear:04x}"},
            "source": {
                "jumpkind": "Ijk_Boring",
                "instruction_count": 1,
                "instructions": [
                    {
                        "address": {"ip": f"0x{linear & 0xffff:04x}", "linear": f"0x{linear:04x}"},
                        "bytes": "e90000",
                        "disassembly": f"jmp 0x{target & 0xffff:04x} (0x{target:04x})",
                        "mnemonic": "jmp",
                        "op_str": f"0x{target & 0xffff:04x}",
                        "size": 3,
                    }
                ],
            },
            "inputs": [],
            "outputs": {"ip": {"op": "const", "value": f"0x{target:04x}", "width": 32}},
            "assignments": [],
        }

    compared = compare_ssa_documents(
        oracle={"schema": "dosunit.ssa.v1", "exe": "oracle.exe", "functions": [block(linear=0x11000, target=0x11020)]},
        candidate={
            "schema": "dosunit.ssa.v1",
            "exe": "candidate.exe",
            "functions": [block(linear=0x12000, target=0x12040)],
        },
        skip_binary_equal=False,
        enable_region_equality=False,
        enable_connectivity=False,
    )

    result = compared["results"][0]
    assert result["status"] == "passed"
    assert result["layout_normalization"]["pairs"] == [
        {"oracle": "0x1020", "candidate": "0x2040", "reason": "control_target"}
    ]


def test_dosunit_compare_ssa_normalizes_conditional_fallthrough_ip_constants():
    def block(*, linear: int, target: int) -> dict[str, object]:
        fallthrough = linear + 2
        return {
            "id": f"ssa-function:demo.exe:jump:{linear:x}",
            "function": {"id": "demo.exe:jump", "name": "jump"},
            "part": {"kind": "block", "index": 0, "entry_delta": "0x0000"},
            "function_entry": {"cs": "0x0000", "ip": f"0x{linear & 0xffff:04x}", "linear": f"0x{linear:04x}"},
            "entry": {"cs": "0x0000", "ip": f"0x{linear & 0xffff:04x}", "linear": f"0x{linear:04x}"},
            "source": {
                "jumpkind": "Ijk_Boring",
                "instruction_count": 1,
                "transfer": {
                    "kind": "direct_successors",
                    "successors": [
                        {"linear": f"0x{target:04x}", "low16": f"0x{target & 0xffff:04x}"},
                        {"linear": f"0x{fallthrough:04x}", "low16": f"0x{fallthrough & 0xffff:04x}"},
                    ],
                },
                "instructions": [
                    {
                        "address": {"ip": f"0x{linear & 0xffff:04x}", "linear": f"0x{linear:04x}"},
                        "bytes": "7400",
                        "disassembly": f"je 0x{target & 0xffff:04x} (0x{target:04x})",
                        "mnemonic": "je",
                        "op_str": f"0x{target & 0xffff:04x}",
                        "size": 2,
                    }
                ],
            },
            "inputs": [],
            "outputs": {"ip": {"op": "const", "value": f"0x{fallthrough & 0xffff:04x}", "width": 16}},
            "assignments": [],
        }

    compared = compare_ssa_documents(
        oracle={"schema": "dosunit.ssa.v1", "exe": "oracle.exe", "functions": [block(linear=0x11000, target=0x11020)]},
        candidate={
            "schema": "dosunit.ssa.v1",
            "exe": "candidate.exe",
            "functions": [block(linear=0x12000, target=0x12040)],
        },
        skip_binary_equal=False,
        enable_region_equality=False,
        enable_connectivity=False,
    )

    result = compared["results"][0]
    assert result["status"] == "passed"
    assert {"oracle": "0x1002", "candidate": "0x2002", "reason": "control_fallthrough"} in result[
        "layout_normalization"
    ]["pairs"]


def test_dosunit_compare_ssa_normalizes_pointer_bound_branch_constants():
    def block(*, linear: int, bound: int, taken: int, fallthrough: int) -> dict[str, object]:
        return {
            "id": f"ssa-function:demo.exe:brkctl:{linear:x}",
            "function": {"id": "demo.exe:brkctl", "name": "brkctl"},
            "part": {"kind": "block", "index": 0, "entry_delta": "0x0000"},
            "function_entry": {"cs": "0x0000", "ip": f"0x{linear & 0xffff:04x}", "linear": f"0x{linear:04x}"},
            "entry": {"cs": "0x0000", "ip": f"0x{linear & 0xffff:04x}", "linear": f"0x{linear:04x}"},
            "source": {
                "jumpkind": "Ijk_Boring",
                "instruction_count": 3,
                "transfer": {
                    "kind": "direct_successors",
                    "successors": [
                        {"linear": f"0x{taken:04x}", "low16": f"0x{taken & 0xffff:04x}"},
                        {"linear": f"0x{fallthrough:04x}", "low16": f"0x{fallthrough & 0xffff:04x}"},
                    ],
                },
                "instructions": [
                    {
                        "address": {"ip": f"0x{linear & 0xffff:04x}", "linear": f"0x{linear:04x}"},
                        "disassembly": "add si, 4",
                        "mnemonic": "add",
                        "op_str": "si, 4",
                        "size": 3,
                    },
                    {
                        "address": {"ip": f"0x{(linear + 3) & 0xffff:04x}", "linear": f"0x{linear + 3:04x}"},
                        "disassembly": f"cmp si, 0x{bound & 0xffff:04x}",
                        "mnemonic": "cmp",
                        "op_str": f"si, 0x{bound & 0xffff:04x}",
                        "size": 4,
                    },
                    {
                        "address": {"ip": f"0x{(linear + 7) & 0xffff:04x}", "linear": f"0x{linear + 7:04x}"},
                        "disassembly": f"jae 0x{taken & 0xffff:04x} (0x{taken:04x})",
                        "mnemonic": "jae",
                        "op_str": f"0x{taken & 0xffff:04x}",
                        "size": 2,
                    },
                ],
            },
            "inputs": [{"name": "si", "width": 16}],
            "assignments": [
                {
                    "id": "v0",
                    "op": "add",
                    "width": 16,
                    "args": [
                        {"op": "input", "name": "si", "width": 16},
                        {"op": "const", "value": "0x0004", "width": 16},
                    ],
                },
                {
                    "id": "v1",
                    "op": "uge",
                    "width": 1,
                    "args": [{"ref": "v0"}, {"op": "const", "value": f"0x{bound & 0xffff:04x}", "width": 16}],
                },
                {
                    "id": "v2",
                    "op": "ite",
                    "width": 16,
                    "args": [
                        {"ref": "v1"},
                        {"op": "const", "value": f"0x{taken & 0xffff:04x}", "width": 16},
                        {"op": "const", "value": f"0x{fallthrough & 0xffff:04x}", "width": 16},
                    ],
                },
            ],
            "outputs": {"ip": {"ref": "v2"}},
        }

    compared = compare_ssa_documents(
        oracle={
            "schema": "dosunit.ssa.v1",
            "exe": "oracle.exe",
            "functions": [block(linear=0x107F5, bound=0x618A, taken=0x10802, fallthrough=0x107FE)],
        },
        candidate={
            "schema": "dosunit.ssa.v1",
            "exe": "candidate.exe",
            "functions": [block(linear=0x1027D, bound=0xA076, taken=0x1028A, fallthrough=0x10286)],
        },
        skip_binary_equal=False,
        enable_region_equality=False,
        enable_connectivity=False,
    )

    result = compared["results"][0]
    assert result["status"] == "passed"
    assert {"oracle": "0x618a", "candidate": "0xa076", "reason": "pointer_bound"} in result[
        "layout_normalization"
    ]["pairs"]


def test_dosunit_compare_ssa_checks_observed_successor_state_connectivity():
    oracle_pred = _ssa_block_stub("demo.exe:flow", "flow", base=0x1000, delta=0x0000, index=0, successors=[0x0004])
    oracle_succ = _ssa_block_stub("demo.exe:flow", "flow", base=0x1000, delta=0x0004, index=1)
    candidate_pred = _ssa_block_stub("demo.exe:flow", "flow", base=0x2000, delta=0x0000, index=0, successors=[0x0004])
    candidate_succ = _ssa_block_stub("demo.exe:flow", "flow", base=0x2000, delta=0x0004, index=1)
    oracle_pred["inputs"] = [{"name": "cx", "width": 16}]
    candidate_pred["inputs"] = [{"name": "cx", "width": 16}]
    oracle_pred["outputs"]["bx"] = {
        "op": "add",
        "width": 16,
        "args": [{"op": "input", "name": "cx", "width": 16}, {"op": "const", "value": "0x0001", "width": 16}],
    }
    candidate_pred["outputs"]["bx"] = {
        "op": "add",
        "width": 16,
        "args": [{"op": "input", "name": "cx", "width": 16}, {"op": "const", "value": "0x0001", "width": 16}],
    }
    oracle_succ["inputs"] = [{"name": "bx", "width": 16}]
    candidate_succ["inputs"] = [{"name": "bx", "width": 16}]
    oracle_succ["outputs"]["bx"] = {"op": "input", "name": "bx", "width": 16}
    candidate_succ["outputs"]["bx"] = {"op": "input", "name": "bx", "width": 16}
    oracle = {"schema": "dosunit.ssa.v1", "exe": "oracle.exe", "functions": [oracle_pred, oracle_succ]}
    candidate = {"schema": "dosunit.ssa.v1", "exe": "candidate.exe", "functions": [candidate_pred, candidate_succ]}

    compared = compare_ssa_documents(oracle=oracle, candidate=candidate, enable_region_equality=False)

    assert compared["summary"]["passed"] == 2
    assert compared["connectivity"]["status"] == "passed"
    assert compared["connectivity"]["edges_checked"] == 1
    assert compared["connectivity"]["state_edges_checked"] == 1
    assert compared["connectivity"]["state_inputs_checked"] == 1


def test_dosunit_compare_ssa_ignores_ambient_successor_state_connectivity():
    oracle_pred = _ssa_block_stub("demo.exe:flow", "flow", base=0x1000, delta=0x0000, index=0, successors=[0x0004])
    oracle_succ = _ssa_block_stub("demo.exe:flow", "flow", base=0x1000, delta=0x0004, index=1)
    candidate_pred = _ssa_block_stub("demo.exe:flow", "flow", base=0x2000, delta=0x0000, index=0, successors=[0x0004])
    candidate_succ = _ssa_block_stub("demo.exe:flow", "flow", base=0x2000, delta=0x0004, index=1)
    oracle_succ["inputs"] = [{"name": "bp", "width": 16}, {"name": "ds", "width": 16}, {"name": "flags", "width": 16}]
    candidate_succ["inputs"] = [
        {"name": "bp", "width": 16},
        {"name": "ds", "width": 16},
        {"name": "flags", "width": 16},
    ]
    oracle = {"schema": "dosunit.ssa.v1", "exe": "oracle.exe", "functions": [oracle_pred, oracle_succ]}
    candidate = {"schema": "dosunit.ssa.v1", "exe": "candidate.exe", "functions": [candidate_pred, candidate_succ]}

    compared = compare_ssa_documents(oracle=oracle, candidate=candidate, enable_region_equality=False)

    assert compared["summary"]["passed"] == 2
    assert compared["connectivity"]["status"] == "passed"
    assert compared["connectivity"]["state_edges_checked"] == 1
    assert compared["connectivity"]["state_inputs_checked"] == 0


def test_dosunit_compare_ssa_ignores_ambient_fields_in_unobserved_state():
    oracle_pred = _ssa_block_stub("demo.exe:flow", "flow", base=0x1000, delta=0x0000, index=0, successors=[0x0004])
    oracle_succ = _ssa_block_stub("demo.exe:flow", "flow", base=0x1000, delta=0x0004, index=1)
    candidate_pred = _ssa_block_stub("demo.exe:flow", "flow", base=0x2000, delta=0x0000, index=0, successors=[0x0004])
    candidate_succ = _ssa_block_stub("demo.exe:flow", "flow", base=0x2000, delta=0x0004, index=1)
    oracle_succ["inputs"] = [
        {"name": "bx", "width": 16},
        {"name": "ds", "width": 16},
        {"name": "flags", "width": 16},
    ]
    candidate_succ["inputs"] = [
        {"name": "bx", "width": 16},
        {"name": "ds", "width": 16},
        {"name": "flags", "width": 16},
    ]
    oracle = {"schema": "dosunit.ssa.v1", "exe": "oracle.exe", "functions": [oracle_pred, oracle_succ]}
    candidate = {"schema": "dosunit.ssa.v1", "exe": "candidate.exe", "functions": [candidate_pred, candidate_succ]}

    compared = compare_ssa_documents(oracle=oracle, candidate=candidate, enable_region_equality=False)

    assert compared["summary"]["passed"] == 2
    assert compared["summary"]["refused"] == 0
    assert compared["connectivity"]["status"] == "passed"
    assert compared["connectivity"]["state_edges_checked"] == 1
    assert compared["connectivity"]["state_inputs_checked"] == 0


def test_dosunit_compare_ssa_skips_external_shared_tail_connectivity():
    oracle_pred = _ssa_block_stub("demo.exe:tailjmp", "tailjmp", base=0x1000, delta=0x0000, index=0, successors=[0x0030])
    candidate_pred = _ssa_block_stub(
        "demo.exe:tailjmp", "tailjmp", base=0x2000, delta=0x0000, index=0, successors=[0x0030]
    )
    oracle_pred["source"]["function_machine_code_size"] = 0x10
    candidate_pred["source"]["function_machine_code_size"] = 0x10
    oracle = {"schema": "dosunit.ssa.v1", "exe": "oracle.exe", "functions": [oracle_pred]}
    candidate = {"schema": "dosunit.ssa.v1", "exe": "candidate.exe", "functions": [candidate_pred]}

    compared = compare_ssa_documents(oracle=oracle, candidate=candidate, enable_region_equality=False)

    assert compared["summary"]["passed"] == 1
    assert compared["connectivity"]["status"] == "not_applicable"
    assert compared["connectivity"]["edges_checked"] == 0
    assert compared["connectivity"]["external_successor_edges_skipped"] == 2
    assert compared["connectivity"]["refusals"] == []


def test_dosunit_compare_ssa_reports_passed_loop_scc():
    oracle = {
        "schema": "dosunit.ssa.v1",
        "exe": "oracle.exe",
        "functions": [
            _ssa_block_stub("demo.exe:loop", "loop", base=0x1000, delta=0x0000, index=0, successors=[0x0004]),
            _ssa_block_stub("demo.exe:loop", "loop", base=0x1000, delta=0x0004, index=1, successors=[0x0000]),
        ],
    }
    candidate = {
        "schema": "dosunit.ssa.v1",
        "exe": "candidate.exe",
        "functions": [
            _ssa_block_stub("demo.exe:loop", "loop", base=0x2000, delta=0x0000, index=0, successors=[0x0004]),
            _ssa_block_stub("demo.exe:loop", "loop", base=0x2000, delta=0x0004, index=1, successors=[0x0000]),
        ],
    }

    compared = compare_ssa_documents(oracle=oracle, candidate=candidate, enable_region_equality=False)

    assert compared["summary"]["passed"] == 2
    assert compared["connectivity"]["status"] == "passed"
    assert compared["loop_scc"]["status"] == "passed"
    assert compared["loop_scc"]["total"] == 1
    assert compared["loop_scc"]["results"][0]["block_deltas"] == ["0x0000", "0x0004"]
    report = render_failure_report(compared)
    assert "Loop SCCs: `passed` total `1` passed `1`" in report


def test_dosunit_compare_ssa_reports_passed_call_scc():
    oracle = {
        "schema": "dosunit.ssa.v1",
        "exe": "oracle.exe",
        "functions": [
            _ssa_stub(
                "demo.exe:func_a", "func_a", ip="0x0200", linear="0x1200", jumpkind="Ijk_Call", call_raw="0x1300"
            ),
            _ssa_stub(
                "demo.exe:func_b", "func_b", ip="0x0300", linear="0x1300", jumpkind="Ijk_Call", call_raw="0x1200"
            ),
        ],
    }
    candidate = {
        "schema": "dosunit.ssa.v1",
        "exe": "candidate.exe",
        "functions": [
            _ssa_stub(
                "demo.exe:func_a", "func_a", ip="0x0200", linear="0x1200", jumpkind="Ijk_Call", call_raw="0x1300"
            ),
            _ssa_stub(
                "demo.exe:func_b", "func_b", ip="0x0300", linear="0x1300", jumpkind="Ijk_Call", call_raw="0x1200"
            ),
        ],
    }

    compared = compare_ssa_documents(oracle=oracle, candidate=candidate, enable_region_equality=False)

    assert compared["summary"]["passed"] == 2
    assert compared["call_scc"]["status"] == "passed"
    assert compared["call_scc"]["total"] == 1
    assert compared["call_scc"]["results"][0]["function_count"] == 2
    report = render_failure_report(compared)
    assert "Call SCCs: `passed` total `1` passed `1`" in report


def test_dosunit_compare_ssa_refuses_conditional_connectivity_without_ip_output():
    oracle = {
        "schema": "dosunit.ssa.v1",
        "exe": "oracle.exe",
        "functions": [
            _ssa_block_stub(
                "demo.exe:branch", "branch", base=0x1000, delta=0x0000, index=0, successors=[0x0004, 0x0008]
            ),
            _ssa_block_stub("demo.exe:branch", "branch", base=0x1000, delta=0x0004, index=1),
            _ssa_block_stub("demo.exe:branch", "branch", base=0x1000, delta=0x0008, index=2),
        ],
    }
    candidate = {
        "schema": "dosunit.ssa.v1",
        "exe": "candidate.exe",
        "functions": [
            _ssa_block_stub(
                "demo.exe:branch", "branch", base=0x2000, delta=0x0000, index=0, successors=[0x0004, 0x0008]
            ),
            _ssa_block_stub("demo.exe:branch", "branch", base=0x2000, delta=0x0004, index=1),
            _ssa_block_stub("demo.exe:branch", "branch", base=0x2000, delta=0x0008, index=2),
        ],
    }

    compared = compare_ssa_documents(oracle=oracle, candidate=candidate)

    assert compared["summary"]["passed"] == 2
    assert compared["summary"]["refused"] == 1
    assert compared["connectivity"]["status"] == "refused"
    refused = next(result for result in compared["results"] if result["reason"] == "branch_predicate_unobserved")
    assert refused["mismatches"][0]["kind"] == "branch_predicate_unobserved"
    report = render_failure_report(compared)
    assert "conditional direct-successor block does not expose ip" in report


def test_dosunit_compare_ssa_aligns_mixed_width_z3_operands():
    oracle_function = _ssa_stub("demo.exe:mixed_width", "mixed_width", ip="0x0200", linear="0x1200")
    candidate_function = _ssa_stub("demo.exe:mixed_width", "mixed_width", ip="0x0200", linear="0x1200")
    common_inputs = [{"name": "bx", "width": 16}]
    oracle_function["inputs"] = common_inputs
    candidate_function["inputs"] = common_inputs
    oracle_function["outputs"] = {"ax": {"ref": "v1"}}
    oracle_function["assignments"] = [
        {"id": "v0", "op": "zext", "width": 32, "args": [{"op": "input", "name": "bx", "width": 16}]},
        {
            "id": "v1",
            "op": "add",
            "width": 32,
            "args": [
                {"ref": "v0"},
                {"op": "const", "value": "0x0001", "width": 16},
            ],
        },
    ]
    candidate_function["outputs"] = {"ax": {"ref": "v1"}}
    candidate_function["assignments"] = [
        {"id": "v0", "op": "zext", "width": 32, "args": [{"op": "input", "name": "bx", "width": 16}]},
        {
            "id": "v1",
            "op": "add",
            "width": 32,
            "args": [
                {"ref": "v0"},
                {"op": "const", "value": "0x00000001", "width": 32},
            ],
        },
    ]

    compared = compare_ssa_documents(oracle=_ssa_doc(oracle_function), candidate=_ssa_doc(candidate_function))

    assert compared["summary"]["passed"] == 1


def test_dosunit_compare_ssa_detects_changed_successor_block(tmp_path: Path):
    original_image = bytearray(0x240)
    candidate_image = bytearray(0x240)
    original_image[0x200:0x20D] = b"\x83\xf8\x01\x75\x04\xb8\x02\x00\xc3\xb8\x03\x00\xc3"
    candidate_image[0x200:0x20D] = b"\x83\xf8\x01\x75\x04\xb8\x02\x00\xc3\xb8\x04\x00\xc3"
    original = tmp_path / "original.exe"
    candidate = tmp_path / "candidate.exe"
    original.write_bytes(_mz_exe(bytes(original_image)))
    candidate.write_bytes(_mz_exe(bytes(candidate_image)))
    catalog = _edge_catalog("demo.exe:branchy", "branchy", offset=0x0200, size=0x0D)

    oracle = lower_straightline_ssa_document(exe_path=original, functions_catalog=catalog, output_regs=("ax",))
    candidate_ssa = lower_straightline_ssa_document(exe_path=candidate, functions_catalog=catalog, output_regs=("ax",))
    compared = compare_ssa_documents(oracle=oracle, candidate=candidate_ssa)

    assert oracle["counters"]["ssa_parts_lowered"] == 3
    assert candidate_ssa["counters"]["ssa_parts_lowered"] == 3
    assert "ip" in oracle["functions"][0]["outputs"]
    assert "ip" in candidate_ssa["functions"][0]["outputs"]
    assert compared["summary"]["total"] == 3
    assert compared["summary"]["failed"] == 1
    failed = next(result for result in compared["results"] if result["status"] == "failed")
    assert failed["oracle_detail"]["part"]["entry_delta"] == "0x0009"
    assert failed["mismatches"][0]["kind"] == "output_expr_changed"
    assert failed["mismatches"][0]["reg"] == "ax"


def test_dosunit_compare_ssa_region_equality_covers_reblocked_branchy_function(tmp_path: Path):
    original_image = bytearray(0x240)
    candidate_image = bytearray(0x240)
    original_code = b"\x3d\x01\x00\x74\x04\xbb\x22\x22\xc3\xbb\x11\x11\xc3"
    candidate_code = b"\x3d\x01\x00\x75\x04\xbb\x11\x11\xc3\xbb\x22\x22\xc3"
    original_image[0x200 : 0x200 + len(original_code)] = original_code
    candidate_image[0x200 : 0x200 + len(candidate_code)] = candidate_code
    original = tmp_path / "original.exe"
    candidate = tmp_path / "candidate.exe"
    original.write_bytes(_mz_exe(bytes(original_image)))
    candidate.write_bytes(_mz_exe(bytes(candidate_image)))
    catalog = _edge_catalog("demo.exe:branchy", "branchy", offset=0x0200, size=len(original_code))

    oracle = lower_straightline_ssa_document(exe_path=original, functions_catalog=catalog, output_regs=("bx",))
    candidate_ssa = lower_straightline_ssa_document(exe_path=candidate, functions_catalog=catalog, output_regs=("bx",))
    without_region = compare_ssa_documents(oracle=oracle, candidate=candidate_ssa, enable_region_equality=False)
    compared = compare_ssa_documents(oracle=oracle, candidate=candidate_ssa)

    assert oracle["counters"]["ssa_parts_lowered"] == 3
    assert candidate_ssa["counters"]["ssa_parts_lowered"] == 3
    assert without_region["summary"]["failed"] >= 1
    assert compared["region_equality"]["status"] == "passed"
    assert compared["region_equality"]["passed"] == 1
    assert compared["region_equality"]["covered_results"] >= 1
    assert compared["summary"]["failed"] == 0
    assert compared["summary"]["refused"] == 0
    assert any(result.get("reason") == "covered_by_region_equal" for result in compared["results"])


def test_dosunit_compare_ssa_region_equality_keeps_real_branch_mismatch_failed(tmp_path: Path):
    original_image = bytearray(0x240)
    candidate_image = bytearray(0x240)
    original_code = b"\x3d\x01\x00\x74\x04\xbb\x22\x22\xc3\xbb\x11\x11\xc3"
    candidate_code = b"\x3d\x01\x00\x75\x04\xbb\x11\x11\xc3\xbb\x33\x33\xc3"
    original_image[0x200 : 0x200 + len(original_code)] = original_code
    candidate_image[0x200 : 0x200 + len(candidate_code)] = candidate_code
    original = tmp_path / "original.exe"
    candidate = tmp_path / "candidate.exe"
    original.write_bytes(_mz_exe(bytes(original_image)))
    candidate.write_bytes(_mz_exe(bytes(candidate_image)))
    catalog = _edge_catalog("demo.exe:branchy", "branchy", offset=0x0200, size=len(original_code))

    oracle = lower_straightline_ssa_document(exe_path=original, functions_catalog=catalog, output_regs=("bx",))
    candidate_ssa = lower_straightline_ssa_document(exe_path=candidate, functions_catalog=catalog, output_regs=("bx",))
    compared = compare_ssa_documents(oracle=oracle, candidate=candidate_ssa)

    assert compared["region_equality"]["status"] == "failed"
    assert compared["region_equality"]["failed"] == 1
    assert compared["summary"]["failed"] >= 1
    region_failure = compared["region_equality"]["results"][0]["mismatches"][0]
    assert region_failure["kind"] == "output_expr_changed"
    assert region_failure["reg"] == "bx"
    report = render_failure_report(compared)
    assert "Function Region Equality" in report
    assert "Region observables" in report
    assert "Oracle region first instructions" in report
    assert "`0x0200 (0x1200): cmp ax, 1`" in report
    assert "Candidate region first instructions" in report


def test_dosunit_compare_ssa_region_equality_prunes_constant_bounded_loop():
    oracle = _manual_loop_ssa_doc("oracle.exe", constant_count=True)
    candidate = _manual_loop_ssa_doc("candidate.exe", constant_count=True)

    refused = compare_ssa_documents(oracle=oracle, candidate=candidate, max_region_loop_unroll=0)
    compared = compare_ssa_documents(oracle=oracle, candidate=candidate, max_region_loop_unroll=1)

    assert refused["region_equality"]["status"] == "refused"
    assert refused["region_equality"]["results"][0]["reason"] == "unsupported_ir"
    assert compared["region_equality"]["status"] == "passed"
    region = compared["region_equality"]["results"][0]
    assert region["oracle_summary"]["loop_cuts"] == 0
    assert region["oracle_summary"]["branch_prunes"] >= 2
    assert region["oracle_summary"]["branch_merges"] == 0


def test_dosunit_compare_ssa_region_equality_refuses_symbolic_loop_cut():
    oracle = _manual_loop_ssa_doc("oracle.exe", constant_count=False)
    candidate = _manual_loop_ssa_doc("candidate.exe", constant_count=False)

    compared = compare_ssa_documents(oracle=oracle, candidate=candidate, max_region_loop_unroll=1)

    assert compared["region_equality"]["status"] == "refused"
    result = compared["region_equality"]["results"][0]
    assert result["reason"] == "loop_bound_incomplete"
    assert result["oracle_summary"]["mismatches"][0]["kind"] == "loop_bound_incomplete"
    report = render_failure_report(compared)
    assert "Function Region Equality" in report
    assert "loop_bound_incomplete" in report


def test_dosunit_compare_ssa_uses_region_proven_callee_for_shifted_call(tmp_path: Path):
    original_image = bytearray(0x280)
    candidate_image = bytearray(0x280)
    original_callee = b"\x3d\x01\x00\x74\x04\xbb\x22\x22\xc3\xbb\x11\x11\xc3"
    candidate_callee = b"\x3d\x01\x00\x75\x04\xbb\x11\x11\xc3\xbb\x22\x22\xc3"
    original_image[0x200:0x204] = b"\xe8\x0d\x00\xc3"
    original_image[0x210 : 0x210 + len(original_callee)] = original_callee
    candidate_image[0x200:0x204] = b"\xe8\x2d\x00\xc3"
    candidate_image[0x230 : 0x230 + len(candidate_callee)] = candidate_callee
    original = tmp_path / "original.exe"
    candidate = tmp_path / "candidate.exe"
    original.write_bytes(_mz_exe(bytes(original_image)))
    candidate.write_bytes(_mz_exe(bytes(candidate_image)))
    original_catalog = {
        "schema": "dosunit.functions.v1",
        "module": "demo.exe",
        "program_kind": "mz_exe",
        "functions": [
            _edge_function("demo.exe:caller", "caller", offset=0x0200, size=4),
            _edge_function("demo.exe:callee", "callee", offset=0x0210, size=len(original_callee)),
        ],
        "diagnostics": [],
    }
    candidate_catalog = {
        "schema": "dosunit.functions.v1",
        "module": "demo.exe",
        "program_kind": "mz_exe",
        "functions": [
            _edge_function("demo.exe:caller", "caller", offset=0x0200, size=4),
            _edge_function("demo.exe:callee_rebuilt", "callee_rebuilt", offset=0x0230, size=len(candidate_callee)),
        ],
        "diagnostics": [],
    }
    mapping = {
        "schema": "dosunit.mapping.v1",
        "functions": [
            {
                "oracle_id": "demo.exe:caller",
                "oracle_name": "caller",
                "candidate_id": "demo.exe:caller",
                "candidate_name": "caller",
            },
            {
                "oracle_id": "demo.exe:callee",
                "oracle_name": "callee",
                "candidate_id": "demo.exe:callee_rebuilt",
                "candidate_name": "callee_rebuilt",
            },
        ],
    }

    oracle = lower_straightline_ssa_document(
        exe_path=original,
        functions_catalog=original_catalog,
        output_regs=("bx", "sp"),
        follow_call_fallthrough=False,
    )
    candidate_ssa = lower_straightline_ssa_document(
        exe_path=candidate,
        functions_catalog=candidate_catalog,
        output_regs=("bx", "sp"),
        follow_call_fallthrough=False,
    )
    compared = compare_ssa_documents(oracle=oracle, candidate=candidate_ssa, mapping_document=mapping)

    assert compared["region_equality"]["status"] == "passed"
    assert compared["summary"]["failed"] == 0
    assert compared["summary"]["refused"] == 0
    caller = next(result for result in compared["results"] if result["function"]["name"] == "caller")
    assert caller["status"] == "passed"
    assert caller["call_compare"]["proof_fact"]["proof"] == "region_equal"
    assert caller["call_compare"]["reason"] == "direct call targets are equivalent through proven callee equality"


def test_dosunit_compare_ssa_abi_composes_branchy_function_effects(tmp_path: Path):
    original_image = bytearray(0x240)
    candidate_image = bytearray(0x240)
    original_image[0x200:0x217] = (
        b"\xb3\x02\x81\xf9\x9d\x7d\x73\x0a\xfe\xcb\x81\xf9\x1a\x6a\x73\x02\xfe\xcb\x88\x1e\x7b\x02\xc3"
    )
    candidate_image[0x200:0x21E] = (
        b"\x81\xf9\x9d\x7d"
        b"\x72\x06"
        b"\xc6\x06\x7b\x02\x02"
        b"\xc3"
        b"\x81\xf9\x1a\x6a"
        b"\x72\x06"
        b"\xc6\x06\x7b\x02\x01"
        b"\xc3"
        b"\xc6\x06\x7b\x02\x00"
        b"\xc3"
    )
    original = tmp_path / "original.exe"
    candidate = tmp_path / "candidate.exe"
    original.write_bytes(_mz_exe(bytes(original_image)))
    candidate.write_bytes(_mz_exe(bytes(candidate_image)))
    original_catalog = _edge_catalog(
        "demo.exe:sample_set_variant_count", "sample_set_variant_count", offset=0x0200, size=0x17
    )
    candidate_catalog = _edge_catalog(
        "demo.exe:sample_set_variant_count", "sample_set_variant_count", offset=0x0200, size=0x1E
    )

    output_regs = ("ax", "bx", "cx", "dx", "sp", "ds", "ip")
    oracle = lower_straightline_ssa_document(
        exe_path=original, functions_catalog=original_catalog, output_regs=output_regs
    )
    candidate_ssa = lower_straightline_ssa_document(
        exe_path=candidate, functions_catalog=candidate_catalog, output_regs=output_regs
    )
    abi_manifest = {
        "schema": "test.abi.v1",
        "functions": [
            {
                "name": "sample_set_variant_count",
                "kind": "near",
                "calling_convention": "near_register_cx",
                "inputs": [{"location": "cx", "name": "setup_value", "width": 16}],
                "preserved": ["ds"],
                "clobbers": ["bx", "flags"],
                "effects": [
                    {"space": "DS", "segment": "ds", "offset": "0x027b", "size": 1, "name": "sample_variant_max_index"}
                ],
            }
        ],
    }

    compared = compare_ssa_abi_documents(oracle=oracle, candidate=candidate_ssa, abi_manifest=abi_manifest)

    assert compared["summary"]["passed"] == 1
    assert compared["results"][0]["observables"]["regs"] == ["ds", "sp"]
    assert compared["results"][0]["observables"]["memory"][0]["name"] == "sample_variant_max_index"


def test_dosunit_compare_ssa_abi_uses_explicit_static_observe_regs(tmp_path: Path):
    original_image = bytearray(0x220)
    candidate_image = bytearray(0x220)
    original_image[0x200:0x207] = b"\xc6\x06\x7b\x02\x01\xc3"
    candidate_image[0x200:0x207] = b"\xc6\x06\x7b\x02\x01\xc3"
    original = tmp_path / "original.exe"
    candidate = tmp_path / "candidate.exe"
    original.write_bytes(_mz_exe(bytes(original_image)))
    candidate.write_bytes(_mz_exe(bytes(candidate_image)))
    catalog = _edge_catalog("demo.exe:enable", "enable", offset=0x0200, size=0x06)

    output_regs = ("sp", "ds", "bp", "ip")
    oracle = lower_straightline_ssa_document(exe_path=original, functions_catalog=catalog, output_regs=output_regs)
    candidate_ssa = lower_straightline_ssa_document(
        exe_path=candidate, functions_catalog=catalog, output_regs=output_regs
    )
    abi_manifest = {
        "schema": "test.abi.v1",
        "functions": [
            {
                "name": "enable",
                "kind": "near",
                "preserved": ["bp", "ds"],
                "ssa_observe_regs": ["sp"],
                "effects": [{"space": "DS", "segment": "ds", "offset": "0x027b", "size": 1, "name": "enabled"}],
            }
        ],
    }

    compared = compare_ssa_abi_documents(oracle=oracle, candidate=candidate_ssa, abi_manifest=abi_manifest)

    assert compared["summary"]["passed"] == 1
    assert compared["results"][0]["observables"]["regs"] == ["sp"]


def test_dosunit_compare_ssa_abi_canonicalizes_far_stack_arguments(tmp_path: Path):
    original_image = bytearray(0x240)
    candidate_image = bytearray(0x240)
    original_image[0x200:0x21B] = (
        b"\x55\x89\xe5\x1e\xb8\x00\x01\x8e\xd8\x8b\x46\x06\x3b\x06\x84\x02\x7c\x03\xa1\x84\x02\xa3\x7e\x02\x1f\x5d\xcb"
    )
    candidate_image[0x200:0x21B] = (
        b"\x1e\xb8\x00\x01\x8e\xd8\x55\x89\xe5\x8b\x46\x08\x3b\x06\x84\x02\x7c\x03\xa1\x84\x02\xa3\x7e\x02\x5d\x1f\xcb"
    )
    original = tmp_path / "original.exe"
    candidate = tmp_path / "candidate.exe"
    original.write_bytes(_mz_exe(bytes(original_image)))
    candidate.write_bytes(_mz_exe(bytes(candidate_image)))
    catalog = _edge_catalog("demo.exe:set_pitch", "set_pitch", offset=0x0200, size=0x1B)
    catalog["functions"][0]["return_kind"] = "far"

    output_regs = ("ax", "bp", "ds", "sp", "ss", "ip")
    oracle = lower_straightline_ssa_document(exe_path=original, functions_catalog=catalog, output_regs=output_regs)
    candidate_ssa = lower_straightline_ssa_document(
        exe_path=candidate, functions_catalog=catalog, output_regs=output_regs
    )
    abi_manifest = {
        "schema": "test.abi.v1",
        "data_segment_contract": {"static_data_segment": "0x0100"},
        "functions": [
            {
                "name": "set_pitch",
                "kind": "far",
                "calling_convention": "far_stack_1_loadds",
                "stack_args": [{"bp_offset": "0x0006", "name": "pitch", "width": 16}],
                "preserved": ["bp", "ds"],
                "clobbers": ["ax", "flags"],
                "ssa_observe_regs": ["sp"],
                "effects": [{"space": "DS", "offset": "0x027e", "size": 2, "name": "pitch_clamped"}],
            }
        ],
    }

    compared = compare_ssa_abi_documents(oracle=oracle, candidate=candidate_ssa, abi_manifest=abi_manifest)

    assert compared["summary"]["passed"] == 1


def test_dosunit_compare_ssa_abi_can_ignore_declared_balanced_calls(tmp_path: Path):
    image = bytearray(0x240)
    image[0x200:0x211] = b"\x53\xbb\x01\x00\xe8\x06\x00\x88\x1e\x7b\x02\x5b\xc3\xb8\x34\x12\xc3"
    original = tmp_path / "original.exe"
    candidate = tmp_path / "candidate.exe"
    original.write_bytes(_mz_exe(bytes(image)))
    candidate.write_bytes(_mz_exe(bytes(image)))
    catalog = _edge_catalog("demo.exe:wrapper", "wrapper", offset=0x0200, size=0x0D)

    output_regs = ("ax", "bx", "sp", "ds", "ip", "ss")
    oracle = lower_straightline_ssa_document(exe_path=original, functions_catalog=catalog, output_regs=output_regs)
    candidate_ssa = lower_straightline_ssa_document(
        exe_path=candidate, functions_catalog=catalog, output_regs=output_regs
    )
    abi_manifest = {
        "schema": "test.abi.v1",
        "functions": [
            {
                "name": "wrapper",
                "kind": "near",
                "preserved": ["bx", "ds"],
                "clobbers": ["ax", "flags"],
                "ssa_call_policy": "balanced_ignore",
                "effects": [{"space": "DS", "segment": "ds", "offset": "0x027b", "size": 1, "name": "wrapped_store"}],
            }
        ],
    }

    compared = compare_ssa_abi_documents(oracle=oracle, candidate=candidate_ssa, abi_manifest=abi_manifest)

    assert compared["summary"]["passed"] == 1
    assert compared["results"][0]["observables"]["regs"] == ["bx", "ds", "sp"]


def test_dosunit_compare_ssa_abi_summary_call_checks_stack_argument(tmp_path: Path):
    image = bytearray(0x240)
    image[0x200:0x208] = b"\xb8\x34\x12\x50\xe8\x09\x00\xc3"
    image[0x210] = 0xC3
    original = tmp_path / "original.exe"
    candidate = tmp_path / "candidate.exe"
    original.write_bytes(_mz_exe(bytes(image)))
    candidate.write_bytes(_mz_exe(bytes(image)))
    catalog = _edge_catalog("demo.exe:wrapper", "wrapper", offset=0x0200, size=0x08)

    output_regs = ("ax", "sp", "ip", "ss")
    oracle = lower_straightline_ssa_document(exe_path=original, functions_catalog=catalog, output_regs=output_regs)
    candidate_ssa = lower_straightline_ssa_document(
        exe_path=candidate, functions_catalog=catalog, output_regs=output_regs
    )
    abi_manifest = {
        "schema": "test.abi.v1",
        "functions": [
            {
                "name": "wrapper",
                "kind": "near",
                "ssa_call_policy": "summary",
                "call_summaries": [
                    {
                        "id": "helper_call",
                        "target_low16": "0x1210",
                        "kind": "near",
                        "stack_args": [{"name": "value", "width": 16, "entry_sp_offset": "0x0002"}],
                        "returns": [],
                        "preserved": ["ss"],
                        "clobbers": ["ax", "flags"],
                    }
                ],
            }
        ],
    }

    compared = compare_ssa_abi_documents(oracle=oracle, candidate=candidate_ssa, abi_manifest=abi_manifest)

    assert compared["summary"]["passed"] == 1
    outputs = compared["results"][0]["oracle_summary"]["outputs"]
    assert "callarg:helper_call:value" in outputs


def test_dosunit_compare_ssa_abi_summary_call_fails_changed_stack_argument(tmp_path: Path):
    original_image = bytearray(0x240)
    candidate_image = bytearray(0x240)
    original_image[0x200:0x208] = b"\xb8\x34\x12\x50\xe8\x09\x00\xc3"
    candidate_image[0x200:0x208] = b"\xb8\x35\x12\x50\xe8\x09\x00\xc3"
    original_image[0x210] = 0xC3
    candidate_image[0x210] = 0xC3
    original = tmp_path / "original.exe"
    candidate = tmp_path / "candidate.exe"
    original.write_bytes(_mz_exe(bytes(original_image)))
    candidate.write_bytes(_mz_exe(bytes(candidate_image)))
    catalog = _edge_catalog("demo.exe:wrapper", "wrapper", offset=0x0200, size=0x08)

    output_regs = ("ax", "sp", "ip", "ss")
    oracle = lower_straightline_ssa_document(exe_path=original, functions_catalog=catalog, output_regs=output_regs)
    candidate_ssa = lower_straightline_ssa_document(
        exe_path=candidate, functions_catalog=catalog, output_regs=output_regs
    )
    abi_manifest = {
        "schema": "test.abi.v1",
        "functions": [
            {
                "name": "wrapper",
                "kind": "near",
                "ssa_call_policy": "summary",
                "call_summaries": [
                    {
                        "id": "helper_call",
                        "target_low16": "0x1210",
                        "kind": "near",
                        "stack_args": [{"name": "value", "width": 16, "entry_sp_offset": "0x0002"}],
                        "returns": [],
                        "preserved": ["ss"],
                        "clobbers": ["ax", "flags"],
                    }
                ],
            }
        ],
    }

    compared = compare_ssa_abi_documents(oracle=oracle, candidate=candidate_ssa, abi_manifest=abi_manifest)

    assert compared["summary"]["failed"] == 1
    mismatch = compared["results"][0]["mismatches"][0]
    assert mismatch["kind"] == "output_expr_changed"
    assert mismatch["reg"] == "callarg:helper_call:value"


def test_dosunit_compare_ssa_abi_summary_call_composes_return_register_to_fallthrough_store(tmp_path: Path):
    original_image = bytearray(0x240)
    candidate_image = bytearray(0x240)
    original_image[0x200:0x208] = b"\xe8\x0d\x00\xa3\x7b\x02\x90\xc3"
    candidate_image[0x200:0x208] = b"\xe8\x0d\x00\x89\x1e\x7b\x02\xc3"
    original_image[0x210] = 0xC3
    candidate_image[0x210] = 0xC3
    original = tmp_path / "original.exe"
    candidate = tmp_path / "candidate.exe"
    original.write_bytes(_mz_exe(bytes(original_image)))
    candidate.write_bytes(_mz_exe(bytes(candidate_image)))
    catalog = _edge_catalog("demo.exe:wrapper", "wrapper", offset=0x0200, size=0x08)

    output_regs = ("ax", "bx", "sp", "ip", "ds", "ss")
    oracle = lower_straightline_ssa_document(
        exe_path=original,
        functions_catalog=catalog,
        output_regs=output_regs,
        follow_call_fallthrough=True,
    )
    candidate_ssa = lower_straightline_ssa_document(
        exe_path=candidate,
        functions_catalog=catalog,
        output_regs=output_regs,
        follow_call_fallthrough=True,
    )
    abi_manifest = {
        "schema": "test.abi.v1",
        "functions": [
            {
                "name": "wrapper",
                "kind": "near",
                "ssa_call_policy": "summary",
                "call_summaries": [
                    {
                        "id": "helper_call",
                        "target_low16": "0x1210",
                        "kind": "near",
                        "returns": ["ax"],
                        "preserved": ["ds", "ss"],
                        "clobbers": ["flags"],
                    }
                ],
                "effects": [{"space": "DS", "segment": "ds", "offset": "0x027b", "size": 2, "name": "helper_result"}],
            }
        ],
    }

    compared = compare_ssa_abi_documents(oracle=oracle, candidate=candidate_ssa, abi_manifest=abi_manifest)

    assert compared["summary"]["failed"] == 1
    mismatch = compared["results"][0]["mismatches"][0]
    assert mismatch["kind"] == "output_expr_changed"
    assert mismatch["reg"] == "memory:027b:2:helper_result"


def test_dosunit_compare_ssa_abi_summary_call_broad_memory_clobber_kills_stale_store(tmp_path: Path):
    original_image = bytearray(0x240)
    candidate_image = bytearray(0x240)
    original_image[0x200:0x20C] = b"\xc6\x06\x7b\x02\x11\xe8\x08\x00\xa0\x7b\x02\xc3"
    candidate_image[0x200:0x20C] = b"\xc6\x06\x7b\x02\x22\xe8\x08\x00\xa0\x7b\x02\xc3"
    original_image[0x210] = 0xC3
    candidate_image[0x210] = 0xC3
    original = tmp_path / "original.exe"
    candidate = tmp_path / "candidate.exe"
    original.write_bytes(_mz_exe(bytes(original_image)))
    candidate.write_bytes(_mz_exe(bytes(candidate_image)))
    catalog = _edge_catalog("demo.exe:wrapper", "wrapper", offset=0x0200, size=0x0C)

    output_regs = ("ax", "sp", "ip", "ds", "ss")
    oracle = lower_straightline_ssa_document(
        exe_path=original,
        functions_catalog=catalog,
        output_regs=output_regs,
        follow_call_fallthrough=True,
    )
    candidate_ssa = lower_straightline_ssa_document(
        exe_path=candidate,
        functions_catalog=catalog,
        output_regs=output_regs,
        follow_call_fallthrough=True,
    )
    base_summary = {
        "id": "helper_call",
        "target_low16": "0x1210",
        "kind": "near",
        "returns": [],
        "preserved": ["ds", "ss"],
        "clobbers": ["ax", "flags"],
    }
    no_clobber_manifest = {
        "schema": "test.abi.v1",
        "functions": [
            {
                "name": "wrapper",
                "kind": "near",
                "returns": ["ax"],
                "ssa_call_policy": "summary",
                "call_summaries": [base_summary],
            }
        ],
    }
    clobber_manifest = {
        "schema": "test.abi.v1",
        "functions": [
            {
                "name": "wrapper",
                "kind": "near",
                "returns": ["ax"],
                "ssa_call_policy": "summary",
                "call_summaries": [{**base_summary, "effects": [{"kind": "memory_clobber", "name": "helper_heap"}]}],
            }
        ],
    }

    no_clobber = compare_ssa_abi_documents(oracle=oracle, candidate=candidate_ssa, abi_manifest=no_clobber_manifest)
    clobbered = compare_ssa_abi_documents(oracle=oracle, candidate=candidate_ssa, abi_manifest=clobber_manifest)

    assert no_clobber["summary"]["failed"] == 1
    assert no_clobber["results"][0]["mismatches"][0]["reg"] == "ax"
    assert clobbered["summary"]["passed"] == 1


def test_dosunit_compare_ssa_abi_summary_call_range_memory_clobber_is_not_broad(tmp_path: Path):
    original_image = bytearray(0x240)
    candidate_image = bytearray(0x240)
    original_image[0x200:0x20C] = b"\xc6\x06\x7b\x02\x11\xe8\x08\x00\xa0\x7b\x02\xc3"
    candidate_image[0x200:0x20C] = b"\xc6\x06\x7b\x02\x22\xe8\x08\x00\xa0\x7b\x02\xc3"
    original_image[0x210] = 0xC3
    candidate_image[0x210] = 0xC3
    original = tmp_path / "original.exe"
    candidate = tmp_path / "candidate.exe"
    original.write_bytes(_mz_exe(bytes(original_image)))
    candidate.write_bytes(_mz_exe(bytes(candidate_image)))
    catalog = _edge_catalog("demo.exe:wrapper", "wrapper", offset=0x0200, size=0x0C)

    output_regs = ("ax", "sp", "ip", "ds", "ss")
    oracle = lower_straightline_ssa_document(
        exe_path=original,
        functions_catalog=catalog,
        output_regs=output_regs,
        follow_call_fallthrough=True,
    )
    candidate_ssa = lower_straightline_ssa_document(
        exe_path=candidate,
        functions_catalog=catalog,
        output_regs=output_regs,
        follow_call_fallthrough=True,
    )
    base_summary = {
        "id": "helper_call",
        "target_low16": "0x1210",
        "kind": "near",
        "returns": [],
        "preserved": ["ds", "ss"],
        "clobbers": ["ax", "flags"],
    }

    same_range_manifest = {
        "schema": "test.abi.v1",
        "functions": [
            {
                "name": "wrapper",
                "kind": "near",
                "returns": ["ax"],
                "ssa_call_policy": "summary",
                "call_summaries": [
                    {
                        **base_summary,
                        "effects": [
                            {
                                "kind": "memory_clobber",
                                "name": "helper_byte",
                                "segment": "ds",
                                "offset": "0x027b",
                                "size": 1,
                            }
                        ],
                    }
                ],
            }
        ],
    }
    unrelated_range_manifest = {
        "schema": "test.abi.v1",
        "functions": [
            {
                "name": "wrapper",
                "kind": "near",
                "returns": ["ax"],
                "ssa_call_policy": "summary",
                "call_summaries": [
                    {
                        **base_summary,
                        "effects": [
                            {
                                "kind": "memory_clobber",
                                "name": "helper_other_byte",
                                "segment": "ds",
                                "offset": "0x027c",
                                "size": 1,
                            }
                        ],
                    }
                ],
            }
        ],
    }

    same_range = compare_ssa_abi_documents(oracle=oracle, candidate=candidate_ssa, abi_manifest=same_range_manifest)
    unrelated_range = compare_ssa_abi_documents(
        oracle=oracle,
        candidate=candidate_ssa,
        abi_manifest=unrelated_range_manifest,
    )

    assert same_range["summary"]["passed"] == 1
    assert unrelated_range["summary"]["failed"] == 1
    assert unrelated_range["results"][0]["mismatches"][0]["reg"] == "ax"


def test_dosunit_compare_ssa_abi_summary_call_broad_memory_clobber_keeps_load_address_observable(tmp_path: Path):
    original_image = bytearray(0x240)
    candidate_image = bytearray(0x240)
    original_image[0x200:0x20C] = b"\xc6\x06\x7b\x02\x11\xe8\x08\x00\xa0\x7b\x02\xc3"
    candidate_image[0x200:0x20C] = b"\xc6\x06\x7b\x02\x11\xe8\x08\x00\xa0\x7c\x02\xc3"
    original_image[0x210] = 0xC3
    candidate_image[0x210] = 0xC3
    original = tmp_path / "original.exe"
    candidate = tmp_path / "candidate.exe"
    original.write_bytes(_mz_exe(bytes(original_image)))
    candidate.write_bytes(_mz_exe(bytes(candidate_image)))
    catalog = _edge_catalog("demo.exe:wrapper", "wrapper", offset=0x0200, size=0x0C)

    output_regs = ("ax", "sp", "ip", "ds", "ss")
    oracle = lower_straightline_ssa_document(
        exe_path=original,
        functions_catalog=catalog,
        output_regs=output_regs,
        follow_call_fallthrough=True,
    )
    candidate_ssa = lower_straightline_ssa_document(
        exe_path=candidate,
        functions_catalog=catalog,
        output_regs=output_regs,
        follow_call_fallthrough=True,
    )
    abi_manifest = {
        "schema": "test.abi.v1",
        "functions": [
            {
                "name": "wrapper",
                "kind": "near",
                "returns": ["ax"],
                "ssa_call_policy": "summary",
                "call_summaries": [
                    {
                        "id": "helper_call",
                        "target_low16": "0x1210",
                        "kind": "near",
                        "returns": [],
                        "preserved": ["ds", "ss"],
                        "clobbers": ["ax", "flags"],
                        "effects": [{"kind": "memory_clobber", "name": "helper_heap"}],
                    }
                ],
            }
        ],
    }

    compared = compare_ssa_abi_documents(oracle=oracle, candidate=candidate_ssa, abi_manifest=abi_manifest)

    assert compared["summary"]["failed"] == 1
    assert compared["results"][0]["mismatches"][0]["reg"] == "ax"


def test_dosunit_compare_ssa_abi_summary_call_uses_target_ordinal_for_repeated_callee(tmp_path: Path):
    image = bytearray(0x240)
    image[0x200:0x20F] = b"\xb8\x11\x11\x50\xe8\x09\x00\xb8\x22\x22\x50\xe8\x02\x00\xc3"
    image[0x210] = 0xC3
    original = tmp_path / "original.exe"
    candidate = tmp_path / "candidate.exe"
    original.write_bytes(_mz_exe(bytes(image)))
    candidate.write_bytes(_mz_exe(bytes(image)))
    catalog = _edge_catalog("demo.exe:wrapper", "wrapper", offset=0x0200, size=0x0F)

    output_regs = ("ax", "sp", "ip", "ss")
    oracle = lower_straightline_ssa_document(
        exe_path=original,
        functions_catalog=catalog,
        output_regs=output_regs,
        follow_call_fallthrough=True,
    )
    candidate_ssa = lower_straightline_ssa_document(
        exe_path=candidate,
        functions_catalog=catalog,
        output_regs=output_regs,
        follow_call_fallthrough=True,
    )
    abi_manifest = _repeated_helper_call_abi_manifest()

    compared = compare_ssa_abi_documents(oracle=oracle, candidate=candidate_ssa, abi_manifest=abi_manifest)

    assert compared["summary"]["passed"] == 1
    outputs = set(compared["results"][0]["oracle_summary"]["outputs"])
    assert "callarg:first_helper:value" in outputs
    assert "callarg:second_helper:value" in outputs


def test_dosunit_compare_ssa_abi_summary_call_repeated_callee_fails_changed_second_arg(tmp_path: Path):
    original_image = bytearray(0x240)
    candidate_image = bytearray(0x240)
    original_image[0x200:0x20F] = b"\xb8\x11\x11\x50\xe8\x09\x00\xb8\x22\x22\x50\xe8\x02\x00\xc3"
    candidate_image[0x200:0x20F] = b"\xb8\x11\x11\x50\xe8\x09\x00\xb8\x23\x22\x50\xe8\x02\x00\xc3"
    original_image[0x210] = 0xC3
    candidate_image[0x210] = 0xC3
    original = tmp_path / "original.exe"
    candidate = tmp_path / "candidate.exe"
    original.write_bytes(_mz_exe(bytes(original_image)))
    candidate.write_bytes(_mz_exe(bytes(candidate_image)))
    catalog = _edge_catalog("demo.exe:wrapper", "wrapper", offset=0x0200, size=0x0F)

    output_regs = ("ax", "sp", "ip", "ss")
    oracle = lower_straightline_ssa_document(
        exe_path=original,
        functions_catalog=catalog,
        output_regs=output_regs,
        follow_call_fallthrough=True,
    )
    candidate_ssa = lower_straightline_ssa_document(
        exe_path=candidate,
        functions_catalog=catalog,
        output_regs=output_regs,
        follow_call_fallthrough=True,
    )
    abi_manifest = _repeated_helper_call_abi_manifest()

    compared = compare_ssa_abi_documents(oracle=oracle, candidate=candidate_ssa, abi_manifest=abi_manifest)

    assert compared["summary"]["failed"] == 1
    mismatch = compared["results"][0]["mismatches"][0]
    assert mismatch["kind"] == "output_expr_changed"
    assert mismatch["reg"] == "callarg:second_helper:value"


def test_dosunit_compare_ssa_abi_summary_call_can_select_by_callsite_delta(tmp_path: Path):
    image = bytearray(0x240)
    image[0x200:0x20F] = b"\xb8\x11\x11\x50\xe8\x09\x00\xb8\x22\x22\x50\xe8\x02\x00\xc3"
    image[0x210] = 0xC3
    original = tmp_path / "original.exe"
    candidate = tmp_path / "candidate.exe"
    original.write_bytes(_mz_exe(bytes(image)))
    candidate.write_bytes(_mz_exe(bytes(image)))
    catalog = _edge_catalog("demo.exe:wrapper", "wrapper", offset=0x0200, size=0x0F)

    output_regs = ("ax", "sp", "ip", "ss")
    oracle = lower_straightline_ssa_document(
        exe_path=original,
        functions_catalog=catalog,
        output_regs=output_regs,
        follow_call_fallthrough=True,
    )
    candidate_ssa = lower_straightline_ssa_document(
        exe_path=candidate,
        functions_catalog=catalog,
        output_regs=output_regs,
        follow_call_fallthrough=True,
    )
    abi_manifest = _repeated_helper_call_abi_manifest()
    first, second = abi_manifest["functions"][0]["call_summaries"]
    first.pop("target_ordinal")
    second.pop("target_ordinal")
    first["callsite_entry_delta"] = "0x0000"
    second["callsite_entry_delta"] = "0x0007"

    compared = compare_ssa_abi_documents(oracle=oracle, candidate=candidate_ssa, abi_manifest=abi_manifest)

    assert compared["summary"]["passed"] == 1
    outputs = set(compared["results"][0]["oracle_summary"]["outputs"])
    assert "callarg:first_helper:value" in outputs
    assert "callarg:second_helper:value" in outputs


def test_dosunit_compare_ssa_abi_summary_call_supports_indirect_callsite_selector(tmp_path: Path):
    image = bytearray(0x240)
    image[0x200:0x207] = b"\xb8\x34\x12\x50\xff\xd3\xc3"
    original = tmp_path / "original.exe"
    candidate = tmp_path / "candidate.exe"
    original.write_bytes(_mz_exe(bytes(image)))
    candidate.write_bytes(_mz_exe(bytes(image)))
    catalog = _edge_catalog("demo.exe:wrapper", "wrapper", offset=0x0200, size=0x07)

    output_regs = ("ax", "bx", "sp", "ip", "ss")
    oracle = lower_straightline_ssa_document(exe_path=original, functions_catalog=catalog, output_regs=output_regs)
    candidate_ssa = lower_straightline_ssa_document(
        exe_path=candidate, functions_catalog=catalog, output_regs=output_regs
    )
    abi_manifest = {
        "schema": "test.abi.v1",
        "functions": [
            {
                "name": "wrapper",
                "kind": "near",
                "ssa_call_policy": "summary",
                "call_summaries": [
                    {
                        "id": "indirect_helper",
                        "callsite_entry_delta": "0x0000",
                        "kind": "near",
                        "stack_args": [{"name": "value", "width": 16, "entry_sp_offset": "0x0002"}],
                        "returns": [],
                        "preserved": ["ss"],
                        "clobbers": ["ax", "flags"],
                    }
                ],
            }
        ],
    }

    compared = compare_ssa_abi_documents(oracle=oracle, candidate=candidate_ssa, abi_manifest=abi_manifest)

    assert compared["summary"]["passed"] == 1
    outputs = set(compared["results"][0]["oracle_summary"]["outputs"])
    assert "callarg:indirect_helper:value" in outputs


def test_dosunit_compare_ssa_abi_summary_call_supports_recovered_indirect_target_set(tmp_path: Path):
    image = bytearray(0x240)
    image[0x200:0x207] = b"\xb8\x34\x12\x50\xff\xd3\xc3"
    original = tmp_path / "original.exe"
    candidate = tmp_path / "candidate.exe"
    original.write_bytes(_mz_exe(bytes(image)))
    candidate.write_bytes(_mz_exe(bytes(image)))
    catalog = _edge_catalog("demo.exe:wrapper", "wrapper", offset=0x0200, size=0x07)

    output_regs = ("ax", "bx", "sp", "ip", "ss")
    oracle = lower_straightline_ssa_document(exe_path=original, functions_catalog=catalog, output_regs=output_regs)
    candidate_ssa = lower_straightline_ssa_document(
        exe_path=candidate, functions_catalog=catalog, output_regs=output_regs
    )
    for document in (oracle, candidate_ssa):
        transfer = document["functions"][0]["source"]["transfer"]
        transfer["target_candidates"] = [
            {"low16": "0x4321"},
            {"low16": "0x5678"},
        ]
    abi_manifest = {
        "schema": "test.abi.v1",
        "functions": [
            {
                "name": "wrapper",
                "kind": "near",
                "ssa_call_policy": "summary",
                "call_summaries": [
                    {
                        "id": "indirect_set_helper",
                        "target_low16s": ["0x5678", "0x9abc"],
                        "kind": "near",
                        "stack_args": [{"name": "value", "width": 16, "entry_sp_offset": "0x0002"}],
                        "returns": [],
                        "preserved": ["ss"],
                        "clobbers": ["ax", "flags"],
                    }
                ],
            }
        ],
    }

    compared = compare_ssa_abi_documents(oracle=oracle, candidate=candidate_ssa, abi_manifest=abi_manifest)

    assert compared["summary"]["passed"] == 1
    outputs = set(compared["results"][0]["oracle_summary"]["outputs"])
    assert "callarg:indirect_set_helper:value" in outputs


def test_dosunit_compare_ssa_abi_msc_prologue_policy_refuses_non_prologue_calls(tmp_path: Path):
    image = bytearray(0x240)
    image[0x200:0x211] = b"\x53\xbb\x01\x00\xe8\x06\x00\x88\x1e\x7b\x02\x5b\xc3\xb8\x34\x12\xc3"
    original = tmp_path / "original.exe"
    candidate = tmp_path / "candidate.exe"
    original.write_bytes(_mz_exe(bytes(image)))
    candidate.write_bytes(_mz_exe(bytes(image)))
    catalog = _edge_catalog("demo.exe:wrapper", "wrapper", offset=0x0200, size=0x0D)

    output_regs = ("ax", "bx", "sp", "ds", "ip", "ss")
    oracle = lower_straightline_ssa_document(exe_path=original, functions_catalog=catalog, output_regs=output_regs)
    candidate_ssa = lower_straightline_ssa_document(
        exe_path=candidate, functions_catalog=catalog, output_regs=output_regs
    )
    abi_manifest = {
        "schema": "test.abi.v1",
        "functions": [
            {
                "name": "wrapper",
                "kind": "near",
                "returns": ["ax"],
                "preserved": ["bx", "ds"],
                "ssa_call_policy": "msc_prologue_stack_check",
            }
        ],
    }

    compared = compare_ssa_abi_documents(oracle=oracle, candidate=candidate_ssa, abi_manifest=abi_manifest)

    assert compared["summary"]["refused"] == 1
    assert compared["results"][0]["reason"] == "call_boundary"


def test_dosunit_compare_ssa_abi_bounded_loop_unroll(tmp_path: Path):
    image = bytearray(0x240)
    image[0x200:0x214] = bytes.fromhex("558bec31c08b4e0485c97e044049ebf88be55dc3")
    original = tmp_path / "original.exe"
    candidate = tmp_path / "candidate.exe"
    original.write_bytes(_mz_exe(bytes(image)))
    candidate.write_bytes(_mz_exe(bytes(image)))
    catalog = _edge_catalog("demo.exe:countdown", "countdown", offset=0x0200, size=0x14)
    output_regs = ("ax", "bp", "sp", "ip", "ss")
    oracle = lower_straightline_ssa_document(
        exe_path=original,
        functions_catalog=catalog,
        output_regs=output_regs,
        max_blocks_per_function=16,
    )
    candidate_ssa = lower_straightline_ssa_document(
        exe_path=candidate,
        functions_catalog=catalog,
        output_regs=output_regs,
        max_blocks_per_function=16,
    )
    abi_manifest = {
        "schema": "test.abi.v1",
        "functions": [
            {
                "name": "countdown",
                "kind": "near",
                "returns": ["ax"],
                "preserved": ["bp"],
            }
        ],
    }

    refused = compare_ssa_abi_documents(oracle=oracle, candidate=candidate_ssa, abi_manifest=abi_manifest)
    compared = compare_ssa_abi_documents(
        oracle=oracle,
        candidate=candidate_ssa,
        abi_manifest=abi_manifest,
        max_loop_unroll=2,
    )

    assert refused["summary"]["refused"] == 1
    assert compared["summary"]["passed"] == 1
    assert compared["results"][0]["oracle_summary"]["loop_cuts"] > 0


def test_dosunit_compare_ssa_abi_accepts_watcom_register_c_rewrite_with_different_clobbers():
    oracle = _watcom_register_abi_doc(
        "original-asm.exe",
        function_id="demo.exe:asm_adlib_mix",
        name="asm_adlib_mix",
        style="asm",
    )
    candidate = _watcom_register_abi_doc(
        "rewritten-c.exe",
        function_id="demo.exe:c_adlib_mix",
        name="c_adlib_mix",
        style="watcom_c",
    )

    compared = compare_ssa_abi_documents(
        oracle=oracle,
        candidate=candidate,
        abi_manifest=_watcom_register_abi_manifest(),
        mapping_document=_watcom_register_abi_mapping(),
    )

    assert compared["summary"]["total"] == 1
    assert compared["summary"]["passed"] == 1
    assert compared["summary"]["failed"] == 0
    assert compared["summary"]["refused"] == 0
    result = compared["results"][0]
    assert result["mapped_candidate"]["name"] == "c_adlib_mix"
    assert result["observables"]["regs"] == ["ax", "bp", "ds", "dx", "sp"]
    assert "bx" not in result["observables"]["regs"]
    assert "cx" not in result["observables"]["regs"]
    assert result["status"] == "passed"
    report = render_failure_report(compared)
    assert "DOS Unit ABI SSA Report" in report
    assert "No failed or refused ABI functions." in report


def test_dosunit_compare_ssa_abi_fails_watcom_register_c_rewrite_visible_return_change():
    oracle = _watcom_register_abi_doc(
        "original-asm.exe",
        function_id="demo.exe:asm_adlib_mix",
        name="asm_adlib_mix",
        style="asm",
    )
    candidate = _watcom_register_abi_doc(
        "rewritten-c.exe",
        function_id="demo.exe:c_adlib_mix",
        name="c_adlib_mix",
        style="watcom_c_bug",
    )

    compared = compare_ssa_abi_documents(
        oracle=oracle,
        candidate=candidate,
        abi_manifest=_watcom_register_abi_manifest(),
        mapping_document=_watcom_register_abi_mapping(),
    )

    assert compared["summary"]["passed"] == 0
    assert compared["summary"]["failed"] == 1
    result = compared["results"][0]
    assert result["status"] == "failed"
    assert result["reason"] == "observable_mismatch"
    assert any(
        mismatch.get("kind") == "output_expr_changed" and mismatch.get("reg") == "dx"
        for mismatch in result["mismatches"]
    )
    report = render_failure_report(compared)
    assert "Calling convention: `watcom_register_ax_dx`" in report
    assert "Register: `dx`" in report


def test_dosunit_cli_compare_ssa_abi_handles_synthetic_watcom_register_manifest(tmp_path: Path):
    oracle = _watcom_register_abi_doc(
        "original-asm.exe",
        function_id="demo.exe:asm_adlib_mix",
        name="asm_adlib_mix",
        style="asm",
    )
    candidate = _watcom_register_abi_doc(
        "rewritten-c.exe",
        function_id="demo.exe:c_adlib_mix",
        name="c_adlib_mix",
        style="watcom_c",
    )
    oracle_path = tmp_path / "original-asm.ssa.json"
    candidate_path = tmp_path / "rewritten-c.ssa.json"
    manifest_path = tmp_path / "watcom-register-abi.json"
    mapping_path = tmp_path / "mapping.json"
    out_path = tmp_path / "abi.compare.json"
    report_path = tmp_path / "abi.report.md"
    oracle_path.write_text(json.dumps(oracle))
    candidate_path.write_text(json.dumps(candidate))
    manifest_path.write_text(json.dumps(_watcom_register_abi_manifest()))
    mapping_path.write_text(json.dumps(_watcom_register_abi_mapping()))

    rc = dosunit_main(
        [
            "compare-ssa-abi",
            "--oracle-ssa",
            str(oracle_path),
            "--candidate-ssa",
            str(candidate_path),
            "--abi-manifest",
            str(manifest_path),
            "--mapping",
            str(mapping_path),
            "--max-rss-mb",
            "0",
            "--out",
            str(out_path),
        ]
    )

    assert rc == 0
    document = json.loads(out_path.read_text())
    assert document["summary"]["passed"] == 1
    assert document["results"][0]["function"]["calling_convention"] == "watcom_register_ax_dx"
    assert document["results"][0]["mapped_candidate"]["id"] == "demo.exe:c_adlib_mix"
    assert dosunit_main(["report-failures", "--results", str(out_path), "--out", str(report_path)]) == 0
    report = report_path.read_text()
    assert "DOS Unit ABI SSA Report" in report
    assert "No failed or refused ABI functions." in report


def test_dosunit_compare_ssa_abi_proves_stack_arg_branch_loop_rewrite():
    oracle = _stack_arg_loop_abi_doc(
        "original-asm.exe",
        function_id="demo.exe:asm_apply_boost",
        name="asm_apply_boost",
        style="asm_loop",
    )
    candidate = _stack_arg_loop_abi_doc(
        "rewritten-c.exe",
        function_id="demo.exe:c_apply_boost",
        name="c_apply_boost",
        style="watcom_c_branch",
    )

    compared = compare_ssa_abi_documents(
        oracle=oracle,
        candidate=candidate,
        abi_manifest=_stack_arg_loop_abi_manifest(),
        mapping_document=_stack_arg_loop_abi_mapping(),
        max_loop_unroll=2,
    )

    assert compared["summary"]["passed"] == 1
    result = compared["results"][0]
    assert result["function"]["stack_args"] == [{"name": "boost", "width": 16, "entry_sp_offset": "0x0002"}]
    assert result["observables"]["regs"] == ["ax", "bp", "ds", "sp"]
    assert result["observables"]["memory"][0]["name"] == "last_boosted_value"
    assert result["oracle_summary"]["loop_cuts"] > 0
    assert result["candidate_summary"]["loop_cuts"] == 0
    assert result["reason"] in {None, "ssa_equal"}


def test_dosunit_compare_ssa_matches_mapped_parts_by_entry_delta_before_index():
    oracle_function = _ssa_stub("oracle.exe:dispatch", "dispatch", ip="0x010b", linear="0x110b")
    oracle_function["id"] = "ssa-function:oracle-dispatch-delta-000b"
    oracle_function["part"] = {"kind": "block", "index": 1, "entry_delta": "0x000b"}
    oracle_function["outputs"] = {"ax": {"op": "const", "value": "0x0001", "width": 16}}

    wrong_index_candidate = _ssa_stub("candidate.exe:dispatch", "dispatch", ip="0x011a", linear="0x111a")
    wrong_index_candidate["id"] = "ssa-function:candidate-wrong-index"
    wrong_index_candidate["part"] = {"kind": "block", "index": 1, "entry_delta": "0x001a"}
    wrong_index_candidate["outputs"] = {"ax": {"op": "const", "value": "0x0002", "width": 16}}

    matching_delta_candidate = _ssa_stub("candidate.exe:dispatch", "dispatch", ip="0x010b", linear="0x110b")
    matching_delta_candidate["id"] = "ssa-function:candidate-matching-delta"
    matching_delta_candidate["part"] = {"kind": "block", "index": 2, "entry_delta": "0x000b"}
    matching_delta_candidate["outputs"] = {"ax": {"op": "const", "value": "0x0001", "width": 16}}

    mapping = {
        "schema": "dosunit.mapping.v1",
        "id": "mapping:test",
        "functions": [
            {
                "oracle_id": "oracle.exe:dispatch",
                "oracle_name": "dispatch",
                "candidate_id": "candidate.exe:dispatch",
                "candidate_name": "dispatch",
            }
        ],
    }

    compared = compare_ssa_documents(
        oracle={"schema": "dosunit.ssa.v1", "exe": "oracle.exe", "functions": [oracle_function]},
        candidate={
            "schema": "dosunit.ssa.v1",
            "exe": "candidate.exe",
            "functions": [wrong_index_candidate, matching_delta_candidate],
        },
        mapping_document=mapping,
    )

    assert compared["summary"]["passed"] == 1
    assert compared["results"][0]["candidate_function"] == "ssa-function:candidate-matching-delta"


def test_dosunit_compare_ssa_does_not_pair_delta_block_by_index_when_delta_missing():
    oracle_function = _ssa_stub("oracle.exe:dispatch", "dispatch", ip="0x010b", linear="0x110b")
    oracle_function["id"] = "ssa-function:oracle-dispatch-delta-000b"
    oracle_function["part"] = {"kind": "block", "index": 1, "entry_delta": "0x000b"}
    oracle_function["outputs"] = {"ax": {"op": "const", "value": "0x0001", "width": 16}}

    wrong_index_candidate = _ssa_stub("candidate.exe:dispatch", "dispatch", ip="0x011a", linear="0x111a")
    wrong_index_candidate["id"] = "ssa-function:candidate-wrong-index"
    wrong_index_candidate["part"] = {"kind": "block", "index": 1, "entry_delta": "0x001a"}
    wrong_index_candidate["outputs"] = {"ax": {"op": "const", "value": "0x0002", "width": 16}}

    mapping = {
        "schema": "dosunit.mapping.v1",
        "id": "mapping:test",
        "functions": [
            {
                "oracle_id": "oracle.exe:dispatch",
                "oracle_name": "dispatch",
                "candidate_id": "candidate.exe:dispatch",
                "candidate_name": "dispatch",
            }
        ],
    }

    compared = compare_ssa_documents(
        oracle={"schema": "dosunit.ssa.v1", "exe": "oracle.exe", "functions": [oracle_function]},
        candidate={"schema": "dosunit.ssa.v1", "exe": "candidate.exe", "functions": [wrong_index_candidate]},
        mapping_document=mapping,
        enable_region_equality=False,
        enable_connectivity=False,
    )

    assert compared["summary"]["failed"] == 0
    assert compared["summary"]["refused"] == 1
    assert compared["results"][0]["reason"] == "candidate_ssa_missing"
    assert compared["results"][0]["candidate_function"] is None


def test_dosunit_compare_ssa_matches_unique_normalized_block_signature_when_delta_shifted():
    oracle_function = _ssa_stub("oracle.exe:itoa", "itoa", ip="0xf20e", linear="0x1020e")
    oracle_function["id"] = "ssa-function:oracle-itoa-chunk"
    oracle_function["part"] = {"kind": "block", "index": 3, "entry_delta": "0x07d4"}
    oracle_function["source"]["instructions"] = [
        {
            "address": {"ip": "0xf20e", "linear": "0x1020e"},
            "bytes": "e90001",
            "disassembly": "jmp 0xf311 (0x10311)",
            "mnemonic": "jmp",
            "op_str": "0x10311",
            "size": 3,
        }
    ]

    candidate_function = _ssa_stub("candidate.exe:itoa", "itoa", ip="0xf4ec", linear="0x104ec")
    candidate_function["id"] = "ssa-function:candidate-itoa-chunk"
    candidate_function["part"] = {"kind": "block", "index": 9, "entry_delta": "0x0154"}
    candidate_function["source"]["instructions"] = [
        {
            "address": {"ip": "0xf4ec", "linear": "0x104ec"},
            "bytes": "e93412",
            "disassembly": "jmp 0x10723 (0x10723)",
            "mnemonic": "jmp",
            "op_str": "0x10723",
            "size": 3,
        }
    ]

    mapping = {
        "schema": "dosunit.mapping.v1",
        "id": "mapping:test",
        "functions": [
            {
                "oracle_id": "oracle.exe:itoa",
                "oracle_name": "itoa",
                "candidate_id": "candidate.exe:itoa",
                "candidate_name": "itoa",
            }
        ],
    }

    compared = compare_ssa_documents(
        oracle={"schema": "dosunit.ssa.v1", "exe": "oracle.exe", "functions": [oracle_function]},
        candidate={"schema": "dosunit.ssa.v1", "exe": "candidate.exe", "functions": [candidate_function]},
        mapping_document=mapping,
        enable_region_equality=False,
        enable_connectivity=False,
    )

    assert compared["summary"]["passed"] == 1
    assert compared["results"][0]["candidate_function"] == "ssa-function:candidate-itoa-chunk"


def test_dosunit_compare_ssa_matches_unique_exact_block_signature_before_normalized_signature():
    oracle_function = _ssa_stub("oracle.exe:open", "open", ip="0xee35", linear="0xfe35")
    oracle_function["id"] = "ssa-function:oracle-open-dosret"
    oracle_function["part"] = {"kind": "block", "index": 14, "entry_delta": "0xfb41"}
    oracle_function["source"]["instructions"] = [
        {
            "address": {"ip": "0xee35", "linear": "0xfe35"},
            "bytes": "7307",
            "disassembly": "jae 0xee3e (0xfe3e)",
            "mnemonic": "jae",
            "op_str": "0xfe3e",
            "size": 2,
        }
    ]

    candidate_function = _ssa_stub("candidate.exe:open", "open", ip="0xe601", linear="0xf601")
    candidate_function["id"] = "ssa-function:candidate-open-dosret"
    candidate_function["part"] = {"kind": "block", "index": 14, "entry_delta": "0xf931"}
    candidate_function["source"]["instructions"] = [
        {
            "address": {"ip": "0xe601", "linear": "0xf601"},
            "bytes": "7307",
            "disassembly": "jae 0xe60a (0xf60a)",
            "mnemonic": "jae",
            "op_str": "0xf60a",
            "size": 2,
        }
    ]

    mapping = {
        "schema": "dosunit.mapping.v1",
        "id": "mapping:test",
        "functions": [
            {
                "oracle_id": "oracle.exe:open",
                "oracle_name": "open",
                "candidate_id": "candidate.exe:open",
                "candidate_name": "open",
            }
        ],
    }

    compared = compare_ssa_documents(
        oracle={"schema": "dosunit.ssa.v1", "exe": "oracle.exe", "functions": [oracle_function]},
        candidate={"schema": "dosunit.ssa.v1", "exe": "candidate.exe", "functions": [candidate_function]},
        mapping_document=mapping,
        enable_region_equality=False,
        enable_connectivity=False,
    )

    assert compared["summary"]["passed"] == 1
    assert compared["results"][0]["candidate_function"] == "ssa-function:candidate-open-dosret"


def test_dosunit_compare_ssa_matches_mapped_candidate_shared_tail_by_signature():
    oracle_function = _ssa_stub("oracle.exe:lseek", "lseek", ip="0xee35", linear="0xfe35")
    oracle_function["id"] = "ssa-function:oracle-lseek-shared-tail"
    oracle_function["part"] = {"kind": "block", "index": 12, "entry_delta": "0x0503"}
    oracle_function["source"]["function_machine_code_size"] = 0x0600
    oracle_function["source"]["instructions"] = [
        {
            "address": {"ip": "0xee35", "linear": "0xfe35"},
            "bytes": "7307",
            "disassembly": "jae 0xee3e (0xfe3e)",
            "mnemonic": "jae",
            "op_str": "0xfe3e",
            "size": 2,
        }
    ]

    candidate_function = _ssa_stub("candidate.exe:lseek", "lseek", ip="0xe601", linear="0xf601")
    candidate_function["id"] = "ssa-function:candidate-lseek-shared-tail"
    candidate_function["part"] = {"kind": "block", "index": 12, "entry_delta": "0xf9ab"}
    candidate_function["source"]["function_machine_code_size"] = 0x0100
    candidate_function["source"]["instructions"] = [
        {
            "address": {"ip": "0xe601", "linear": "0xf601"},
            "bytes": "7307",
            "disassembly": "jae 0xe60a (0xf60a)",
            "mnemonic": "jae",
            "op_str": "0xf60a",
            "size": 2,
        }
    ]

    mapping = {
        "schema": "dosunit.mapping.v1",
        "id": "mapping:test",
        "functions": [
            {
                "oracle_id": "oracle.exe:lseek",
                "oracle_name": "lseek",
                "candidate_id": "candidate.exe:lseek",
                "candidate_name": "lseek",
            }
        ],
    }

    compared = compare_ssa_documents(
        oracle={"schema": "dosunit.ssa.v1", "exe": "oracle.exe", "functions": [oracle_function]},
        candidate={"schema": "dosunit.ssa.v1", "exe": "candidate.exe", "functions": [candidate_function]},
        mapping_document=mapping,
        enable_region_equality=False,
        enable_connectivity=False,
    )

    assert compared["summary"]["passed"] == 1
    assert compared["results"][0]["candidate_function"] == "ssa-function:candidate-lseek-shared-tail"


def test_dosunit_compare_ssa_connectivity_uses_paired_candidate_shared_tail_body():
    oracle_pred = _ssa_block_stub("oracle.exe:lseek", "lseek", base=0x1000, delta=0x0000, index=0, successors=[0x0010])
    oracle_succ = _ssa_block_stub("oracle.exe:lseek", "lseek", base=0x1000, delta=0x0010, index=1)
    candidate_pred = _ssa_block_stub(
        "candidate.exe:lseek", "lseek", base=0x2000, delta=0xF000, index=0, successors=[0xF010]
    )
    candidate_succ = _ssa_block_stub("candidate.exe:lseek", "lseek", base=0x2000, delta=0xF010, index=1)
    for function, raw_bytes in (
        (oracle_pred, "eb0e"),
        (candidate_pred, "eb0e"),
        (oracle_succ, "c3"),
        (candidate_succ, "c3"),
    ):
        function["source"]["function_machine_code_size"] = 0x0020
        function["source"]["instructions"][0]["bytes"] = raw_bytes
        function["source"]["instructions"][0]["mnemonic"] = "jmp" if raw_bytes == "eb0e" else "ret"
        function["source"]["instructions"][0]["op_str"] = "0x0010" if raw_bytes == "eb0e" else ""
    oracle_succ["inputs"] = [{"name": "ax", "width": 16}]
    candidate_succ["inputs"] = [{"name": "ax", "width": 16}]
    mapping = {
        "schema": "dosunit.mapping.v1",
        "id": "mapping:test",
        "functions": [
            {
                "oracle_id": "oracle.exe:lseek",
                "oracle_name": "lseek",
                "candidate_id": "candidate.exe:lseek",
                "candidate_name": "lseek",
            }
        ],
    }

    compared = compare_ssa_documents(
        oracle={"schema": "dosunit.ssa.v1", "exe": "oracle.exe", "functions": [oracle_pred, oracle_succ]},
        candidate={"schema": "dosunit.ssa.v1", "exe": "candidate.exe", "functions": [candidate_pred, candidate_succ]},
        mapping_document=mapping,
        enable_region_equality=False,
    )

    assert compared["summary"]["refused"] == 0
    assert compared["connectivity"]["status"] == "passed"
    assert compared["connectivity"]["state_edges_checked"] == 1


def test_dosunit_region_precompose_gate_refuses_branch_fanout_before_path_explosion():
    blocks = [
        _ssa_block_stub("demo.exe:branchy", "branchy", base=0x1000, delta=index * 4, index=index, successors=[0, 4])
        for index in range(33)
    ]

    gate = straightline_ssa._region_precompose_memory_gate(blocks, blocks, max_rss_mb=4096)

    assert gate is not None
    assert gate["kind"] == "solver_gate"
    assert gate["reason"] == "slice_too_large"
    assert gate["metric"] == "region_conditional_blocks"
    assert gate["value"] == 33
    assert gate["limit"] == 32


def test_dosunit_region_mismatch_with_unproven_callee_is_refusal_evidence():
    assert straightline_ssa._region_mismatches_blocked_by_unproven_call(
        [
            {
                "kind": "memory_expr_changed",
                "call_compare": {"equivalent": False, "reason": "no mapping proves direct call target equivalence"},
            }
        ]
    )
    assert not straightline_ssa._region_mismatches_blocked_by_unproven_call(
        [{"kind": "memory_expr_changed", "call_compare": {"equivalent": True}}]
    )
    assert not straightline_ssa._region_mismatches_blocked_by_unproven_call(
        [{"kind": "memory_expr_changed"}]
    )


def test_dosunit_compare_ssa_accepts_both_sides_stopping_at_indirect_call():
    oracle_function = _ssa_stub("oracle.exe:dispatch", "dispatch", ip="0x0200", linear="0x1200", jumpkind="Ijk_Call")
    candidate_function = _ssa_stub(
        "candidate.exe:dispatch", "dispatch", ip="0x0300", linear="0x1300", jumpkind="Ijk_Call"
    )

    compared = compare_ssa_documents(
        oracle={"schema": "dosunit.ssa.v1", "exe": "oracle.exe", "functions": [oracle_function]},
        candidate={"schema": "dosunit.ssa.v1", "exe": "candidate.exe", "functions": [candidate_function]},
    )

    assert compared["summary"]["passed"] == 1
    assert compared["results"][0]["call_compare"]["equivalent"] is True
    assert compared["results"][0]["call_compare"]["reason"] == "both call targets are indirect expressions"


def test_dosunit_compare_ssa_reports_output_set_changes():
    oracle_function = _ssa_stub("demo.exe:leaf", "leaf", ip="0x0200", linear="0x1200")
    candidate_function = _ssa_stub("demo.exe:leaf", "leaf", ip="0x0200", linear="0x1200")
    candidate_function["outputs"] = {
        **candidate_function["outputs"],
        "dx": {"op": "const", "value": "0x0000", "width": 16},
    }
    oracle = {"schema": "dosunit.ssa.v1", "exe": "oracle.exe", "functions": [oracle_function]}
    candidate = {"schema": "dosunit.ssa.v1", "exe": "candidate.exe", "functions": [candidate_function]}

    compared = compare_ssa_documents(oracle=oracle, candidate=candidate)

    assert compared["summary"]["failed"] == 1
    mismatch = compared["results"][0]["mismatches"][0]
    assert mismatch["kind"] == "output_set_changed"
    assert mismatch["candidate_only"] == ["dx"]


def test_dosunit_compare_ssa_normalizes_layout_memory_operands():
    oracle_function = _manual_ssa_function(
        "global_load",
        ["mov ax, word ptr [0x61fe]"],
        inputs=[{"kind": "memory", "name": "mem", "addr_width": 32, "value_width": 8}],
        assignments=[
            {
                "id": "v0",
                "op": "loadle",
                "width": 16,
                "args": [
                    {"op": "mem_input", "name": "mem", "addr_width": 32, "value_width": 8},
                    {"op": "const", "value": "0x61fe", "width": 32},
                ],
            }
        ],
        outputs={"ax": {"ref": "v0"}},
    )
    candidate_function = _manual_ssa_function(
        "global_load",
        ["mov ax, word ptr [0xa0e8]"],
        inputs=[{"kind": "memory", "name": "mem", "addr_width": 32, "value_width": 8}],
        assignments=[
            {
                "id": "v0",
                "op": "loadle",
                "width": 16,
                "args": [
                    {"op": "mem_input", "name": "mem", "addr_width": 32, "value_width": 8},
                    {"op": "const", "value": "0xa0e8", "width": 32},
                ],
            }
        ],
        outputs={"ax": {"ref": "v0"}},
    )

    compared = compare_ssa_documents(oracle=_ssa_doc(oracle_function), candidate=_ssa_doc(candidate_function))

    assert compared["summary"]["passed"] == 1
    assert compared["results"][0]["layout_normalization"]["pairs"] == [
        {"oracle": "0x61fe", "candidate": "0xa0e8", "reason": "absolute_memory_operand"}
    ]


def test_dosunit_compare_ssa_normalizes_absolute_layout_memory_operands():
    oracle_function = _manual_ssa_function(
        "global_store",
        ["mov byte ptr [0x286], 1"],
        inputs=[{"kind": "memory", "name": "mem", "addr_width": 32, "value_width": 8}],
        assignments=[
            {
                "id": "v0",
                "op": "storele",
                "width": 8,
                "args": [
                    {"op": "mem_input", "name": "mem", "addr_width": 32, "value_width": 8},
                    {"op": "const", "value": "0x0286", "width": 32},
                    {"op": "const", "value": "0x01", "width": 8},
                ],
            }
        ],
        outputs={"memory": {"ref": "v0"}},
    )
    candidate_function = _manual_ssa_function(
        "global_store",
        ["mov byte ptr [0x28a], 1"],
        inputs=[{"kind": "memory", "name": "mem", "addr_width": 32, "value_width": 8}],
        assignments=[
            {
                "id": "v0",
                "op": "storele",
                "width": 8,
                "args": [
                    {"op": "mem_input", "name": "mem", "addr_width": 32, "value_width": 8},
                    {"op": "const", "value": "0x028a", "width": 32},
                    {"op": "const", "value": "0x01", "width": 8},
                ],
            }
        ],
        outputs={"memory": {"ref": "v0"}},
    )

    compared = compare_ssa_documents(oracle=_ssa_doc(oracle_function), candidate=_ssa_doc(candidate_function))

    assert compared["summary"]["passed"] == 1
    assert compared["results"][0]["layout_normalization"]["pairs"] == [
        {"oracle": "0x0286", "candidate": "0x028a", "reason": "absolute_memory_operand"}
    ]


def test_dosunit_compare_ssa_does_not_cross_swap_absolute_memory_operands():
    oracle_function = _manual_ssa_function(
        "cross_swap",
        ["mov ax, word ptr [0x505a]", "mul word ptr [0x0e5a]"],
        inputs=[{"kind": "memory", "name": "mem", "addr_width": 32, "value_width": 8}],
        assignments=[
            {
                "id": "v0",
                "op": "loadle",
                "width": 16,
                "args": [
                    {"op": "mem_input", "name": "mem", "addr_width": 32, "value_width": 8},
                    {"op": "const", "value": "0x505a", "width": 32},
                ],
            },
            {
                "id": "v1",
                "op": "loadle",
                "width": 16,
                "args": [
                    {"op": "mem_input", "name": "mem", "addr_width": 32, "value_width": 8},
                    {"op": "const", "value": "0x0e5a", "width": 32},
                ],
            },
            {"id": "v2", "op": "mul", "width": 16, "args": [{"ref": "v0"}, {"ref": "v1"}]},
        ],
        outputs={"ax": {"ref": "v2"}},
    )
    candidate_function = _manual_ssa_function(
        "cross_swap",
        ["mov ax, word ptr [0x0e5a]", "mul word ptr [0x505a]"],
        inputs=[{"kind": "memory", "name": "mem", "addr_width": 32, "value_width": 8}],
        assignments=[
            {
                "id": "v0",
                "op": "loadle",
                "width": 16,
                "args": [
                    {"op": "mem_input", "name": "mem", "addr_width": 32, "value_width": 8},
                    {"op": "const", "value": "0x0e5a", "width": 32},
                ],
            },
            {
                "id": "v1",
                "op": "loadle",
                "width": 16,
                "args": [
                    {"op": "mem_input", "name": "mem", "addr_width": 32, "value_width": 8},
                    {"op": "const", "value": "0x505a", "width": 32},
                ],
            },
            {"id": "v2", "op": "mul", "width": 16, "args": [{"ref": "v0"}, {"ref": "v1"}]},
        ],
        outputs={"ax": {"ref": "v2"}},
    )

    compared = compare_ssa_documents(oracle=_ssa_doc(oracle_function), candidate=_ssa_doc(candidate_function))

    assert compared["summary"]["passed"] == 1
    assert compared["results"][0]["layout_normalization"] is None


def test_dosunit_compare_ssa_projects_nonterminal_register_outputs_to_connectivity():
    oracle_function = _manual_ssa_function(
        "branch_tmp",
        ["cmp word ptr [0x1000], ax", "jne 0x1210"],
        inputs=[],
        assignments=[],
        outputs={
            "ax": {"op": "const", "value": "0x1111", "width": 16},
            "ip": {"op": "const", "value": "0x1210", "width": 16},
        },
    )
    candidate_function = _manual_ssa_function(
        "branch_tmp",
        ["cmp word ptr [0x1000], ax", "jne 0x1210"],
        inputs=[],
        assignments=[],
        outputs={
            "ax": {"op": "const", "value": "0x2222", "width": 16},
            "ip": {"op": "const", "value": "0x1210", "width": 16},
        },
    )
    for function in (oracle_function, candidate_function):
        function["source"]["jumpkind"] = "Ijk_Boring"
        function["source"]["transfer"] = {
            "kind": "direct_successors",
            "successors": [{"linear": "0x1210", "low16": "0x1210"}],
        }

    compared = compare_ssa_documents(
        oracle=_ssa_doc(oracle_function),
        candidate=_ssa_doc(candidate_function),
        enable_connectivity=False,
    )

    assert compared["summary"]["passed"] == 1
    assert compared["results"][0]["output_projection"]["outputs"] == ["ip"]


def test_dosunit_compare_ssa_normalizes_loadds_segment_immediates():
    oracle_function = _manual_ssa_function(
        "loadds",
        ["mov ax, 0x100", "mov ds, ax"],
        outputs={"ds": {"op": "const", "value": "0x0100", "width": 16}},
    )
    candidate_function = _manual_ssa_function(
        "loadds",
        ["mov ax, 0x200", "mov ds, ax"],
        outputs={"ds": {"op": "const", "value": "0x0200", "width": 16}},
    )

    compared = compare_ssa_documents(oracle=_ssa_doc(oracle_function), candidate=_ssa_doc(candidate_function))

    assert compared["summary"]["passed"] == 1
    assert compared["results"][0]["layout_normalization"]["pairs"] == [
        {"oracle": "0x0100", "candidate": "0x0200", "reason": "data_segment_immediate"}
    ]


def test_dosunit_compare_ssa_normalizes_signed_layout_displacements():
    oracle_function = _manual_ssa_function(
        "signed_global_load",
        ["mov ax, word ptr [bx + 0x629e]"],
        inputs=[{"kind": "memory", "name": "mem", "addr_width": 32, "value_width": 8}],
        assignments=[
            {
                "id": "v0",
                "op": "loadle",
                "width": 16,
                "args": [
                    {"op": "mem_input", "name": "mem", "addr_width": 32, "value_width": 8},
                    {"op": "const", "value": "0x0000629e", "width": 32},
                ],
            }
        ],
        outputs={"ax": {"ref": "v0"}},
    )
    candidate_function = _manual_ssa_function(
        "signed_global_load",
        ["mov ax, word ptr [bx - 0x5e78]"],
        inputs=[{"kind": "memory", "name": "mem", "addr_width": 32, "value_width": 8}],
        assignments=[
            {
                "id": "v0",
                "op": "loadle",
                "width": 16,
                "args": [
                    {"op": "mem_input", "name": "mem", "addr_width": 32, "value_width": 8},
                    {"op": "const", "value": "0xffffa188", "width": 32},
                ],
            }
        ],
        outputs={"ax": {"ref": "v0"}},
    )

    compared = compare_ssa_documents(oracle=_ssa_doc(oracle_function), candidate=_ssa_doc(candidate_function))

    assert compared["summary"]["passed"] == 1
    assert compared["results"][0]["layout_normalization"]["pairs"] == [
        {"oracle": "0x629e", "candidate": "0xa188", "reason": "memory_operand"}
    ]


def test_dosunit_compare_ssa_normalizes_same_delta_address_bases():
    oracle_function = _manual_ssa_function(
        "same_delta_base",
        ["sub ax, 0x1000", "mov cx, word ptr [0x2000]"],
        inputs=[{"name": "ax", "width": 16}],
        assignments=[
            {
                "id": "v0",
                "op": "sub",
                "width": 16,
                "args": [{"op": "input", "name": "ax", "width": 16}, {"op": "const", "value": "0x1000", "width": 16}],
            }
        ],
        outputs={"ax": {"ref": "v0"}},
    )
    candidate_function = _manual_ssa_function(
        "same_delta_base",
        ["sub ax, 0x3000", "mov cx, word ptr [0x4000]"],
        inputs=[{"name": "ax", "width": 16}],
        assignments=[
            {
                "id": "v0",
                "op": "sub",
                "width": 16,
                "args": [{"op": "input", "name": "ax", "width": 16}, {"op": "const", "value": "0x3000", "width": 16}],
            }
        ],
        outputs={"ax": {"ref": "v0"}},
    )

    compared = compare_ssa_documents(oracle=_ssa_doc(oracle_function), candidate=_ssa_doc(candidate_function))

    assert compared["summary"]["passed"] == 1
    assert compared["results"][0]["layout_normalization"]["pairs"] == [
        {"oracle": "0x2000", "candidate": "0x4000", "reason": "absolute_memory_operand"},
        {"oracle": "0x1000", "candidate": "0x3000", "reason": "same_delta_address_base"},
    ]


def test_dosunit_compare_ssa_normalizes_sub_on_pointer_register_when_used_as_memory_base():
    oracle_function = _manual_ssa_function(
        "pointer_sub",
        ["sub bx, 0x1000", "mov ax, word ptr [bx]"],
        inputs=[{"name": "bx", "width": 16}],
        assignments=[
            {
                "id": "v0",
                "op": "sub",
                "width": 16,
                "args": [{"op": "input", "name": "bx", "width": 16}, {"op": "const", "value": "0x1000", "width": 16}],
            }
        ],
        outputs={"bx": {"ref": "v0"}},
    )
    candidate_function = _manual_ssa_function(
        "pointer_sub",
        ["sub bx, 0x3000", "mov ax, word ptr [bx]"],
        inputs=[{"name": "bx", "width": 16}],
        assignments=[
            {
                "id": "v0",
                "op": "sub",
                "width": 16,
                "args": [{"op": "input", "name": "bx", "width": 16}, {"op": "const", "value": "0x3000", "width": 16}],
            }
        ],
        outputs={"bx": {"ref": "v0"}},
    )

    compared = compare_ssa_documents(oracle=_ssa_doc(oracle_function), candidate=_ssa_doc(candidate_function))

    assert compared["summary"]["passed"] == 1
    assert compared["results"][0]["layout_normalization"]["pairs"] == [
        {"oracle": "0x1000", "candidate": "0x3000", "reason": "pointer_arithmetic"}
    ]


def test_dosunit_compare_ssa_does_not_normalize_sub_on_pointer_register_without_memory_use():
    oracle_function = _manual_ssa_function(
        "integer_sub",
        ["sub bx, 0x1000", "ret"],
        inputs=[{"name": "bx", "width": 16}],
        assignments=[
            {
                "id": "v0",
                "op": "sub",
                "width": 16,
                "args": [{"op": "input", "name": "bx", "width": 16}, {"op": "const", "value": "0x1000", "width": 16}],
            }
        ],
        outputs={"bx": {"ref": "v0"}},
    )
    candidate_function = _manual_ssa_function(
        "integer_sub",
        ["sub bx, 0x3000", "ret"],
        inputs=[{"name": "bx", "width": 16}],
        assignments=[
            {
                "id": "v0",
                "op": "sub",
                "width": 16,
                "args": [{"op": "input", "name": "bx", "width": 16}, {"op": "const", "value": "0x3000", "width": 16}],
            }
        ],
        outputs={"bx": {"ref": "v0"}},
    )

    compared = compare_ssa_documents(oracle=_ssa_doc(oracle_function), candidate=_ssa_doc(candidate_function))

    assert compared["summary"]["failed"] == 1
    assert compared["results"][0].get("layout_normalization") is None


def test_dosunit_compare_ssa_normalizes_repeated_same_delta_constant_sets():
    oracle_function = _manual_ssa_function(
        "same_delta_constants",
        ["sub ax, 0x61fe", "add ax, 0x629e"],
        inputs=[{"name": "ax", "width": 16}],
        assignments=[
            {
                "id": "v0",
                "op": "sub",
                "width": 16,
                "args": [{"op": "input", "name": "ax", "width": 16}, {"op": "const", "value": "0x61fe", "width": 16}],
            },
            {
                "id": "v1",
                "op": "add",
                "width": 16,
                "args": [{"ref": "v0"}, {"op": "const", "value": "0x629e", "width": 16}],
            },
        ],
        outputs={"ax": {"ref": "v1"}},
    )
    candidate_function = _manual_ssa_function(
        "same_delta_constants",
        ["sub ax, 0xa0e8", "add ax, 0xa188"],
        inputs=[{"name": "ax", "width": 16}],
        assignments=[
            {
                "id": "v0",
                "op": "sub",
                "width": 16,
                "args": [{"op": "input", "name": "ax", "width": 16}, {"op": "const", "value": "0xa0e8", "width": 16}],
            },
            {
                "id": "v1",
                "op": "add",
                "width": 16,
                "args": [{"ref": "v0"}, {"op": "const", "value": "0xa188", "width": 16}],
            },
        ],
        outputs={"ax": {"ref": "v1"}},
    )

    compared = compare_ssa_documents(oracle=_ssa_doc(oracle_function), candidate=_ssa_doc(candidate_function))

    assert compared["summary"]["passed"] == 1
    assert compared["results"][0]["layout_normalization"]["pairs"] == [
        {"oracle": "0x61fe", "candidate": "0xa0e8", "reason": "same_delta_constant_set"},
        {"oracle": "0x629e", "candidate": "0xa188", "reason": "same_delta_constant_set"},
    ]


def test_dosunit_compare_ssa_normalizes_layout_call_argument_immediates():
    oracle_function = _manual_ssa_function(
        "call_arg_pointer",
        ["mov ax, 0x1855", "push ax", "call 0x2000"],
        outputs={"memory": {"op": "const", "value": "0x1855", "width": 16}},
    )
    candidate_function = _manual_ssa_function(
        "call_arg_pointer",
        ["mov ax, 0x17c1", "push ax", "call 0x2000"],
        outputs={"memory": {"op": "const", "value": "0x17c1", "width": 16}},
    )

    compared = compare_ssa_documents(oracle=_ssa_doc(oracle_function), candidate=_ssa_doc(candidate_function))

    assert compared["summary"]["passed"] == 1
    assert compared["results"][0]["layout_normalization"]["pairs"] == [
        {"oracle": "0x1855", "candidate": "0x17c1", "reason": "call_argument_immediate"}
    ]


def test_dosunit_compare_ssa_does_not_normalize_plain_numeric_call_arguments():
    oracle_function = _manual_ssa_function(
        "call_arg_number",
        ["mov ax, 0x000f", "push ax", "call 0x2000"],
        outputs={"memory": {"op": "const", "value": "0x000f", "width": 16}},
    )
    candidate_function = _manual_ssa_function(
        "call_arg_number",
        ["mov ax, 0x0010", "push ax", "call 0x2000"],
        outputs={"memory": {"op": "const", "value": "0x0010", "width": 16}},
    )

    compared = compare_ssa_documents(oracle=_ssa_doc(oracle_function), candidate=_ssa_doc(candidate_function))

    assert compared["summary"]["failed"] == 1
    assert compared["results"][0]["layout_normalization"] is None


def test_dosunit_compare_ssa_normalizes_ivt_segment_constants():
    oracle_function = _manual_ssa_function(
        "install_handler",
        ["mov ax, 0x1088", "mov word ptr es:[2], ax"],
        outputs={"ax": {"op": "const", "value": "0x1088", "width": 16}},
    )
    candidate_function = _manual_ssa_function(
        "install_handler",
        ["mov ax, 0x1159", "mov word ptr es:[2], ax"],
        outputs={"ax": {"op": "const", "value": "0x1159", "width": 16}},
    )

    compared = compare_ssa_documents(oracle=_ssa_doc(oracle_function), candidate=_ssa_doc(candidate_function))

    assert compared["summary"]["passed"] == 1
    assert compared["results"][0]["layout_normalization"]["pairs"] == [
        {"oracle": "0x1088", "candidate": "0x1159", "reason": "ivt_segment"}
    ]


def test_dosunit_compare_ssa_does_not_normalize_plain_changed_immediates():
    oracle_function = _manual_ssa_function(
        "changed_immediate",
        ["mov ax, 0x2000"],
        outputs={"ax": {"op": "const", "value": "0x2000", "width": 16}},
    )
    candidate_function = _manual_ssa_function(
        "changed_immediate",
        ["mov ax, 0x3000"],
        outputs={"ax": {"op": "const", "value": "0x3000", "width": 16}},
    )

    compared = compare_ssa_documents(oracle=_ssa_doc(oracle_function), candidate=_ssa_doc(candidate_function))

    assert compared["summary"]["failed"] == 1
    assert compared["results"][0].get("layout_normalization") is None
    assert compared["results"][0]["mismatches"][0]["kind"] == "output_expr_changed"


def test_dosunit_report_shows_layout_normalization_on_failed_rows():
    document = {
        "schema": "dosunit.ssa_compare.v1",
        "oracle": "oracle.exe",
        "candidate": "candidate.exe",
        "mapping": None,
        "summary": {"total": 1, "passed": 0, "failed": 1, "refused": 0, "skipped_unmapped": 0, "solver_time_ms": 0},
        "results": [
            {
                "status": "failed",
                "reason": "observable_mismatch",
                "function": {"id": "demo.exe:global_load", "name": "global_load"},
                "layout_normalization": {
                    "kind": "layout_constants",
                    "pairs": [{"oracle": "0x61fe", "candidate": "0xa0e8", "reason": "memory_operand"}],
                },
                "mismatches": [{"kind": "output_expr_changed", "reg": "ax"}],
            }
        ],
    }

    report = render_failure_report(document)

    assert "Layout constant normalization" in report
    assert "candidate `0xa0e8` -> oracle `0x61fe`" in report


def test_dosunit_compare_ssa_uses_mapping_and_reports_unmapped_by_default(tmp_path: Path):
    original_image = bytearray(0x280)
    candidate_image = bytearray(0x280)
    original_image[0x200:0x206] = b"\x89\xd8\x83\xc0\x01\xc3"  # mov ax, bx; add ax, 1; ret
    original_image[0x210:0x214] = b"\xb8\x34\x12\xc3"  # mov ax, 0x1234; ret
    candidate_image[0x220:0x224] = b"\x89\xd8\x40\xc3"  # mov ax, bx; inc ax; ret
    original = tmp_path / "original.exe"
    candidate = tmp_path / "candidate.exe"
    original.write_bytes(_mz_exe(bytes(original_image)))
    candidate.write_bytes(_mz_exe(bytes(candidate_image)))
    original_catalog = {
        "schema": "dosunit.functions.v1",
        "id": "functions:original",
        "module": "demo.exe",
        "program_kind": "mz_exe",
        "functions": [
            _edge_function("demo.exe:orig_leaf", "orig_leaf", offset=0x0200, size=6),
            _edge_function("demo.exe:unmapped_leaf", "unmapped_leaf", offset=0x0210, size=4),
        ],
        "diagnostics": [],
    }
    candidate_catalog = {
        "schema": "dosunit.functions.v1",
        "id": "functions:candidate",
        "module": "demo.exe",
        "program_kind": "mz_exe",
        "functions": [_edge_function("demo.exe:rebuilt_leaf", "rebuilt_leaf", offset=0x0220, size=4)],
        "diagnostics": [],
    }
    mapping = {
        "schema": "dosunit.mapping.v1",
        "id": "mapping:test",
        "functions": [
            {
                "oracle_id": "demo.exe:orig_leaf",
                "oracle_name": "orig_leaf",
                "candidate_id": "demo.exe:rebuilt_leaf",
                "candidate_name": "rebuilt_leaf",
                "candidate_entry": {"cs": "0x0000", "ip": "0x0220", "kind": "near"},
                "sources": ["fixture"],
            }
        ],
    }

    oracle = lower_straightline_ssa_document(
        exe_path=original,
        functions_catalog=original_catalog,
        output_regs=("ax", "bx"),
        follow_call_fallthrough=False,
    )
    candidate_ssa = lower_straightline_ssa_document(
        exe_path=candidate,
        functions_catalog=candidate_catalog,
        output_regs=("ax", "bx"),
        follow_call_fallthrough=False,
    )
    compared = compare_ssa_documents(oracle=oracle, candidate=candidate_ssa, mapping_document=mapping)

    assert compared["summary"]["total"] == 2
    assert compared["summary"]["passed"] == 1
    assert compared["summary"]["refused"] == 1
    assert compared["summary"]["skipped_unmapped"] == 1
    assert compared["results"][0]["candidate_function"] == candidate_ssa["functions"][0]["id"]
    assert compared["results"][1]["reason"] == "mapping_missing"
    report = render_failure_report(compared)
    assert "Unmapped oracle functions: 1" in report
    assert "Missing-function rows skipped: 1" in report
    assert "function_missing" not in report

    skipped = compare_ssa_documents(
        oracle=oracle, candidate=candidate_ssa, mapping_document=mapping, include_unmapped=False
    )
    assert skipped["summary"]["total"] == 1
    assert skipped["summary"]["refused"] == 0


def test_dosunit_failure_report_skips_region_function_missing_by_default():
    report = render_failure_report(
        {
            "schema": "dosunit.ssa_compare.v1",
            "oracle": "oracle.exe",
            "candidate": "candidate.exe",
            "mapping": "mapping:test",
            "summary": {"total": 0, "passed": 0, "failed": 0, "refused": 0, "skipped_unmapped": 0, "solver_time_ms": 0},
            "results": [],
            "region_equality": {
                "status": "failed",
                "passed": 0,
                "failed": 1,
                "refused": 1,
                "covered_results": 0,
                "results": [
                    {
                        "status": "refused",
                        "reason": "function_missing",
                        "function": {"id": "demo.exe:missing_region", "name": "missing_region"},
                        "mismatches": [{"kind": "function_missing"}],
                    },
                    {
                        "status": "failed",
                        "reason": "observable_mismatch",
                        "function": {"id": "demo.exe:visible_region", "name": "visible_region"},
                        "mismatches": [{"kind": "output_expr_changed", "reg": "ax"}],
                    },
                ],
            },
        }
    )

    assert "Missing-function region rows skipped: 1" in report
    assert "missing_region" not in report
    assert "visible_region" in report


def test_dosunit_compare_ssa_normalizes_mapped_direct_call_targets(tmp_path: Path):
    original_image = bytearray(0x300)
    candidate_image = bytearray(0x300)
    original_image[0x200:0x204] = b"\xe8\x2d\x00\xc3"  # call 0x1230; ret
    original_image[0x230:0x234] = b"\xb8\x34\x12\xc3"  # mov ax, 0x1234; ret
    candidate_image[0x220:0x224] = b"\xe8\x3d\x00\xc3"  # call 0x1260; ret
    candidate_image[0x260:0x264] = b"\xb8\x34\x12\xc3"  # mov ax, 0x1234; ret
    original = tmp_path / "original.exe"
    candidate = tmp_path / "candidate.exe"
    original.write_bytes(_mz_exe(bytes(original_image)))
    candidate.write_bytes(_mz_exe(bytes(candidate_image)))
    original_catalog = {
        "schema": "dosunit.functions.v1",
        "id": "functions:original",
        "module": "demo.exe",
        "program_kind": "mz_exe",
        "functions": [
            _edge_function("demo.exe:caller", "caller", offset=0x0200, size=4),
            _edge_function("demo.exe:callee", "callee", offset=0x0230, size=4),
        ],
        "diagnostics": [],
    }
    candidate_catalog = {
        "schema": "dosunit.functions.v1",
        "id": "functions:candidate",
        "module": "demo.exe",
        "program_kind": "mz_exe",
        "functions": [
            _edge_function("demo.exe:caller_rebuilt", "caller_rebuilt", offset=0x0220, size=4),
            _edge_function("demo.exe:callee_rebuilt", "callee_rebuilt", offset=0x0260, size=4),
        ],
        "diagnostics": [],
    }
    mapping = {
        "schema": "dosunit.mapping.v1",
        "id": "mapping:test",
        "functions": [
            {
                "oracle_id": "demo.exe:caller",
                "oracle_name": "caller",
                "candidate_id": "demo.exe:caller_rebuilt",
                "candidate_name": "caller_rebuilt",
                "candidate_entry": {"cs": "0x0000", "ip": "0x0220", "kind": "near"},
                "sources": ["fixture"],
            },
            {
                "oracle_id": "demo.exe:callee",
                "oracle_name": "callee",
                "candidate_id": "demo.exe:callee_rebuilt",
                "candidate_name": "callee_rebuilt",
                "candidate_entry": {"cs": "0x0000", "ip": "0x0260", "kind": "near"},
                "sources": ["fixture"],
            },
        ],
    }

    oracle = lower_straightline_ssa_document(exe_path=original, functions_catalog=original_catalog, output_regs=("ax",))
    candidate_ssa = lower_straightline_ssa_document(
        exe_path=candidate, functions_catalog=candidate_catalog, output_regs=("ax",)
    )
    compared = compare_ssa_documents(oracle=oracle, candidate=candidate_ssa, mapping_document=mapping)

    caller = next(result for result in compared["results"] if result["function"]["name"] == "caller")
    assert caller["status"] == "passed"
    assert caller["call_compare"]["equivalent"] is True
    assert caller["call_compare"]["oracle"]["resolved"]["name"] == "callee"
    assert caller["call_compare"]["candidate"]["resolved"]["name"] == "callee_rebuilt"
    assert caller["call_compare"]["oracle"]["resolved"]["instructions"][0]["disassembly"] == "mov ax, 0x1234"
    assert all(item["applied"] for item in caller["call_compare"]["normalizations"])
    report_document = {
        "schema": "dosunit.ssa_compare.v1",
        "oracle": str(original),
        "candidate": str(candidate),
        "mapping": "mapping:test",
        "summary": {"total": 1, "passed": 0, "failed": 1, "refused": 0, "skipped_unmapped": 0, "solver_time_ms": 0},
        "results": [
            {
                **caller,
                "status": "failed",
                "reason": "observable_mismatch",
                "mismatches": [{"kind": "output_expr_changed", "reg": "call_target"}],
            }
        ],
    }
    report = render_failure_report(report_document)
    assert "Target first instructions" in report
    assert "mov ax, 0x1234" in report


def test_dosunit_compare_ssa_uses_z3_proven_callee_lemma_for_shifted_call(tmp_path: Path):
    original_image = bytearray(0x300)
    candidate_image = bytearray(0x300)
    original_image[0x200:0x204] = b"\xe8\x2d\x00\xc3"  # call 0x1230; ret
    original_image[0x230:0x236] = b"\x89\xd8\x83\xc0\x01\xc3"  # mov ax, bx; add ax, 1; ret
    candidate_image[0x220:0x224] = b"\xe8\x3d\x00\xc3"  # call 0x1260; ret
    candidate_image[0x260:0x267] = b"\x89\xd8\xf7\xd0\xf7\xd8\xc3"  # mov ax, bx; not ax; neg ax; ret
    original = tmp_path / "original.exe"
    candidate = tmp_path / "candidate.exe"
    original.write_bytes(_mz_exe(bytes(original_image)))
    candidate.write_bytes(_mz_exe(bytes(candidate_image)))
    original_catalog = {
        "schema": "dosunit.functions.v1",
        "module": "demo.exe",
        "functions": [
            _edge_function("demo.exe:caller", "caller", offset=0x0200, size=4),
            _edge_function("demo.exe:callee", "callee", offset=0x0230, size=6),
        ],
    }
    candidate_catalog = {
        "schema": "dosunit.functions.v1",
        "module": "demo.exe",
        "functions": [
            _edge_function("demo.exe:caller_rebuilt", "caller_rebuilt", offset=0x0220, size=4),
            _edge_function("demo.exe:callee_rebuilt", "callee_rebuilt", offset=0x0260, size=7),
        ],
    }
    mapping = {
        "schema": "dosunit.mapping.v1",
        "id": "mapping:test",
        "functions": [
            {
                "oracle_id": "demo.exe:caller",
                "oracle_name": "caller",
                "candidate_id": "demo.exe:caller_rebuilt",
                "candidate_name": "caller_rebuilt",
                "candidate_entry": {"cs": "0x0000", "ip": "0x0220", "kind": "near"},
            },
            {
                "oracle_id": "demo.exe:callee",
                "oracle_name": "callee",
                "candidate_id": "demo.exe:callee_rebuilt",
                "candidate_name": "callee_rebuilt",
                "candidate_entry": {"cs": "0x0000", "ip": "0x0260", "kind": "near"},
            },
        ],
    }

    oracle = lower_straightline_ssa_document(
        exe_path=original,
        functions_catalog=original_catalog,
        output_regs=("ax", "bx"),
        follow_call_fallthrough=False,
    )
    candidate_ssa = lower_straightline_ssa_document(
        exe_path=candidate,
        functions_catalog=candidate_catalog,
        output_regs=("ax", "bx"),
        follow_call_fallthrough=False,
    )
    compared = compare_ssa_documents(oracle=oracle, candidate=candidate_ssa, mapping_document=mapping)

    caller = next(result for result in compared["results"] if result["function"]["name"] == "caller")
    callee = next(result for result in compared["results"] if result["function"]["name"] == "callee")
    assert compared["summary"]["passed"] == 2
    assert callee["status"] == "passed"
    assert callee["reason"] is None
    assert caller["status"] == "passed"
    assert caller["call_compare"]["reason"] == "direct call targets are equivalent through proven callee equality"
    assert caller["call_compare"]["proof_fact"]["proof"] == "z3_equal"
    assert caller["call_compare"]["proof_fact"]["id"].startswith("semantic-equality-fact:")
    assert caller["call_compare"]["semantic_target"]["source"] == "proof_fact"
    assert caller["call_compare"]["semantic_target"]["value"].startswith("0x")
    report_document = {
        "schema": "dosunit.ssa_compare.v1",
        "oracle": str(original),
        "candidate": str(candidate),
        "mapping": "mapping:test",
        "summary": {"total": 1, "passed": 0, "failed": 1, "refused": 0, "skipped_unmapped": 0, "solver_time_ms": 0},
        "results": [
            {
                **caller,
                "status": "failed",
                "reason": "observable_mismatch",
                "mismatches": [{"kind": "output_expr_changed", "reg": "call_target"}],
            }
        ],
    }
    report = render_failure_report(report_document)
    assert "Callee proof: `z3_equal` oracle `callee` -> candidate `callee_rebuilt`" in report
    assert "Semantic call target:" in report


def test_dosunit_compare_ssa_ignores_volatile_pre_call_register_outputs():
    oracle_caller = _ssa_call_boundary_function("demo.exe:caller", "caller", ax="0x1111", sp="0xfff4")
    candidate_caller = _ssa_call_boundary_function("demo.exe:caller", "caller", ax="0x2222", sp="0xfff6")
    oracle_callee = _ssa_stub("demo.exe:callee", "callee", ip="0x0500", linear="0x1500")
    candidate_callee = _ssa_stub("demo.exe:callee", "callee", ip="0x0500", linear="0x1500")
    for callee in (oracle_callee, candidate_callee):
        callee["source"]["machine_code_sha256"] = "same-callee"
        callee["source"]["machine_code_size"] = 1

    compared = compare_ssa_documents(
        oracle={"schema": "dosunit.ssa.v1", "exe": "oracle.exe", "functions": [oracle_caller, oracle_callee]},
        candidate={"schema": "dosunit.ssa.v1", "exe": "candidate.exe", "functions": [candidate_caller, candidate_callee]},
        skip_binary_equal=False,
    )

    caller = next(result for result in compared["results"] if result["function"]["name"] == "caller")
    assert caller["status"] == "passed"


def test_dosunit_compare_ssa_still_checks_call_boundary_memory_outputs():
    oracle_caller = _ssa_call_boundary_function("demo.exe:caller", "caller", memory="0x1111")
    candidate_caller = _ssa_call_boundary_function("demo.exe:caller", "caller", memory="0x2222")
    oracle_callee = _ssa_stub("demo.exe:callee", "callee", ip="0x0500", linear="0x1500")
    candidate_callee = _ssa_stub("demo.exe:callee", "callee", ip="0x0500", linear="0x1500")
    for callee in (oracle_callee, candidate_callee):
        callee["source"]["machine_code_sha256"] = "same-callee"
        callee["source"]["machine_code_size"] = 1

    compared = compare_ssa_documents(
        oracle={"schema": "dosunit.ssa.v1", "exe": "oracle.exe", "functions": [oracle_caller, oracle_callee]},
        candidate={"schema": "dosunit.ssa.v1", "exe": "candidate.exe", "functions": [candidate_caller, candidate_callee]},
        skip_binary_equal=False,
    )

    caller = next(result for result in compared["results"] if result["function"]["name"] == "caller")
    assert caller["status"] == "failed"
    assert any(
        mismatch["kind"] == "output_expr_changed" and mismatch.get("reg") == "memory"
        for mismatch in caller["mismatches"]
    )


def test_dosunit_compare_ssa_normalizes_equivalent_call_stack_store_addresses():
    oracle_caller = _ssa_call_boundary_stack_store_function("demo.exe:caller", "caller", frame_delta="0xfffa", value="0x1234")
    candidate_caller = _ssa_call_boundary_stack_store_function(
        "demo.exe:caller", "caller", frame_delta="0xfffc", value="0x1234"
    )
    oracle_callee = _ssa_stub("demo.exe:callee", "callee", ip="0x0500", linear="0x1500")
    candidate_callee = _ssa_stub("demo.exe:callee", "callee", ip="0x0500", linear="0x1500")
    for callee in (oracle_callee, candidate_callee):
        callee["source"]["machine_code_sha256"] = "same-callee"
        callee["source"]["machine_code_size"] = 1

    compared = compare_ssa_documents(
        oracle={"schema": "dosunit.ssa.v1", "exe": "oracle.exe", "functions": [oracle_caller, oracle_callee]},
        candidate={"schema": "dosunit.ssa.v1", "exe": "candidate.exe", "functions": [candidate_caller, candidate_callee]},
        skip_binary_equal=False,
    )

    caller = next(result for result in compared["results"] if result["function"]["name"] == "caller")
    assert caller["status"] == "passed"


def test_dosunit_compare_ssa_keeps_call_stack_store_value_observable():
    oracle_caller = _ssa_call_boundary_stack_store_function("demo.exe:caller", "caller", frame_delta="0xfffa", value="0x1234")
    candidate_caller = _ssa_call_boundary_stack_store_function(
        "demo.exe:caller", "caller", frame_delta="0xfffc", value="0x5678"
    )
    oracle_callee = _ssa_stub("demo.exe:callee", "callee", ip="0x0500", linear="0x1500")
    candidate_callee = _ssa_stub("demo.exe:callee", "callee", ip="0x0500", linear="0x1500")
    for callee in (oracle_callee, candidate_callee):
        callee["source"]["machine_code_sha256"] = "same-callee"
        callee["source"]["machine_code_size"] = 1

    compared = compare_ssa_documents(
        oracle={"schema": "dosunit.ssa.v1", "exe": "oracle.exe", "functions": [oracle_caller, oracle_callee]},
        candidate={"schema": "dosunit.ssa.v1", "exe": "candidate.exe", "functions": [candidate_caller, candidate_callee]},
        skip_binary_equal=False,
    )

    caller = next(result for result in compared["results"] if result["function"]["name"] == "caller")
    assert caller["status"] == "failed"
    assert any(mismatch["kind"] in {"memory_expr_changed", "output_expr_changed"} for mismatch in caller["mismatches"])


def test_dosunit_compare_ssa_refuses_caller_when_mapped_callee_not_proven(tmp_path: Path):
    original_image = bytearray(0x300)
    candidate_image = bytearray(0x300)
    original_image[0x200:0x204] = b"\xe8\x2d\x00\xc3"  # call 0x1230; ret
    original_image[0x230:0x236] = b"\x89\xd8\x83\xc0\x01\xc3"  # mov ax, bx; add ax, 1; ret
    candidate_image[0x220:0x224] = b"\xe8\x3d\x00\xc3"  # call 0x1260; ret
    candidate_image[0x260:0x266] = b"\x89\xd8\x83\xc0\x02\xc3"  # mov ax, bx; add ax, 2; ret
    original = tmp_path / "original.exe"
    candidate = tmp_path / "candidate.exe"
    original.write_bytes(_mz_exe(bytes(original_image)))
    candidate.write_bytes(_mz_exe(bytes(candidate_image)))
    original_catalog = {
        "schema": "dosunit.functions.v1",
        "module": "demo.exe",
        "functions": [
            _edge_function("demo.exe:caller", "caller", offset=0x0200, size=4),
            _edge_function("demo.exe:callee", "callee", offset=0x0230, size=6),
        ],
    }
    candidate_catalog = {
        "schema": "dosunit.functions.v1",
        "module": "demo.exe",
        "functions": [
            _edge_function("demo.exe:caller_rebuilt", "caller_rebuilt", offset=0x0220, size=4),
            _edge_function("demo.exe:callee_rebuilt", "callee_rebuilt", offset=0x0260, size=6),
        ],
    }
    mapping = {
        "schema": "dosunit.mapping.v1",
        "id": "mapping:test",
        "functions": [
            {
                "oracle_id": "demo.exe:caller",
                "oracle_name": "caller",
                "candidate_id": "demo.exe:caller_rebuilt",
                "candidate_name": "caller_rebuilt",
                "candidate_entry": {"cs": "0x0000", "ip": "0x0220", "kind": "near"},
            },
            {
                "oracle_id": "demo.exe:callee",
                "oracle_name": "callee",
                "candidate_id": "demo.exe:callee_rebuilt",
                "candidate_name": "callee_rebuilt",
                "candidate_entry": {"cs": "0x0000", "ip": "0x0260", "kind": "near"},
            },
        ],
    }

    oracle = lower_straightline_ssa_document(
        exe_path=original, functions_catalog=original_catalog, output_regs=("ax", "bx")
    )
    candidate_ssa = lower_straightline_ssa_document(
        exe_path=candidate, functions_catalog=candidate_catalog, output_regs=("ax", "bx")
    )
    compared = compare_ssa_documents(oracle=oracle, candidate=candidate_ssa, mapping_document=mapping)

    caller = next(result for result in compared["results"] if result["function"]["name"] == "caller")
    callee = next(result for result in compared["results"] if result["function"]["name"] == "callee")
    assert callee["status"] == "failed"
    assert caller["status"] == "refused"
    assert caller["reason"] == "callee_not_proven"
    assert caller["call_compare"]["unproven_reason"] == "direct call targets are equivalent through function mapping"

    compatibility = compare_ssa_documents(
        oracle=oracle,
        candidate=candidate_ssa,
        mapping_document=mapping,
        enable_callee_lemmas=False,
    )
    compatibility_caller = next(result for result in compatibility["results"] if result["function"]["name"] == "caller")
    assert compatibility_caller["status"] == "passed"
    assert (
        compatibility_caller["call_compare"]["reason"] == "direct call targets are equivalent through function mapping"
    )
    assert compatibility_caller["call_compare"]["semantic_target"]["source"] == "resolved_target"


def test_dosunit_compare_ssa_accepts_strict_mapped_callee_with_matching_normalized_signature(tmp_path: Path):
    original_image = bytearray(0x400)
    candidate_image = bytearray(0x400)
    original_image[0x200:0x204] = b"\xe8\x2d\x00\xc3"  # call 0x1230; ret
    original_image[0x230:0x250] = bytes.fromhex(
        "55 8b ec 57 56 06 55 bb 34 12 a3 78 56 8b 46 04 e8 20 01 5d 07 5e 5f 5d c3 90 90 90 90 90 90 90"
    )
    candidate_image[0x220:0x224] = b"\xe8\x3d\x00\xc3"  # call 0x1260; ret
    candidate_image[0x260:0x280] = bytes.fromhex(
        "55 8b ec 57 56 06 55 bb ab cd a3 ef be 8b 46 04 e8 40 02 5d 07 5e 5f 5d c3 90 90 90 90 90 90 90"
    )
    original = tmp_path / "original.exe"
    candidate = tmp_path / "candidate.exe"
    original.write_bytes(_mz_exe(bytes(original_image)))
    candidate.write_bytes(_mz_exe(bytes(candidate_image)))
    original_catalog = {
        "schema": "dosunit.functions.v1",
        "module": "demo.exe",
        "functions": [
            _edge_function("demo.exe:caller", "caller", offset=0x0200, size=4),
            _edge_function("demo.exe:callee", "callee", offset=0x0230, size=0x20),
        ],
    }
    candidate_catalog = {
        "schema": "dosunit.functions.v1",
        "module": "demo.exe",
        "functions": [
            _edge_function("demo.exe:caller_rebuilt", "caller_rebuilt", offset=0x0220, size=4),
            _edge_function("demo.exe:callee_rebuilt", "callee_rebuilt", offset=0x0260, size=0x20),
        ],
    }
    mapping = {
        "schema": "dosunit.mapping.v1",
        "id": "mapping:test",
        "functions": [
            {
                "oracle_id": "demo.exe:caller",
                "oracle_name": "caller",
                "candidate_id": "demo.exe:caller_rebuilt",
                "candidate_name": "caller_rebuilt",
                "candidate_entry": {"cs": "0x0000", "ip": "0x0220", "kind": "near"},
            },
            {
                "oracle_id": "demo.exe:callee",
                "oracle_name": "callee",
                "candidate_id": "demo.exe:callee_rebuilt",
                "candidate_name": "callee_rebuilt",
                "candidate_entry": {"cs": "0x0000", "ip": "0x0260", "kind": "near"},
            },
        ],
    }

    oracle = lower_straightline_ssa_document(
        exe_path=original, functions_catalog=original_catalog, output_regs=("ax", "sp")
    )
    candidate_ssa = lower_straightline_ssa_document(
        exe_path=candidate, functions_catalog=candidate_catalog, output_regs=("ax", "sp")
    )
    oracle_caller_only = dict(oracle)
    oracle_caller_only["functions"] = [
        function for function in oracle["functions"] if function["function"]["name"] == "caller"
    ]
    candidate_caller_only = dict(candidate_ssa)
    candidate_caller_only["functions"] = [
        function for function in candidate_ssa["functions"] if function["function"]["name"] == "caller_rebuilt"
    ]
    compared = compare_ssa_documents(
        oracle=oracle_caller_only,
        candidate=candidate_caller_only,
        oracle_index_document=oracle,
        candidate_index_document=candidate_ssa,
        mapping_document=mapping,
        max_solver_memory_stores=32,
    )

    caller = next(result for result in compared["results"] if result["function"]["name"] == "caller")
    assert caller["status"] == "passed"
    assert caller["call_compare"]["equivalent"] is True
    assert caller["call_compare"]["reason"] in {
        "direct call targets are equivalent through function mapping",
        "direct call targets have identical layout-normalized binary-local signatures",
    }
    assert caller["call_compare"]["semantic_target"]["source"] == "resolved_target"


def test_dosunit_compare_ssa_resolves_near_call_low16_linear_before_ip_collision():
    oracle = {
        "schema": "dosunit.ssa.v1",
        "exe": "oracle.exe",
        "functions": [
            _ssa_stub(
                "oracle.exe:drawNumber",
                "drawNumber",
                ip="0xa183",
                linear="0xb183",
                jumpkind="Ijk_Call",
                call_raw="0xfa3a",
            ),
            _ssa_stub("oracle.exe:itoa", "itoa", ip="0xea3a", linear="0xfa3a"),
        ],
    }
    candidate = {
        "schema": "dosunit.ssa.v1",
        "exe": "candidate.exe",
        "functions": [
            _ssa_stub(
                "candidate.exe:drawNumber",
                "drawNumber",
                ip="0x6169",
                linear="0x7169",
                jumpkind="Ijk_Call",
                call_raw="0x0390",
            ),
            _ssa_stub("candidate.exe:itoa", "itoa", ip="0xf390", linear="0x10390"),
            _ssa_stub("candidate.exe:clipComputeOutcode", "clipComputeOutcode", ip="0x0390", linear="0x11920"),
        ],
    }
    mapping = {
        "schema": "dosunit.mapping.v1",
        "id": "mapping:test",
        "functions": [
            {
                "oracle_id": "oracle.exe:drawNumber",
                "oracle_name": "drawNumber",
                "candidate_id": "candidate.exe:drawNumber",
                "candidate_name": "drawNumber",
                "candidate_entry": {"cs": "0x0000", "ip": "0x6169", "kind": "near"},
            },
            {
                "oracle_id": "oracle.exe:itoa",
                "oracle_name": "itoa",
                "candidate_id": "candidate.exe:itoa",
                "candidate_name": "itoa",
                "candidate_entry": {"cs": "0x0000", "ip": "0xf390", "kind": "near"},
            },
        ],
    }

    compared = compare_ssa_documents(oracle=oracle, candidate=candidate, mapping_document=mapping)

    caller = compared["results"][0]
    assert caller["status"] == "passed"
    assert caller["call_compare"]["equivalent"] is True
    assert caller["call_compare"]["candidate"]["resolved"]["name"] == "itoa"


def test_dosunit_compare_ssa_resolves_linear_low16_aliases_before_ip_collision():
    oracle = {
        "schema": "dosunit.ssa.v1",
        "exe": "oracle.exe",
        "functions": [
            _ssa_stub(
                "oracle.exe:__getbuf", "__getbuf", ip="0xf288", linear="0x10288", jumpkind="Ijk_Call", call_raw="0x05d2"
            ),
            _ssa_stub("oracle.exe:unk_libc6", "unk_libc6", ip="0xf5d2", linear="0x105d2"),
        ],
    }
    candidate = {
        "schema": "dosunit.ssa.v1",
        "exe": "candidate.exe",
        "functions": [
            _ssa_stub(
                "candidate.exe:__getbuf",
                "__getbuf",
                ip="0xea22",
                linear="0xfa22",
                jumpkind="Ijk_Call",
                call_raw="0x0096",
            ),
            _ssa_stub("candidate.exe:__nmalloc", "__nmalloc", ip="0xf096", linear="0x10096"),
            _ssa_stub("candidate.exe:malloc", "malloc", ip="0xf096", linear="0x10096"),
            _ssa_stub("candidate.exe:projectVertexToScreen", "projectVertexToScreen", ip="0x0096", linear="0x11626"),
        ],
    }
    mapping = {
        "schema": "dosunit.mapping.v1",
        "id": "mapping:test",
        "functions": [
            {
                "oracle_id": "oracle.exe:__getbuf",
                "oracle_name": "__getbuf",
                "candidate_id": "candidate.exe:__getbuf",
                "candidate_name": "__getbuf",
                "candidate_entry": {"cs": "0x0000", "ip": "0xea22", "kind": "near"},
            },
            {
                "oracle_id": "oracle.exe:unk_libc6",
                "oracle_name": "unk_libc6",
                "candidate_id": "candidate.exe:__nmalloc",
                "candidate_name": "__nmalloc",
                "candidate_entry": {"cs": "0x0000", "ip": "0xf096", "kind": "near"},
            },
        ],
    }

    compared = compare_ssa_documents(oracle=oracle, candidate=candidate, mapping_document=mapping)

    caller = compared["results"][0]
    assert caller["status"] == "passed"
    assert caller["call_compare"]["equivalent"] is True
    assert caller["call_compare"]["candidate"]["resolved"]["name"] == "__nmalloc"
    assert [alias["name"] for alias in caller["call_compare"]["candidate"]["aliases"]] == ["__nmalloc", "malloc"]


def test_dosunit_compare_ssa_accepts_semantically_identical_renamed_call_targets():
    oracle = {
        "schema": "dosunit.ssa.v1",
        "exe": "oracle.exe",
        "functions": [
            _ssa_stub(
                "oracle.exe:caller", "caller", ip="0x0200", linear="0x1200", jumpkind="Ijk_Call", call_raw="0x1500"
            ),
            _ssa_stub("oracle.exe:unk_libc6", "unk_libc6", ip="0x0500", linear="0x1500"),
        ],
    }
    candidate = {
        "schema": "dosunit.ssa.v1",
        "exe": "candidate.exe",
        "functions": [
            _ssa_stub(
                "candidate.exe:caller", "caller", ip="0x0300", linear="0x1300", jumpkind="Ijk_Call", call_raw="0x2600"
            ),
            _ssa_stub("candidate.exe:__nmalloc", "__nmalloc", ip="0x0600", linear="0x2600"),
        ],
    }
    mapping = {
        "schema": "dosunit.mapping.v1",
        "id": "mapping:test",
        "functions": [
            {
                "oracle_id": "oracle.exe:caller",
                "oracle_name": "caller",
                "candidate_id": "candidate.exe:caller",
                "candidate_name": "caller",
                "candidate_entry": {"cs": "0x0000", "ip": "0x0300", "kind": "near"},
            }
        ],
    }

    compared = compare_ssa_documents(oracle=oracle, candidate=candidate, mapping_document=mapping)

    caller = compared["results"][0]
    assert caller["status"] == "passed"
    assert caller["call_compare"]["equivalent"] is True
    assert caller["call_compare"]["reason"] == "direct call target entry blocks have identical compact SSA"


def test_dosunit_compare_ssa_accepts_decorated_call_target_symbol_names():
    oracle = {
        "schema": "dosunit.ssa.v1",
        "exe": "oracle.exe",
        "functions": [
            _ssa_stub(
                "oracle.exe:caller", "caller", ip="0x0200", linear="0x1200", jumpkind="Ijk_Call", call_raw="0x1500"
            ),
            _ssa_stub("oracle.exe:anuldiv", "anuldiv", ip="0x0500", linear="0x1500"),
        ],
    }
    candidate = {
        "schema": "dosunit.ssa.v1",
        "exe": "candidate.exe",
        "functions": [
            _ssa_stub(
                "candidate.exe:caller", "caller", ip="0x0300", linear="0x1300", jumpkind="Ijk_Call", call_raw="0x2600"
            ),
            _ssa_stub("candidate.exe:__aNuldiv", "__aNuldiv", ip="0x0600", linear="0x2600"),
        ],
    }
    mapping = {
        "schema": "dosunit.mapping.v1",
        "id": "mapping:test",
        "functions": [
            {
                "oracle_id": "oracle.exe:caller",
                "oracle_name": "caller",
                "candidate_id": "candidate.exe:caller",
                "candidate_name": "caller",
                "candidate_entry": {"cs": "0x0000", "ip": "0x0300", "kind": "near"},
            }
        ],
    }

    compared = compare_ssa_documents(oracle=oracle, candidate=candidate, mapping_document=mapping)

    caller = compared["results"][0]
    assert caller["status"] == "passed"
    assert caller["call_compare"]["equivalent"] is True
    assert caller["call_compare"]["reason"] == "direct call targets have equivalent normalized symbol names"


def test_dosunit_compare_ssa_resolves_same_entry_call_target_aliases_by_default():
    oracle = {
        "schema": "dosunit.ssa.v1",
        "exe": "oracle.exe",
        "functions": [
            _ssa_stub("oracle.exe:rand", "rand", ip="0xebda", linear="0xfbda", jumpkind="Ijk_Call", call_raw="0xfcb0"),
            _ssa_stub("oracle.exe:__aNlmul", "__aNlmul", ip="0xecb0", linear="0xfcb0"),
        ],
    }
    candidate = {
        "schema": "dosunit.ssa.v1",
        "exe": "candidate.exe",
        "functions": [
            _ssa_stub(
                "candidate.exe:rand", "rand", ip="0xf582", linear="0x10582", jumpkind="Ijk_Call", call_raw="0x0666"
            ),
            _ssa_stub("candidate.exe:__aNlmul", "__aNlmul", ip="0xf666", linear="0x10666"),
            _ssa_stub("candidate.exe:__aNulmul", "__aNulmul", ip="0xf666", linear="0x10666"),
        ],
    }
    mapping = {
        "schema": "dosunit.mapping.v1",
        "id": "mapping:test",
        "functions": [
            {
                "oracle_id": "oracle.exe:rand",
                "oracle_name": "rand",
                "candidate_id": "candidate.exe:rand",
                "candidate_name": "rand",
                "candidate_entry": {"cs": "0x0000", "ip": "0xf582", "kind": "near"},
            },
            {
                "oracle_id": "oracle.exe:__aNlmul",
                "oracle_name": "__aNlmul",
                "candidate_id": "candidate.exe:__aNlmul",
                "candidate_name": "__aNlmul",
                "candidate_entry": {"cs": "0x0000", "ip": "0xf666", "kind": "near"},
            },
        ],
    }

    compared = compare_ssa_documents(oracle=oracle, candidate=candidate, mapping_document=mapping)

    rand = compared["results"][0]
    assert rand["status"] == "passed"
    assert rand["call_compare"]["equivalent"] is True
    assert (
        rand["call_compare"]["candidate"]["resolution_note"]
        == "resolved through same-entry aliases by by_linear_low16_all"
    )
    assert [alias["name"] for alias in rand["call_compare"]["candidate"]["aliases"]] == ["__aNlmul", "__aNulmul"]


def test_dosunit_compare_ssa_resolves_exact_linear_same_entry_call_target_aliases():
    oracle = {
        "schema": "dosunit.ssa.v1",
        "exe": "oracle.exe",
        "functions": [
            _ssa_stub(
                "oracle.exe:caller", "caller", ip="0x0100", linear="0x1100", jumpkind="Ijk_Call", call_raw="0x2080"
            ),
            _ssa_stub("oracle.exe:target_b", "target_b", ip="0x1080", linear="0x2080"),
        ],
    }
    candidate = {
        "schema": "dosunit.ssa.v1",
        "exe": "candidate.exe",
        "functions": [
            _ssa_stub(
                "candidate.exe:caller", "caller", ip="0x0200", linear="0x1200", jumpkind="Ijk_Call", call_raw="0x1300"
            ),
            _ssa_stub("candidate.exe:target_a", "target_a", ip="0x0300", linear="0x1300"),
            _ssa_stub("candidate.exe:target_b", "target_b", ip="0x0300", linear="0x1300"),
        ],
    }
    mapping = {
        "schema": "dosunit.mapping.v1",
        "id": "mapping:test",
        "functions": [
            {
                "oracle_id": "oracle.exe:caller",
                "oracle_name": "caller",
                "candidate_id": "candidate.exe:caller",
                "candidate_name": "caller",
                "candidate_entry": {"cs": "0x0000", "ip": "0x0200", "kind": "near"},
            },
            {
                "oracle_id": "oracle.exe:target_b",
                "oracle_name": "target_b",
                "candidate_id": "candidate.exe:target_b",
                "candidate_name": "target_b",
                "candidate_entry": {"cs": "0x0000", "ip": "0x0300", "kind": "near"},
            },
        ],
    }

    compared = compare_ssa_documents(oracle=oracle, candidate=candidate, mapping_document=mapping)

    caller = compared["results"][0]
    assert caller["status"] == "passed"
    assert caller["call_compare"]["equivalent"] is True
    assert (
        caller["call_compare"]["candidate"]["resolution_note"] == "resolved through same-entry aliases by by_linear_all"
    )
    assert [alias["name"] for alias in caller["call_compare"]["candidate"]["aliases"]] == ["target_a", "target_b"]


def test_dosunit_compare_ssa_resolves_unlowered_library_call_by_binary_signature(tmp_path: Path):
    signature = bytes.fromhex("55 8b ec 56 57 b8 34 12 03 c2 5f 5e 5d c3 90 90") * 2
    original_image = bytearray(0x11000)
    candidate_image = bytearray(0x11000)
    original_image[0xE9EC : 0xE9EC + len(signature)] = signature
    candidate_image[0xF34A : 0xF34A + len(signature)] = signature
    original = tmp_path / "original.exe"
    candidate = tmp_path / "candidate.exe"
    original.write_bytes(_mz_exe(bytes(original_image)))
    candidate.write_bytes(_mz_exe(bytes(candidate_image)))
    oracle = {
        "schema": "dosunit.ssa.v1",
        "exe": str(original),
        "functions": [
            _ssa_stub(
                "oracle.exe:caller", "caller", ip="0x2000", linear="0x3000", jumpkind="Ijk_Call", call_raw="0xf9ec"
            )
        ],
    }
    candidate_ssa = {
        "schema": "dosunit.ssa.v1",
        "exe": str(candidate),
        "functions": [
            _ssa_stub(
                "candidate.exe:caller",
                "caller",
                ip="0x2100",
                linear="0x3100",
                jumpkind="Ijk_Call",
                call_raw="0x034a",
            )
        ],
    }

    compared = compare_ssa_documents(oracle=oracle, candidate=candidate_ssa, skip_binary_equal=False)

    caller = compared["results"][0]
    assert caller["status"] == "passed"
    assert caller["call_compare"]["equivalent"] is True
    assert caller["call_compare"]["reason"] == "direct call targets have identical binary-local signatures"
    assert caller["call_compare"]["oracle"]["resolved"]["id"].startswith("library-signature:")
    assert caller["call_compare"]["candidate"]["resolved"]["entry"]["image_offset"] == "0x0000f34a"


def test_dosunit_compare_ssa_rejects_unlowered_library_call_when_binary_signature_differs(tmp_path: Path):
    original_signature = bytes.fromhex("55 8b ec 56 57 b8 34 12 03 c2 5f 5e 5d c3 90 90") * 2
    candidate_signature = bytes.fromhex("55 8b ec 56 57 b8 78 56 2b c2 5f 5e 5d c3 90 90") * 2
    original_image = bytearray(0x11000)
    candidate_image = bytearray(0x11000)
    original_image[0xE9EC : 0xE9EC + len(original_signature)] = original_signature
    candidate_image[0xF34A : 0xF34A + len(candidate_signature)] = candidate_signature
    original = tmp_path / "original.exe"
    candidate = tmp_path / "candidate.exe"
    original.write_bytes(_mz_exe(bytes(original_image)))
    candidate.write_bytes(_mz_exe(bytes(candidate_image)))
    oracle = {
        "schema": "dosunit.ssa.v1",
        "exe": str(original),
        "functions": [
            _ssa_stub(
                "oracle.exe:caller", "caller", ip="0x2000", linear="0x3000", jumpkind="Ijk_Call", call_raw="0xf9ec"
            )
        ],
    }
    candidate_ssa = {
        "schema": "dosunit.ssa.v1",
        "exe": str(candidate),
        "functions": [
            _ssa_stub(
                "candidate.exe:caller",
                "caller",
                ip="0x2100",
                linear="0x3100",
                jumpkind="Ijk_Call",
                call_raw="0x034a",
            )
        ],
    }

    compared = compare_ssa_documents(oracle=oracle, candidate=candidate_ssa, skip_binary_equal=False)

    caller = compared["results"][0]
    assert caller["status"] == "failed"
    assert caller["call_compare"]["equivalent"] is False
    assert caller["call_compare"]["reason"] == "no mapping proves direct call target equivalence"


def test_dosunit_compare_ssa_matches_signature_only_target_to_lowered_function_signature(tmp_path: Path):
    signature = bytes.fromhex("55 8b ec 8a 66 04 cd 16 5d c3 90 90 90 90 90 90") * 2
    original_image = bytearray(0x11000)
    candidate_image = bytearray(0x11000)
    original_image[0xEC00 : 0xEC00 + len(signature)] = signature
    candidate_image[0xF5BE : 0xF5BE + len(signature)] = signature
    original = tmp_path / "original.exe"
    candidate = tmp_path / "candidate.exe"
    original.write_bytes(_mz_exe(bytes(original_image)))
    candidate.write_bytes(_mz_exe(bytes(candidate_image)))
    oracle = {
        "schema": "dosunit.ssa.v1",
        "exe": str(original),
        "functions": [
            _ssa_stub(
                "oracle.exe:caller", "caller", ip="0x2000", linear="0x3000", jumpkind="Ijk_Call", call_raw="0xfc00"
            )
        ],
    }
    candidate_ssa = {
        "schema": "dosunit.ssa.v1",
        "exe": str(candidate),
        "functions": [
            _ssa_stub(
                "candidate.exe:caller",
                "caller",
                ip="0x2100",
                linear="0x3100",
                jumpkind="Ijk_Call",
                call_raw="0x05be",
            ),
            _ssa_stub("candidate.exe:__bios_keybrd", "__bios_keybrd", ip="0xf5be", linear="0x105be"),
        ],
    }

    compared = compare_ssa_documents(oracle=oracle, candidate=candidate_ssa, skip_binary_equal=False)

    caller = compared["results"][0]
    assert caller["status"] == "passed"
    assert caller["call_compare"]["equivalent"] is True
    assert caller["call_compare"]["reason"] == "direct call targets have identical binary-local signatures"
    assert caller["call_compare"]["candidate"]["resolved"]["name"] == "__bios_keybrd"


def test_dosunit_compare_ssa_prefers_wrapped_signature_over_ip_collision(tmp_path: Path):
    signature = bytes.fromhex("55 8b ec 8b 5e 04 0b db 74 04 80 4f fe 01 8b e5") * 2
    collision = bytes.fromhex("87 d1 8a 0e 5e 5c d3 fa 87 d1 0b c9 7e 03 8b 97") * 2
    original_image = bytearray(0x11000)
    candidate_image = bytearray(0x12000)
    original_image[0xF5C0 : 0xF5C0 + len(signature)] = signature
    candidate_image[0xF08C : 0xF08C + len(signature)] = signature
    candidate_image[0x1061C : 0x1061C + len(collision)] = collision
    original = tmp_path / "original.exe"
    candidate = tmp_path / "candidate.exe"
    original.write_bytes(_mz_exe(bytes(original_image)))
    candidate.write_bytes(_mz_exe(bytes(candidate_image)))
    oracle = {
        "schema": "dosunit.ssa.v1",
        "exe": str(original),
        "functions": [
            _ssa_stub(
                "oracle.exe:caller", "caller", ip="0x2000", linear="0x3000", jumpkind="Ijk_Call", call_raw="0x05c0"
            )
        ],
    }
    candidate_ssa = {
        "schema": "dosunit.ssa.v1",
        "exe": str(candidate),
        "functions": [
            _ssa_stub(
                "candidate.exe:caller",
                "caller",
                ip="0x2100",
                linear="0x3100",
                jumpkind="Ijk_Call",
                call_raw="0x008c",
            ),
            _ssa_stub(
                "candidate.exe:wrong_ip_collision",
                "wrong_ip_collision",
                ip="0x008c",
                linear="0x1161c",
            ),
        ],
    }

    compared = compare_ssa_documents(oracle=oracle, candidate=candidate_ssa, skip_binary_equal=False)

    caller = compared["results"][0]
    assert caller["status"] == "passed"
    assert caller["call_compare"]["equivalent"] is True
    assert caller["call_compare"]["reason"] == "direct call targets have identical binary-local signatures"
    assert caller["call_compare"]["candidate"]["resolved"]["name"].startswith("library_signature_")


def test_dosunit_compare_ssa_accepts_mapped_callee_to_signature_only_target(tmp_path: Path):
    oracle_signature = bytes.fromhex("55 8b ec ff 76 08 e8 a7 ff 83 c4 02 ff 76 06 ff") * 2
    candidate_signature = bytes.fromhex("55 8b ec ff 76 08 e8 85 ff 83 c4 02 ff 76 06 ff") * 2
    original_image = bytearray(0x11000)
    candidate_image = bytearray(0x11000)
    original_image[0x9E94 : 0x9E94 + len(oracle_signature)] = oracle_signature
    candidate_image[0x88A5 : 0x88A5 + len(candidate_signature)] = candidate_signature
    original = tmp_path / "original.exe"
    candidate = tmp_path / "candidate.exe"
    original.write_bytes(_mz_exe(bytes(original_image)))
    candidate.write_bytes(_mz_exe(bytes(candidate_image)))
    oracle = {
        "schema": "dosunit.ssa.v1",
        "exe": str(original),
        "functions": [
            _ssa_stub(
                "oracle.exe:caller", "caller", ip="0x2000", linear="0x3000", jumpkind="Ijk_Call", call_raw="0xae94"
            ),
            _ssa_stub("oracle.exe:drawColorPoint", "drawColorPoint", ip="0x9e94", linear="0xae94"),
        ],
    }
    candidate_ssa = {
        "schema": "dosunit.ssa.v1",
        "exe": str(candidate),
        "functions": [
            _ssa_stub(
                "candidate.exe:caller",
                "caller",
                ip="0x2100",
                linear="0x3100",
                jumpkind="Ijk_Call",
                call_raw="0x98a5",
            )
        ],
    }
    mapping = {
        "schema": "dosunit.mapping.v1",
        "functions": [
            {
                "oracle_id": "oracle.exe:caller",
                "oracle_name": "caller",
                "candidate_id": "candidate.exe:caller",
                "candidate_name": "caller",
            },
            {
                "oracle_id": "oracle.exe:drawColorPoint",
                "oracle_name": "drawColorPoint",
                "candidate_id": "candidate.exe:drawColorPoint",
                "candidate_name": "drawColorPoint",
            },
        ],
    }

    compared = compare_ssa_documents(
        oracle=oracle, candidate=candidate_ssa, mapping_document=mapping, skip_binary_equal=False
    )

    caller = compared["results"][0]
    assert caller["status"] == "passed"
    assert caller["call_compare"]["equivalent"] is True
    assert caller["call_compare"]["reason"] == "direct call targets have identical normalized binary-local signatures"


def test_dosunit_compare_ssa_trims_binary_signature_at_terminal_jump(tmp_path: Path):
    oracle_signature = bytes.fromhex("59 8b dc 2b d8 72 0a 3b 1e dc 61 72 04 8b e3 ff e1 33 c0 e9 6b fe 55 8b ec")
    candidate_signature = bytes.fromhex("59 8b dc 2b d8 72 0a 3b 1e ca a0 72 04 8b e3 ff e1 33 c0 e9 45 fe 56 33 f6")
    original_image = bytearray(0x11000)
    candidate_image = bytearray(0x11000)
    original_image[0xE654 : 0xE654 + len(oracle_signature)] = oracle_signature
    candidate_image[0xE324 : 0xE324 + len(candidate_signature)] = candidate_signature
    original = tmp_path / "original.exe"
    candidate = tmp_path / "candidate.exe"
    original.write_bytes(_mz_exe(bytes(original_image)))
    candidate.write_bytes(_mz_exe(bytes(candidate_image)))
    oracle = {
        "schema": "dosunit.ssa.v1",
        "exe": str(original),
        "functions": [
            _ssa_stub(
                "oracle.exe:caller", "caller", ip="0x2000", linear="0x3000", jumpkind="Ijk_Call", call_raw="0xf654"
            )
        ],
    }
    candidate_ssa = {
        "schema": "dosunit.ssa.v1",
        "exe": str(candidate),
        "functions": [
            _ssa_stub(
                "candidate.exe:caller",
                "caller",
                ip="0x2100",
                linear="0x3100",
                jumpkind="Ijk_Call",
                call_raw="0xf324",
            )
        ],
    }

    compared = compare_ssa_documents(oracle=oracle, candidate=candidate_ssa, skip_binary_equal=False)

    caller = compared["results"][0]
    assert caller["status"] == "passed"
    assert caller["call_compare"]["reason"] == "direct call targets have identical normalized binary-local signatures"


def test_dosunit_compare_ssa_accepts_normalized_binary_signature_immediate_differences(tmp_path: Path):
    original_signature = bytes.fromhex("55 8b ec b8 34 12 e9 03 00 90 90 5d c3 90 90 90") * 2
    candidate_signature = bytes.fromhex("55 8b ec b8 78 56 e9 08 00 90 90 5d c3 90 90 90") * 2
    original_image = bytearray(0x11000)
    candidate_image = bytearray(0x11000)
    original_image[0xEC00 : 0xEC00 + len(original_signature)] = original_signature
    candidate_image[0xF5BE : 0xF5BE + len(candidate_signature)] = candidate_signature
    original = tmp_path / "original.exe"
    candidate = tmp_path / "candidate.exe"
    original.write_bytes(_mz_exe(bytes(original_image)))
    candidate.write_bytes(_mz_exe(bytes(candidate_image)))
    oracle = {
        "schema": "dosunit.ssa.v1",
        "exe": str(original),
        "functions": [
            _ssa_stub(
                "oracle.exe:caller", "caller", ip="0x2000", linear="0x3000", jumpkind="Ijk_Call", call_raw="0xfc00"
            )
        ],
    }
    candidate_ssa = {
        "schema": "dosunit.ssa.v1",
        "exe": str(candidate),
        "functions": [
            _ssa_stub(
                "candidate.exe:caller",
                "caller",
                ip="0x2100",
                linear="0x3100",
                jumpkind="Ijk_Call",
                call_raw="0x05be",
            )
        ],
    }

    compared = compare_ssa_documents(oracle=oracle, candidate=candidate_ssa, skip_binary_equal=False)

    caller = compared["results"][0]
    assert caller["status"] == "passed"
    assert caller["call_compare"]["equivalent"] is True
    assert caller["call_compare"]["reason"] == "direct call targets have identical normalized binary-local signatures"


def test_dosunit_report_shows_unresolved_call_targets_by_default(tmp_path: Path):
    document = {
        "schema": "dosunit.ssa_compare.v1",
        "oracle": "oracle.exe",
        "candidate": "candidate.exe",
        "mapping": "mapping:test",
        "summary": {"total": 1, "passed": 0, "failed": 1, "refused": 0, "skipped_unmapped": 0, "solver_time_ms": 0},
        "results": [
            {
                "status": "failed",
                "reason": "observable_mismatch",
                "function": {"id": "oracle.exe:caller", "name": "caller"},
                "call_compare": {
                    "kind": "direct_call",
                    "equivalent": False,
                    "reason": "one or both direct call targets did not resolve to SSA functions",
                    "oracle": {
                        "kind": "direct",
                        "raw": "0x1000",
                        "low16": "0x1000",
                        "resolved": None,
                        "reason": "no SSA function starts at the direct call target",
                    },
                    "candidate": {
                        "kind": "direct",
                        "raw": "0x2000",
                        "low16": "0x2000",
                        "resolved": None,
                        "reason": "no SSA function starts at the direct call target",
                    },
                },
                "mismatches": [{"kind": "output_expr_changed", "reg": "call_target"}],
            }
        ],
    }
    results_path = tmp_path / "ssa.results.json"
    hidden_path = tmp_path / "hidden.md"
    shown_path = tmp_path / "shown.md"
    results_path.write_text(json.dumps(document))

    shown = render_failure_report(document)
    hidden = render_failure_report(document, show_unresolved_call_targets=False)

    assert "Unresolved-call-target rows skipped: 0" in shown
    assert "caller" in shown
    assert "Unresolved-call-target rows skipped: 1" in hidden
    assert "caller" not in hidden
    assert dosunit_main(["report-failures", "--results", str(results_path), "--out", str(shown_path)]) == 0
    assert (
        dosunit_main(
            [
                "report-failures",
                "--results",
                str(results_path),
                "--hide-unresolved-call-targets",
                "--out",
                str(hidden_path),
            ]
        )
        == 0
    )
    assert "caller" in shown_path.read_text()
    assert "caller" not in hidden_path.read_text()


def test_dosunit_report_group_by_function(tmp_path: Path):
    document = {
        "schema": "dosunit.ssa_compare.v1",
        "oracle": "oracle.exe",
        "candidate": "candidate.exe",
        "mapping": "mapping:test",
        "summary": {"total": 2, "passed": 0, "failed": 1, "refused": 1, "skipped_unmapped": 0, "solver_time_ms": 0},
        "results": [
            {
                "status": "failed",
                "reason": "observable_mismatch",
                "function": {"id": "oracle.exe:foo", "name": "foo"},
                "oracle_function": "ssa-function:oracle-foo",
                "candidate_function": "ssa-function:candidate-foo",
                "function_entry": {"cs": "0x0000", "ip": "0x0200"},
                "mismatches": [{"kind": "output_expr_changed", "reg": "ax"}],
                "oracle_detail": {
                    "entry": {"cs": "0x0000", "ip": "0x0200"},
                    "instruction_count": 2,
                    "jumpkind": "Ijk_Ret",
                    "input_count": 1,
                    "assignment_count": 1,
                    "instructions": [{"address": {"ip": "0x0200"}, "disassembly": "ret", "size": 1}],
                },
                "candidate_detail": {
                    "entry": {"cs": "0x0000", "ip": "0x0300"},
                    "instruction_count": 2,
                    "jumpkind": "Ijk_Ret",
                    "input_count": 1,
                    "assignment_count": 1,
                    "instructions": [{"address": {"ip": "0x0300"}, "disassembly": "ret", "size": 1}],
                },
            },
            {
                "status": "refused",
                "reason": "successor_state_unobserved",
                "function": {"id": "oracle.exe:foo", "name": "foo"},
                "oracle_function": "ssa-function:oracle-foo",
                "candidate_function": "ssa-function:candidate-foo",
                "mismatches": [{"kind": "connectivity_state_unobserved", "oracle_missing_inputs": ["ax"]}],
                "oracle_detail": {
                    "entry": {"cs": "0x0000", "ip": "0x0200"},
                    "instruction_count": 2,
                    "jumpkind": "Ijk_Ret",
                    "input_count": 1,
                    "assignment_count": 1,
                    "instructions": [{"address": {"ip": "0x0200"}, "disassembly": "ret", "size": 1}],
                },
                "candidate_detail": {
                    "entry": {"cs": "0x0000", "ip": "0x0300"},
                    "instruction_count": 2,
                    "jumpkind": "Ijk_Ret",
                    "input_count": 1,
                    "assignment_count": 1,
                    "instructions": [{"address": {"ip": "0x0300"}, "disassembly": "ret", "size": 1}],
                },
            },
        ],
    }
    report = render_failure_report(document, group_by_function=True)
    assert "Function-Grouped SSA Results" in report
    assert "### 1. `foo`" in report
    assert "- Entries for function: `2`" in report

    results_path = tmp_path / "ssa.results.json"
    grouped_path = tmp_path / "grouped.md"
    results_path.write_text(json.dumps(document))
    assert (
        dosunit_main(
            ["report-failures", "--results", str(results_path), "--group-by-function", "--out", str(grouped_path)]
        )
        == 0
    )
    grouped = grouped_path.read_text()
    assert "Function id" in grouped
    assert "Mismatch kinds" in grouped


def test_dosunit_report_failed_only_filter(tmp_path: Path):
    document = {
        "schema": "dosunit.ssa_compare.v1",
        "oracle": "oracle.exe",
        "candidate": "candidate.exe",
        "mapping": "mapping:test",
        "summary": {"total": 3, "passed": 0, "failed": 1, "refused": 2, "skipped_unmapped": 0, "solver_time_ms": 0},
        "results": [
            {
                "status": "failed",
                "reason": "observable_mismatch",
                "function": {"id": "oracle.exe:foo", "name": "foo"},
                "oracle_function": "ssa-function:oracle-foo",
                "candidate_function": "ssa-function:candidate-foo",
                "mismatches": [
                    {"kind": "output_expr_changed", "reg": "ax", "oracle_value": "0x0001", "candidate_value": "0x0002"}
                ],
                "oracle_detail": {
                    "entry": {"cs": "0x0000", "ip": "0x0200"},
                    "instruction_count": 1,
                    "instructions": [{"address": {"ip": "0x0200"}, "disassembly": "mov ax, 1"}],
                },
                "candidate_detail": {
                    "entry": {"cs": "0x0000", "ip": "0x0300"},
                    "instruction_count": 1,
                    "instructions": [{"address": {"ip": "0x0300"}, "disassembly": "mov ax, 2"}],
                },
            },
            {
                "status": "refused",
                "reason": "successor_state_unobserved",
                "function": {"id": "oracle.exe:foo", "name": "foo"},
                "oracle_function": "ssa-function:oracle-foo",
                "candidate_function": "ssa-function:candidate-foo",
                "mismatches": [{"kind": "connectivity_state_unobserved", "detail": "ignored"}],
            },
            {
                "status": "refused",
                "reason": "slice_too_large",
                "function": {"id": "oracle.exe:bar", "name": "bar"},
                "oracle_function": "ssa-function:oracle-bar",
                "candidate_function": "ssa-function:candidate-bar",
                "mismatches": [{"kind": "solver_gate", "detail": "ignored"}],
            },
        ],
    }
    report = render_failure_report(document, group_by_function=True, failed_only=True)
    assert "Function-Grouped SSA Results" in report
    assert "foo" in report
    assert "bar" not in report
    assert "successor_state_unobserved" not in report

    results_path = tmp_path / "ssa.results.json"
    filtered_path = tmp_path / "filtered.md"
    results_path.write_text(json.dumps(document))
    assert (
        dosunit_main(
            [
                "report-failures",
                "--results",
                str(results_path),
                "--group-by-function",
                "--failed-only",
                "--out",
                str(filtered_path),
            ]
        )
        == 0
    )
    filtered = filtered_path.read_text()
    assert "Function-Grouped SSA Results" in filtered
    assert "foo" in filtered
    assert "bar" not in filtered


def test_dosunit_straightline_ssa_lowers_memory_load_in_output_slice(tmp_path: Path):
    image = bytearray(0x240)
    image[0x200:0x204] = b"\x8b\x44\x04\xc3"  # mov ax, [si+4]; ret
    exe = tmp_path / "demo.exe"
    exe.write_bytes(_mz_exe(bytes(image)))
    catalog = _edge_catalog("demo.exe:load_indexed", "load_indexed", offset=0x0200, size=4)

    document = lower_straightline_ssa_document(exe_path=exe, functions_catalog=catalog, output_regs=("ax",))

    assert document["counters"]["functions_lowered"] == 1
    function = document["functions"][0]
    assert {"kind": "memory", "name": "mem", "addr_width": 32, "value_width": 8} in function["inputs"]
    assert "loadle" in json.dumps(function["assignments"], sort_keys=True)


def test_dosunit_compare_ssa_checks_memory_store_effects(tmp_path: Path):
    original_image = bytearray(0x240)
    equivalent_image = bytearray(0x240)
    changed_image = bytearray(0x240)
    original_image[0x200:0x204] = b"\x89\x44\x04\xc3"  # mov [si+4], ax; ret
    equivalent_image[0x200:0x204] = b"\x89\x44\x04\xc3"  # mov [si+4], ax; ret
    changed_image[0x200:0x204] = b"\x89\x5c\x04\xc3"  # mov [si+4], bx; ret
    original = tmp_path / "original.exe"
    equivalent = tmp_path / "equivalent.exe"
    changed = tmp_path / "changed.exe"
    original.write_bytes(_mz_exe(bytes(original_image)))
    equivalent.write_bytes(_mz_exe(bytes(equivalent_image)))
    changed.write_bytes(_mz_exe(bytes(changed_image)))
    catalog = _edge_catalog("demo.exe:store_indexed", "store_indexed", offset=0x0200, size=4)

    oracle = lower_straightline_ssa_document(exe_path=original, functions_catalog=catalog, output_regs=("ax",))
    equivalent_ssa = lower_straightline_ssa_document(
        exe_path=equivalent, functions_catalog=catalog, output_regs=("ax",)
    )
    changed_ssa = lower_straightline_ssa_document(exe_path=changed, functions_catalog=catalog, output_regs=("ax",))

    assert oracle["counters"]["functions_lowered"] == 1
    assert "memory" in oracle["functions"][0]["outputs"]
    assert "storele" in json.dumps(oracle["functions"][0]["assignments"], sort_keys=True)
    passed = compare_ssa_documents(oracle=oracle, candidate=equivalent_ssa)
    failed = compare_ssa_documents(oracle=oracle, candidate=changed_ssa)

    assert passed["summary"]["passed"] == 1
    assert failed["summary"]["failed"] == 1
    assert any(mismatch["kind"] == "memory_expr_changed" for mismatch in failed["results"][0]["mismatches"])


def test_dosunit_straightline_ssa_lowers_vex_normalized_partial_register_write(tmp_path: Path):
    image = bytearray(0x240)
    image[0x200:0x203] = b"\xb0\x12\xc3"  # mov al, 0x12; ret
    exe = tmp_path / "demo.exe"
    exe.write_bytes(_mz_exe(bytes(image)))
    catalog = _edge_catalog("demo.exe:partial_reg", "partial_reg", offset=0x0200, size=3)

    document = lower_straightline_ssa_document(exe_path=exe, functions_catalog=catalog, output_regs=("ax",))

    assert document["counters"]["functions_lowered"] == 1
    function = document["functions"][0]
    assert function["inputs"] == [{"name": "ax", "width": 16}]
    serialized = json.dumps(function["assignments"], sort_keys=True)
    assert "0xff00" in serialized
    assert "0x12" in serialized
    assert '"and"' in serialized
    assert '"or"' in serialized


def test_dosunit_straightline_ssa_lowers_ail_equivalent_to_vex(tmp_path: Path):
    image = bytearray(0x240)
    image[0x200:0x206] = b"\x89\xd8\x83\xc0\x01\xc3"  # mov ax, bx; add ax, 1; ret
    exe = tmp_path / "demo.exe"
    exe.write_bytes(_mz_exe(bytes(image)))
    catalog = _edge_catalog("demo.exe:leaf_math", "leaf_math", offset=0x0200, size=6)

    vex = lower_straightline_ssa_document(
        exe_path=exe, functions_catalog=catalog, output_regs=("ax", "sp"), source_ir="vex"
    )
    ail = lower_straightline_ssa_document(
        exe_path=exe, functions_catalog=catalog, output_regs=("ax", "sp"), source_ir="ail"
    )
    compared = compare_ssa_documents(oracle=vex, candidate=ail)

    assert ail["source_ir"] == "ail"
    assert ail["parameters"]["source_ir"] == "ail"
    assert ail["functions"][0]["source"]["ir"] == "ail"
    assert ail["counters"]["functions_lowered"] == 1
    assert compared["summary"]["passed"] == 1
    serialized = json.dumps(ail["functions"][0]["assignments"], sort_keys=True)
    assert "add" in serialized
    assert "flags" not in serialized


def test_dosunit_straightline_ssa_lowers_ail_memory_and_call_boundary(tmp_path: Path):
    store_image = bytearray(0x240)
    call_image = bytearray(0x260)
    store_image[0x200:0x204] = b"\x89\x44\x04\xc3"  # mov [si+4], ax; ret
    call_image[0x200:0x204] = b"\xe8\x1d\x00\xc3"  # call 0x1220; ret
    call_image[0x220:0x224] = b"\xb8\x34\x12\xc3"  # mov ax, 0x1234; ret
    store_exe = tmp_path / "store.exe"
    call_exe = tmp_path / "call.exe"
    store_exe.write_bytes(_mz_exe(bytes(store_image)))
    call_exe.write_bytes(_mz_exe(bytes(call_image)))
    store_catalog = _edge_catalog("demo.exe:store_indexed", "store_indexed", offset=0x0200, size=4)
    call_catalog = {
        "schema": "dosunit.functions.v1",
        "id": "functions:call",
        "module": "demo.exe",
        "program_kind": "mz_exe",
        "functions": [
            _edge_function("demo.exe:caller", "caller", offset=0x0200, size=4),
            _edge_function("demo.exe:callee", "callee", offset=0x0220, size=4),
        ],
        "diagnostics": [],
    }

    vex_store = lower_straightline_ssa_document(
        exe_path=store_exe, functions_catalog=store_catalog, output_regs=("ax", "sp"), source_ir="vex"
    )
    ail_store = lower_straightline_ssa_document(
        exe_path=store_exe, functions_catalog=store_catalog, output_regs=("ax", "sp"), source_ir="ail"
    )
    vex_call = lower_straightline_ssa_document(
        exe_path=call_exe,
        functions_catalog=call_catalog,
        output_regs=("ax", "sp"),
        source_ir="vex",
        follow_call_fallthrough=False,
    )
    ail_call = lower_straightline_ssa_document(
        exe_path=call_exe,
        functions_catalog=call_catalog,
        output_regs=("ax", "sp"),
        source_ir="ail",
        follow_call_fallthrough=False,
    )

    assert "memory" in ail_store["functions"][0]["outputs"]
    assert "storele" in json.dumps(ail_store["functions"][0]["assignments"], sort_keys=True)
    assert compare_ssa_documents(oracle=vex_store, candidate=ail_store)["summary"]["passed"] == 1
    caller = next(function for function in ail_call["functions"] if function["function"]["name"] == "caller")
    assert caller["source"]["jumpkind"] == "Ijk_Call"
    assert caller["source"]["transfer"]["target"]["low16"] == "0x1220"
    assert "memory" in caller["outputs"]
    assert compare_ssa_documents(oracle=vex_call, candidate=ail_call)["summary"]["passed"] == 2


def test_dosunit_straightline_ssa_refuses_oversized_slices_by_assignment_gate(tmp_path: Path):
    image = bytearray(0x240)
    image[0x200:0x206] = b"\x89\xd8\x83\xc0\x01\xc3"  # mov ax, bx; add ax, 1; ret
    exe = tmp_path / "demo.exe"
    exe.write_bytes(_mz_exe(bytes(image)))
    catalog = _edge_catalog("demo.exe:leaf_math", "leaf_math", offset=0x0200, size=6)

    document = lower_straightline_ssa_document(
        exe_path=exe,
        functions_catalog=catalog,
        output_regs=("ax", "sp"),
        max_assignments_per_function=1,
    )

    assert document["counters"]["functions_refused"] == 1
    assert document["refusals"][0]["reason"] == "slice_too_large"
    assert "SSA assignment limit reached" in document["refusals"][0]["detail"]["message"]


def test_dosunit_compare_ssa_refuses_solver_slices_over_gate(tmp_path: Path):
    original_image = bytearray(0x240)
    changed_image = bytearray(0x240)
    original_image[0x200:0x206] = b"\x89\xd8\x83\xc0\x01\xc3"  # mov ax, bx; add ax, 1; ret
    changed_image[0x200:0x206] = b"\x89\xd8\x83\xc0\x02\xc3"  # mov ax, bx; add ax, 2; ret
    original = tmp_path / "original.exe"
    changed = tmp_path / "changed.exe"
    original.write_bytes(_mz_exe(bytes(original_image)))
    changed.write_bytes(_mz_exe(bytes(changed_image)))
    catalog = _edge_catalog("demo.exe:leaf_math", "leaf_math", offset=0x0200, size=6)
    oracle = lower_straightline_ssa_document(exe_path=original, functions_catalog=catalog, output_regs=("ax", "sp"))
    candidate = lower_straightline_ssa_document(exe_path=changed, functions_catalog=catalog, output_regs=("ax", "sp"))

    compared = compare_ssa_documents(
        oracle=oracle, candidate=candidate, max_solver_assignments=1, skip_binary_equal=False
    )

    assert compared["summary"]["refused"] == 1
    assert compared["results"][0]["reason"] == "slice_too_large"
    assert compared["results"][0]["mismatches"][0]["kind"] == "solver_gate"
    assert compared["results"][0]["mismatches"][0]["metric"] == "assignments"


def test_dosunit_straightline_ssa_uses_single_file_vex_disk_cache(tmp_path: Path):
    image = bytearray(0x240)
    image[0x200:0x204] = b"\xb8\x34\x12\xc3"  # mov ax, 0x1234; ret
    exe = tmp_path / "demo.exe"
    exe.write_bytes(_mz_exe(bytes(image)))
    catalog = _edge_catalog("demo.exe:imm_leaf", "imm_leaf", offset=0x0200, size=4)
    cache_dir = tmp_path / "cache"

    first = lower_straightline_ssa_document(
        exe_path=exe, functions_catalog=catalog, output_regs=("ax",), cache_dir=cache_dir
    )
    second = lower_straightline_ssa_document(
        exe_path=exe, functions_catalog=catalog, output_regs=("ax",), cache_dir=cache_dir
    )

    assert first["counters"]["lifter_cache_misses"] == 1
    assert first["counters"]["lifter_cache_writes"] == 1
    assert second["counters"]["lifter_cache_hits"] == 1
    assert second["counters"]["lifter_blocks_lifted"] == 0
    cache_files = list((cache_dir / "vex").glob("*.pickle"))
    assert len(cache_files) == 1


def test_dosunit_cli_ssa_defaults_to_msc16_near_and_accepts_ail(tmp_path: Path):
    image = bytearray(0x240)
    image[0x200:0x204] = b"\xb8\x34\x12\xc3"  # mov ax, 0x1234; ret
    exe = tmp_path / "demo.exe"
    exe.write_bytes(_mz_exe(bytes(image)))
    catalog = _edge_catalog("demo.exe:imm_leaf", "imm_leaf", offset=0x0200, size=4)
    functions_path = tmp_path / "functions.json"
    default_path = tmp_path / "default.ssa.json"
    raw_path = tmp_path / "raw.ssa.json"
    functions_path.write_text(json.dumps(catalog))

    assert (
        dosunit_main(
            ["ssa", "--ir", "ail", "--exe", str(exe), "--functions", str(functions_path), "--out", str(default_path)]
        )
        == 0
    )
    assert (
        dosunit_main(
            ["ssa", "--abi", "raw-all", "--exe", str(exe), "--functions", str(functions_path), "--out", str(raw_path)]
        )
        == 0
    )
    default_doc = json.loads(default_path.read_text())
    raw_doc = json.loads(raw_path.read_text())

    assert default_doc["source_ir"] == "ail"
    assert default_doc["parameters"]["output_regs"] == ["ax", "dx", "sp"]
    assert set(default_doc["functions"][0]["outputs"]) == {"ax", "dx", "sp"}
    assert raw_doc["parameters"]["output_regs"] == ["ax", "bx", "cx", "dx", "si", "di", "bp", "sp"]


def test_dosunit_cli_max_rss_default_and_limit_helpers(monkeypatch):
    monkeypatch.delenv("DOSUNIT_MAX_RSS_MB", raising=False)
    assert dosunit_cli._default_max_rss_mb() == 4096

    monkeypatch.setenv("DOSUNIT_MAX_RSS_MB", "123")
    assert dosunit_cli._default_max_rss_mb() == 123

    monkeypatch.setenv("DOSUNIT_MAX_RSS_MB", "not-an-int")
    assert dosunit_cli._default_max_rss_mb() == 4096

    assert not dosunit_cli._rss_limit_exceeded(None, 4096)
    assert not dosunit_cli._rss_limit_exceeded(4096 * 1024, 4096)
    assert dosunit_cli._rss_limit_exceeded(4096 * 1024 + 1, 4096)
    assert not dosunit_cli._rss_limit_exceeded(10 * 1024 * 1024, 0)


def test_dosunit_cli_compare_ssa_accepts_max_rss_option(tmp_path: Path):
    parser = dosunit_cli.build_parser()
    args = parser.parse_args(
        [
            "compare-ssa",
            "--oracle-ssa",
            str(tmp_path / "oracle.ssa.json"),
            "--candidate-ssa",
            str(tmp_path / "candidate.ssa.json"),
            "--max-rss-mb",
            "2048",
            "--out",
            str(tmp_path / "results.json"),
        ]
    )

    assert args.max_rss_mb == 2048


def test_dosunit_cli_defaults_are_large_program_safe(tmp_path: Path):
    parser = dosunit_cli.build_parser(prog="z3func")

    ssa_args = parser.parse_args(
        [
            "ssa",
            "--exe",
            str(tmp_path / "oracle.exe"),
            "--functions",
            str(tmp_path / "functions.json"),
            "--out",
            str(tmp_path / "oracle.ssa.json"),
        ]
    )
    assert ssa_args.max_blocks_per_function == 1000
    assert ssa_args.max_insns_per_function == 256
    assert ssa_args.max_ssa_assignments == 0
    assert ssa_args.scan_limit == 0x1000

    compare_args = parser.parse_args(
        [
            "compare-ssa",
            "--oracle-ssa",
            str(tmp_path / "oracle.ssa.json"),
            "--candidate-ssa",
            str(tmp_path / "candidate.ssa.json"),
            "--out",
            str(tmp_path / "compare.json"),
        ]
    )
    assert compare_args.solver_timeout_ms == 60000
    assert compare_args.max_solver_assignments == 0
    assert compare_args.max_solver_inputs == 0
    assert compare_args.max_solver_memory_stores == 32
    assert compare_args.semantic_proof_passes == 2
    assert compare_args.max_region_loop_unroll == 2

    batched_args = parser.parse_args(
        [
            "compare-ssa-batched",
            "--oracle-ssa",
            str(tmp_path / "oracle.ssa.json"),
            "--candidate-ssa",
            str(tmp_path / "candidate.ssa.json"),
            "--out-dir",
            str(tmp_path / "batches"),
            "--out",
            str(tmp_path / "aggregate.json"),
        ]
    )
    assert batched_args.batch_size == 64
    assert batched_args.batch_timeout_ms == 300000
    assert batched_args.max_solver_assignments == 0
    assert batched_args.max_solver_inputs == 0
    assert batched_args.semantic_proof_passes == 2
    assert batched_args.max_region_loop_unroll == 2

    abi_args = parser.parse_args(
        [
            "compare-ssa-abi",
            "--oracle-ssa",
            str(tmp_path / "oracle.ssa.json"),
            "--candidate-ssa",
            str(tmp_path / "candidate.ssa.json"),
            "--abi-manifest",
            str(tmp_path / "abi.json"),
            "--out",
            str(tmp_path / "abi.compare.json"),
        ]
    )
    assert abi_args.solver_timeout_ms == 60000
    assert abi_args.max_solver_assignments == 0
    assert abi_args.max_solver_inputs == 0
    assert abi_args.max_solver_memory_stores == 32
    assert abi_args.max_loop_unroll == 2
    assert parser.prog == "z3func"


def test_dosunit_cli_batched_help_does_not_show_stop_as_default(capsys: pytest.CaptureFixture[str]):
    parser = dosunit_cli.build_parser(prog="z3func")

    with pytest.raises(SystemExit) as exc_info:
        parser.parse_args(["compare-ssa-batched", "--help"])

    assert exc_info.value.code == 0
    help_text = capsys.readouterr().out
    assert "Number of oracle SSA units per child compare process" in help_text
    assert "(default: 64)" in help_text
    assert "Continue running later batches after a" in help_text
    assert "--stop-on-failure" in help_text
    assert "Stop after the first failed/refused/nonzero batch\n                        (default:" not in help_text


def test_dosunit_cli_compare_ssa_batched_runs_sequential_child_processes(tmp_path: Path):
    oracle = {
        "schema": "dosunit.ssa.v1",
        "exe": "oracle.exe",
        "functions": [
            _ssa_stub("demo.exe:first", "first", ip="0x0200", linear="0x1200"),
            _ssa_stub("demo.exe:second", "second", ip="0x0300", linear="0x1300"),
        ],
    }
    candidate = {
        "schema": "dosunit.ssa.v1",
        "exe": "candidate.exe",
        "functions": [
            _ssa_stub("demo.exe:first", "first", ip="0x0200", linear="0x1200"),
            _ssa_stub("demo.exe:second", "second", ip="0x0300", linear="0x1300"),
        ],
    }
    oracle_path = tmp_path / "oracle.ssa.json"
    candidate_path = tmp_path / "candidate.ssa.json"
    out_dir = tmp_path / "batches"
    aggregate_path = tmp_path / "batched.compare.json"
    report_path = tmp_path / "batched.report.md"
    oracle_path.write_text(json.dumps(oracle))
    candidate_path.write_text(json.dumps(candidate))

    rc = dosunit_main(
        [
            "compare-ssa-batched",
            "--oracle-ssa",
            str(oracle_path),
            "--candidate-ssa",
            str(candidate_path),
            "--batch-size",
            "1",
            "--max-rss-mb",
            "0",
            "--out-dir",
            str(out_dir),
            "--out",
            str(aggregate_path),
        ]
    )

    assert rc == 0
    aggregate = json.loads(aggregate_path.read_text())
    assert aggregate["schema"] == "dosunit.ssa_batched_compare.v1"
    assert aggregate["summary"]["batches"] == 2
    assert aggregate["summary"]["main_passed"] == 2
    assert aggregate["summary"]["main_failed"] == 0
    assert aggregate["summary"]["main_refused"] == 0
    assert aggregate["summary"]["candidate_only_parts"] == 0
    assert aggregate["summary"]["region_total"] == aggregate["region_equality"]["total"]
    assert aggregate["summary"]["connectivity_edges_checked"] == aggregate["connectivity"]["edges_checked"]
    assert aggregate["summary"]["loop_scc_total"] == aggregate["loop_scc"]["total"]
    assert aggregate["summary"]["call_scc_total"] == aggregate["call_scc"]["total"]
    assert (out_dir / "compare.batch001.json").exists()
    assert (out_dir / "compare.batch002.json").exists()
    assert dosunit_main(["report-failures", "--results", str(aggregate_path), "--out", str(report_path)]) == 0
    report = report_path.read_text()
    assert "Batched SSA Compare Report" in report
    assert "No failed or refused batches" in report
    assert "Candidate-only SSA parts: `0`" in report
    assert "Region equality:" in report
    assert "Connectivity:" in report
    assert "Loop SCCs:" in report
    assert "Call SCCs:" in report


def test_dosunit_compare_ssa_reports_candidate_only_parts():
    oracle = {
        "schema": "dosunit.ssa.v1",
        "exe": "oracle.exe",
        "functions": [_ssa_stub("demo.exe:kept", "kept", ip="0x0200", linear="0x1200")],
    }
    candidate = {
        "schema": "dosunit.ssa.v1",
        "exe": "candidate.exe",
        "functions": [
            _ssa_stub("demo.exe:kept", "kept", ip="0x0200", linear="0x1200"),
            _ssa_stub("demo.exe:extra", "extra", ip="0x0300", linear="0x1300"),
        ],
    }

    document = compare_ssa_documents(oracle=oracle, candidate=candidate)

    assert document["summary"]["passed"] == 1
    assert document["summary"]["candidate_parts_total"] == 2
    assert document["summary"]["candidate_parts_referenced"] == 1
    assert document["summary"]["candidate_only_parts"] == 1
    assert document["candidate_only_parts"]["parts"][0]["function"]["name"] == "extra"
    report = render_failure_report(document)
    assert "Candidate-only SSA parts: `1` of `2`" in report
    assert "## Candidate-Only SSA Parts" in report
    assert "`extra` candidate-only" in report


def test_dosunit_compare_ssa_classifies_candidate_only_alias_parts():
    oracle = {
        "schema": "dosunit.ssa.v1",
        "exe": "oracle.exe",
        "functions": [_ssa_stub("demo.exe:kept", "kept", ip="0x0200", linear="0x1200")],
    }
    candidate = {
        "schema": "dosunit.ssa.v1",
        "exe": "candidate.exe",
        "functions": [
            _ssa_stub("demo.exe:kept", "kept", ip="0x0200", linear="0x1200"),
            _ssa_stub("demo.exe:kept_alias", "keptAlias", ip="0x0200", linear="0x1200"),
        ],
    }

    document = compare_ssa_documents(oracle=oracle, candidate=candidate)

    assert document["summary"]["candidate_only_parts"] == 0
    assert document["summary"]["candidate_alias_only_parts"] == 1
    report = render_failure_report(document)
    assert "Candidate-only SSA parts: `0` of `2` candidate parts, alias-only `1`" in report
    assert "## Candidate Alias-Only SSA Parts" in report
    assert "`keptAlias` candidate-only" in report


def test_dosunit_cli_compare_ssa_batched_reports_candidate_only_parts(tmp_path: Path):
    oracle = {
        "schema": "dosunit.ssa.v1",
        "exe": "oracle.exe",
        "functions": [_ssa_stub("demo.exe:kept", "kept", ip="0x0200", linear="0x1200")],
    }
    candidate = {
        "schema": "dosunit.ssa.v1",
        "exe": "candidate.exe",
        "functions": [
            _ssa_stub("demo.exe:kept", "kept", ip="0x0200", linear="0x1200"),
            _ssa_stub("demo.exe:extra", "extra", ip="0x0300", linear="0x1300"),
        ],
    }
    oracle_path = tmp_path / "oracle.ssa.json"
    candidate_path = tmp_path / "candidate.ssa.json"
    out_dir = tmp_path / "batches"
    aggregate_path = tmp_path / "batched.compare.json"
    report_path = tmp_path / "batched.report.md"
    oracle_path.write_text(json.dumps(oracle))
    candidate_path.write_text(json.dumps(candidate))

    rc = dosunit_main(
        [
            "compare-ssa-batched",
            "--oracle-ssa",
            str(oracle_path),
            "--candidate-ssa",
            str(candidate_path),
            "--batch-size",
            "1",
            "--max-rss-mb",
            "0",
            "--out-dir",
            str(out_dir),
            "--out",
            str(aggregate_path),
        ]
    )

    assert rc == 0
    aggregate = json.loads(aggregate_path.read_text())
    assert aggregate["summary"]["candidate_parts_total"] == 2
    assert aggregate["summary"]["candidate_parts_referenced"] == 1
    assert aggregate["summary"]["candidate_only_parts"] == 1
    assert aggregate["candidate_only_parts"]["parts"][0]["function"]["name"] == "extra"
    assert dosunit_main(["report-failures", "--results", str(aggregate_path), "--out", str(report_path)]) == 0
    report = report_path.read_text()
    assert "Candidate-only SSA parts: `1` of `2`" in report
    assert "## Candidate-Only SSA Parts" in report
    assert "`extra` candidate-only" in report


def test_dosunit_cli_compare_ssa_batched_reports_child_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    oracle = {
        "schema": "dosunit.ssa.v1",
        "exe": "oracle.exe",
        "functions": [_ssa_stub("demo.exe:slow", "slow", ip="0x0200", linear="0x1200")],
    }
    candidate = {
        "schema": "dosunit.ssa.v1",
        "exe": "candidate.exe",
        "functions": [_ssa_stub("demo.exe:slow", "slow", ip="0x0200", linear="0x1200")],
    }
    oracle_path = tmp_path / "oracle.ssa.json"
    candidate_path = tmp_path / "candidate.ssa.json"
    aggregate_path = tmp_path / "batched.compare.json"
    oracle_path.write_text(json.dumps(oracle))
    candidate_path.write_text(json.dumps(candidate))

    def _timeout_run(*_args: object, **_kwargs: object) -> object:
        raise subprocess.TimeoutExpired(cmd=["compare-ssa"], timeout=0.001)

    monkeypatch.setattr(dosunit_cli.subprocess, "run", _timeout_run)

    rc = dosunit_main(
        [
            "compare-ssa-batched",
            "--oracle-ssa",
            str(oracle_path),
            "--candidate-ssa",
            str(candidate_path),
            "--batch-size",
            "1",
            "--batch-timeout-ms",
            "1",
            "--out-dir",
            str(tmp_path / "batches"),
            "--out",
            str(aggregate_path),
        ]
    )

    assert rc == 1
    aggregate = json.loads(aggregate_path.read_text())
    assert aggregate["summary"]["rc_nonzero"] == [1]
    assert aggregate["batches"][0]["status"] == "timeout"
    assert aggregate["batches"][0]["reason"] == "batch_timeout"
    assert aggregate["batches"][0]["functions"] == ["demo.exe:slow"]


def test_dosunit_report_failures_for_ssa_generation_shows_lowering_coverage():
    document = {
        "schema": "dosunit.ssa.v1",
        "counters": {
            "functions_seen": 3,
            "functions_lowered": 2,
            "functions_refused": 1,
            "ssa_parts_lowered": 5,
            "ssa_parts_refused": 1,
            "refusals_by_reason": {"unsupported_ir": 1},
        },
        "refusals": [
            {
                "reason": "unsupported_ir",
                "detail": {"function_id": "demo.exe:bad", "message": "unsupported helper"},
            }
        ],
    }

    report = render_failure_report(document)

    assert "Functions seen: 3" in report
    assert "SSA parts refused: 1" in report
    assert '"unsupported_ir":1' in report
    assert "unsupported helper" in report


def test_dosunit_region_precompose_gate_refuses_memory_capped_huge_regions():
    group = []
    for index in range(300):
        block = _ssa_block_stub("demo.exe:huge", "huge", base=0x1000, delta=index * 2, index=index)
        block["assignments"] = [{"id": f"v{index}_{item}", "op": "const", "value": "0x0000", "width": 16} for item in range(4)]
        group.append(block)

    gate = straightline_ssa._region_precompose_memory_gate(group, group, max_rss_mb=4096)

    assert gate is not None
    assert gate["reason"] == "slice_too_large"
    assert gate["metric"] == "region_parts"
    assert gate["value"] == 300
    assert gate["limit"] == 256


def test_dosunit_cli_ssa_and_compare_ssa(tmp_path: Path):
    original_image = bytearray(0x240)
    candidate_image = bytearray(0x240)
    original_image[0x200:0x204] = b"\xb8\x34\x12\xc3"  # mov ax, 0x1234; ret
    candidate_image[0x200:0x204] = b"\xb8\x35\x12\xc3"  # mov ax, 0x1235; ret
    original = tmp_path / "original.exe"
    candidate = tmp_path / "candidate.exe"
    original.write_bytes(_mz_exe(bytes(original_image)))
    candidate.write_bytes(_mz_exe(bytes(candidate_image)))
    catalog = _edge_catalog("demo.exe:imm_leaf", "imm_leaf", offset=0x0200, size=4)
    functions_path = tmp_path / "functions.json"
    oracle_ssa_path = tmp_path / "oracle.ssa.json"
    candidate_ssa_path = tmp_path / "candidate.ssa.json"
    results_path = tmp_path / "ssa.results.json"
    report_path = tmp_path / "ssa.report.md"
    functions_path.write_text(json.dumps(catalog))

    assert (
        dosunit_main(
            [
                "ssa",
                "--exe",
                str(original),
                "--functions",
                str(functions_path),
                "--output-reg",
                "ax",
                "--out",
                str(oracle_ssa_path),
            ]
        )
        == 0
    )
    assert (
        dosunit_main(
            [
                "ssa",
                "--exe",
                str(candidate),
                "--functions",
                str(functions_path),
                "--output-reg",
                "ax",
                "--out",
                str(candidate_ssa_path),
            ]
        )
        == 0
    )
    rc = dosunit_main(
        [
            "compare-ssa",
            "--oracle-ssa",
            str(oracle_ssa_path),
            "--candidate-ssa",
            str(candidate_ssa_path),
            "--out",
            str(results_path),
        ]
    )

    assert rc == 1
    result = json.loads(results_path.read_text())
    assert result["schema"] == "dosunit.ssa_compare.v1"
    assert result["summary"]["failed"] == 1
    assert dosunit_main(["report-failures", "--results", str(results_path), "--out", str(report_path)]) == 0
    report = report_path.read_text()
    assert "Failed Or Refused SSA Functions" in report
    assert "Register: `ax`" in report
    assert "Counterexample" in report


def test_dosunit_cli_regions_and_compare_regions(tmp_path: Path):
    oracle_image = bytearray(0x240)
    candidate_image = bytearray(0x240)
    oracle_image[0x200:0x20B] = b"\x8b\x5c\x04\x01\xc3\x89\x55\xfe\x75\x01\xc3"
    candidate_image[0x200:0x20B] = b"\x8b\x5c\x04\x01\xc3\x89\x56\xfe\x75\x01\xc3"
    oracle_exe = tmp_path / "oracle.exe"
    candidate_exe = tmp_path / "candidate.exe"
    oracle_exe.write_bytes(_mz_exe(bytes(oracle_image)))
    candidate_exe.write_bytes(_mz_exe(bytes(candidate_image)))
    catalog = _edge_catalog("demo.exe:region", "region", offset=0x0200, size=0x0B)
    functions_path = tmp_path / "functions.json"
    oracle_regions_path = tmp_path / "oracle.regions.json"
    candidate_regions_path = tmp_path / "candidate.regions.json"
    comparison_path = tmp_path / "region.compare.json"
    report_path = tmp_path / "region.report.md"
    functions_path.write_text(json.dumps(catalog))

    assert (
        dosunit_main(
            ["regions", "--exe", str(oracle_exe), "--functions", str(functions_path), "--out", str(oracle_regions_path)]
        )
        == 0
    )
    assert (
        dosunit_main(
            [
                "regions",
                "--exe",
                str(candidate_exe),
                "--functions",
                str(functions_path),
                "--out",
                str(candidate_regions_path),
            ]
        )
        == 0
    )
    rc = dosunit_main(
        [
            "compare-regions",
            "--oracle-regions",
            str(oracle_regions_path),
            "--candidate-regions",
            str(candidate_regions_path),
            "--out",
            str(comparison_path),
        ]
    )

    assert rc == 1
    comparison = json.loads(comparison_path.read_text())
    assert comparison["summary"]["failed"] == 1
    assert dosunit_main(["report-failures", "--results", str(comparison_path), "--out", str(report_path)]) == 0
    report = report_path.read_text()
    assert "# DOS Unit Failure Report" in report
    assert "instruction_operands_changed" in report
    assert "Oracle region entry" in report
    assert "Candidate instruction" in report
    assert "candidate" in report


def _edge_catalog(function_id: str, name: str, *, offset: int, size: int) -> dict[str, object]:
    return {
        "schema": "dosunit.functions.v1",
        "id": "functions:test",
        "module": "demo.exe",
        "program_kind": "mz_exe",
        "functions": [_edge_function(function_id, name, offset=offset, size=size)],
        "diagnostics": [],
    }


def _edge_function(function_id: str, name: str, *, offset: int, size: int) -> dict[str, object]:
    return {
        "id": function_id,
        "names": [name],
        "entry": {
            "kind": "module_relative",
            "segment": "seg000",
            "segment_para": "0x0000",
            "offset": f"0x{offset:04x}",
        },
        "return_kind": "near",
        "sources": ["fixture"],
        "confidence": "medium",
        "size": size,
        "safe_traps": [],
    }


def _ssa_stub(
    function_id: str,
    name: str,
    *,
    ip: str,
    linear: str,
    jumpkind: str = "Ijk_Ret",
    call_raw: str | None = None,
) -> dict[str, object]:
    instructions = [{"address": {"ip": ip, "linear": linear}, "disassembly": "ret", "size": 1}]
    source: dict[str, object] = {
        "jumpkind": jumpkind,
        "instruction_count": len(instructions),
        "instructions": instructions,
    }
    if call_raw is not None:
        source["transfer"] = {
            "kind": "direct_call",
            "jumpkind": "Ijk_Call",
            "target": {"raw": call_raw, "low16": f"0x{int(call_raw, 0) & 0xFFFF:04x}"},
            "fallthrough": {"linear": linear, "low16": f"0x{int(linear, 0) & 0xFFFF:04x}"},
        }
    return {
        "id": f"ssa-function:{function_id}",
        "function": {"id": function_id, "name": name},
        "entry": {"cs": "0x0000", "ip": ip, "linear": linear},
        "source": source,
        "inputs": [],
        "outputs": {"ax": {"op": "const", "value": "0x0000", "width": 16}},
        "assignments": [],
    }


def _ssa_call_boundary_function(
    function_id: str,
    name: str,
    *,
    ax: str = "0x0000",
    dx: str = "0x0000",
    sp: str = "0xfffe",
    memory: str | None = None,
) -> dict[str, object]:
    outputs: dict[str, object] = {
        "ax": {"op": "const", "value": ax, "width": 16},
        "dx": {"op": "const", "value": dx, "width": 16},
        "sp": {"op": "const", "value": sp, "width": 16},
    }
    if memory is not None:
        outputs["memory"] = {"op": "const", "value": memory, "width": 16}
    return {
        "id": f"ssa-function:{function_id}",
        "function": {"id": function_id, "name": name},
        "entry": {"cs": "0x0000", "ip": "0x0200", "linear": "0x1200"},
        "source": {
            "jumpkind": "Ijk_Call",
            "instruction_count": 1,
            "instructions": [{"address": {"ip": "0x0200", "linear": "0x1200"}, "disassembly": "call 0x1500", "size": 3}],
            "transfer": {
                "kind": "direct_call",
                "jumpkind": "Ijk_Call",
                "target": {"raw": "0x1500", "low16": "0x1500"},
                "fallthrough": {"linear": "0x1203", "low16": "0x1203"},
            },
        },
        "inputs": [],
        "outputs": outputs,
        "assignments": [],
    }


def _ssa_call_boundary_stack_store_function(
    function_id: str, name: str, *, frame_delta: str, value: str
) -> dict[str, object]:
    function = _ssa_call_boundary_function(function_id, name)
    function["inputs"] = [{"name": "sp", "width": 16}, {"name": "ss", "width": 16}, {"kind": "memory", "name": "mem"}]
    function["assignments"] = [
        {"id": "v0", "op": "zext", "width": 32, "args": [{"op": "input", "name": "ss", "width": 16}]},
        {"id": "v1", "op": "shl", "width": 32, "args": [{"ref": "v0"}, {"op": "const", "value": "0x04", "width": 8}]},
        {
            "id": "v2",
            "op": "add",
            "width": 16,
            "args": [{"op": "input", "name": "sp", "width": 16}, {"op": "const", "value": frame_delta, "width": 16}],
        },
        {"id": "v3", "op": "zext", "width": 32, "args": [{"ref": "v2"}]},
        {"id": "v4", "op": "add", "width": 32, "args": [{"ref": "v1"}, {"ref": "v3"}]},
        {
            "id": "v5",
            "op": "storele",
            "width": 0,
            "args": [
                {"op": "mem_input", "name": "mem", "addr_width": 32, "value_width": 8},
                {"ref": "v4"},
                {"op": "const", "value": value, "width": 16},
            ],
        },
    ]
    function["outputs"]["memory"] = {"ref": "v5"}
    return function


def _ssa_block_stub(
    function_id: str,
    name: str,
    *,
    base: int,
    delta: int,
    index: int,
    successors: list[int] | None = None,
) -> dict[str, object]:
    linear = base + delta
    source: dict[str, object] = {
        "jumpkind": "Ijk_Boring" if successors else "Ijk_Ret",
        "instruction_count": 1,
        "instructions": [
            {
                "address": {"ip": f"0x{linear & 0xFFFF:04x}", "linear": f"0x{linear:04x}"},
                "disassembly": "jmp" if successors else "ret",
                "size": 1,
            }
        ],
    }
    if successors is not None:
        source["transfer"] = {
            "kind": "direct_successors",
            "jumpkind": "Ijk_Boring",
            "successors": [
                {
                    "linear": f"0x{base + successor:04x}",
                    "low16": f"0x{(base + successor) & 0xFFFF:04x}",
                }
                for successor in successors
            ],
        }
    return {
        "id": f"ssa-function:{function_id}:part{index}",
        "function": {"id": function_id, "name": name},
        "part": {"kind": "block", "index": index, "entry_delta": f"0x{delta:04x}"},
        "function_entry": {"cs": "0x0000", "ip": f"0x{base & 0xFFFF:04x}", "linear": f"0x{base:04x}"},
        "entry": {"cs": "0x0000", "ip": f"0x{linear & 0xFFFF:04x}", "linear": f"0x{linear:04x}"},
        "source": source,
        "inputs": [],
        "outputs": {"ax": {"op": "const", "value": "0x0000", "width": 16}},
        "assignments": [],
    }


def _call_region_blocks(*, base: int, caller_id: str, target: int, callee_id: str) -> list[dict[str, object]]:
    caller_name = caller_id.split(":", 1)[-1]
    callee_name = callee_id.split(":", 1)[-1]
    entry = _ssa_block_stub(caller_id, caller_name, base=base, delta=0x0000, index=0, successors=[0x0004])
    entry["outputs"]["ip"] = {"op": "const", "value": f"0x{(base + 0x0004) & 0xFFFF:04x}", "width": 16}
    call_linear = base + 0x0004
    fallthrough = base + 0x0008
    call = {
        "id": f"ssa-function:{caller_id}:part1",
        "function": {"id": caller_id, "name": caller_name},
        "part": {"kind": "block", "index": 1, "entry_delta": "0x0004"},
        "function_entry": {"cs": "0x0000", "ip": f"0x{base & 0xFFFF:04x}", "linear": f"0x{base:04x}"},
        "entry": {"cs": "0x0000", "ip": f"0x{call_linear & 0xFFFF:04x}", "linear": f"0x{call_linear:04x}"},
        "source": {
            "jumpkind": "Ijk_Call",
            "instruction_count": 1,
            "instructions": [
                {
                    "address": {"ip": f"0x{call_linear & 0xFFFF:04x}", "linear": f"0x{call_linear:04x}"},
                    "disassembly": f"call 0x{target:04x}",
                    "mnemonic": "call",
                    "op_str": f"0x{target:04x}",
                    "size": 3,
                }
            ],
            "transfer": {
                "kind": "direct_call",
                "jumpkind": "Ijk_Call",
                "target": {"raw": f"0x{target:04x}", "low16": f"0x{target & 0xFFFF:04x}", "linear": f"0x{target:04x}"},
                "fallthrough": {"linear": f"0x{fallthrough:04x}", "low16": f"0x{fallthrough & 0xFFFF:04x}"},
            },
            "machine_code_size": 3,
            "machine_code_sha256": f"{target & 0xF:x}" * 64,
        },
        "inputs": [{"name": "memory", "kind": "memory"}, {"name": "sp", "width": 16}],
        "outputs": {
            "memory": {"ref": "v0"},
            "sp": {"op": "input", "name": "sp", "width": 16},
        },
        "assignments": [
            {
                "id": "v0",
                "op": "storele",
                "width": 8,
                "args": [
                    {"op": "mem_input", "name": "memory", "addr_width": 32, "value_width": 8},
                    {"op": "input", "name": "sp", "width": 16},
                    {"op": "const", "value": f"0x{fallthrough & 0xFFFF:04x}", "width": 16},
                ],
            }
        ],
    }
    callee = _ssa_stub(callee_id, callee_name, ip=f"0x{target & 0xFFFF:04x}", linear=f"0x{target:04x}")
    return [entry, call, callee]


def _far_call_region_blocks(*, base: int, caller_id: str) -> list[dict[str, object]]:
    caller_name = caller_id.split(":", 1)[-1]
    entry = _ssa_block_stub(caller_id, caller_name, base=base, delta=0x0000, index=0, successors=[0x0004])
    entry["outputs"]["ip"] = {"op": "const", "value": f"0x{(base + 0x0004) & 0xFFFF:04x}", "width": 16}
    call_linear = base + 0x0004
    fallthrough = call_linear + 5
    return_ip = (call_linear + 5) & 0xFFFF
    call = {
        "id": f"ssa-function:{caller_id}:part1",
        "function": {"id": caller_id, "name": caller_name},
        "part": {"kind": "block", "index": 1, "entry_delta": "0x0004"},
        "function_entry": {"cs": "0x0000", "ip": f"0x{base & 0xFFFF:04x}", "linear": f"0x{base:04x}"},
        "entry": {"cs": "0x0000", "ip": f"0x{call_linear & 0xFFFF:04x}", "linear": f"0x{call_linear:04x}"},
        "source": {
            "jumpkind": "Ijk_Call",
            "instruction_count": 1,
            "instructions": [
                {
                    "address": {"ip": f"0x{call_linear & 0xFFFF:04x}", "linear": f"0x{call_linear:04x}"},
                    "disassembly": "lcall 0x238b, 0xf90",
                    "mnemonic": "lcall",
                    "op_str": "0x238b, 0xf90",
                    "size": 5,
                }
            ],
            "transfer": {
                "kind": "direct_call",
                "jumpkind": "Ijk_Call",
                "fallthrough": {"linear": f"0x{fallthrough:04x}", "low16": f"0x{fallthrough & 0xFFFF:04x}"},
            },
            "machine_code_size": 5,
            "machine_code_sha256": f"{base & 0xF:x}" * 64,
        },
        "inputs": [{"name": "memory", "kind": "memory"}, {"name": "sp", "width": 16}],
        "outputs": {"memory": {"ref": "v1"}, "sp": {"op": "input", "name": "sp", "width": 16}},
        "assignments": [
            {
                "id": "v0",
                "op": "storele",
                "width": 0,
                "args": [
                    {"op": "mem_input", "name": "memory", "addr_width": 32, "value_width": 8},
                    {"op": "input", "name": "sp", "width": 16},
                    {"op": "const", "value": f"0x{(return_ip >> 8) & 0xFF:02x}", "width": 8},
                ],
            },
            {
                "id": "v1",
                "op": "storele",
                "width": 0,
                "args": [
                    {"ref": "v0"},
                    {
                        "op": "add",
                        "width": 16,
                        "args": [
                            {"op": "input", "name": "sp", "width": 16},
                            {"op": "const", "value": "0x0001", "width": 16},
                        ],
                    },
                    {"op": "const", "value": f"0x{return_ip & 0xFF:02x}", "width": 8},
                ],
            },
        ],
    }
    return [entry, call]


def _ssa_doc(function: dict[str, object]) -> dict[str, object]:
    return {"schema": "dosunit.ssa.v1", "exe": "demo.exe", "functions": [function]}


def _watcom_register_abi_doc(exe: str, *, function_id: str, name: str, style: str) -> dict[str, object]:
    ax = {"op": "input", "name": "ax", "width": 16}
    dx = {"op": "input", "name": "dx", "width": 16}
    bp = {"op": "input", "name": "bp", "width": 16}
    sp = {"op": "input", "name": "sp", "width": 16}
    ds = {"op": "input", "name": "ds", "width": 16}
    doubled_dx = {"op": "add", "width": 16, "args": [dx, dx]}
    if style == "asm":
        ax_out = {"op": "add", "width": 16, "args": [ax, doubled_dx]}
        dx_out = dx
        clobbers = {
            "bx": {"op": "const", "value": "0x1111", "width": 16},
            "cx": {"op": "add", "width": 16, "args": [ax, {"op": "const", "value": "0x0007", "width": 16}]},
            "si": {"op": "const", "value": "0x2222", "width": 16},
            "di": {"op": "const", "value": "0x3333", "width": 16},
        }
    elif style == "watcom_c":
        ax_out = {"op": "add", "width": 16, "args": [{"op": "add", "width": 16, "args": [dx, ax]}, dx]}
        dx_out = {"op": "add", "width": 16, "args": [dx, {"op": "const", "value": "0x0000", "width": 16}]}
        clobbers = {
            "bx": {"op": "const", "value": "0xabcd", "width": 16},
            "cx": {"op": "const", "value": "0x4444", "width": 16},
            "si": {"op": "add", "width": 16, "args": [dx, {"op": "const", "value": "0x0055", "width": 16}]},
            "di": {"op": "const", "value": "0x7777", "width": 16},
        }
    elif style == "watcom_c_bug":
        ax_out = {"op": "add", "width": 16, "args": [{"op": "add", "width": 16, "args": [dx, ax]}, dx]}
        dx_out = {"op": "add", "width": 16, "args": [dx, {"op": "const", "value": "0x0001", "width": 16}]}
        clobbers = {
            "bx": {"op": "const", "value": "0xabcd", "width": 16},
            "cx": {"op": "const", "value": "0x4444", "width": 16},
            "si": {"op": "add", "width": 16, "args": [dx, {"op": "const", "value": "0x0055", "width": 16}]},
            "di": {"op": "const", "value": "0x7777", "width": 16},
        }
    else:
        raise AssertionError(f"unknown synthetic Watcom ABI style: {style}")
    function = {
        "id": f"ssa-function:{function_id}:entry",
        "function": {"id": function_id, "name": name},
        "function_entry": {"cs": "0x0000", "ip": "0x0200", "linear": "0x1200"},
        "entry": {"cs": "0x0000", "ip": "0x0200", "linear": "0x1200"},
        "part": {"kind": "whole_function", "index": 0, "entry_delta": "0x0000"},
        "source": {
            "jumpkind": "Ijk_Ret",
            "instruction_count": 3,
            "instructions": [
                {"address": {"ip": "0x0200", "linear": "0x1200"}, "disassembly": "synthetic register abi body"},
                {"address": {"ip": "0x0201", "linear": "0x1201"}, "disassembly": "ret"},
            ],
        },
        "inputs": [
            {"name": "ax", "width": 16},
            {"name": "dx", "width": 16},
            {"name": "bp", "width": 16},
            {"name": "sp", "width": 16},
            {"name": "ds", "width": 16},
        ],
        "assignments": [],
        "outputs": {
            "ax": ax_out,
            "dx": dx_out,
            "bp": bp,
            "sp": sp,
            "ds": ds,
            **clobbers,
        },
    }
    return {"schema": "dosunit.ssa.v1", "exe": exe, "functions": [function], "refusals": []}


def _watcom_register_abi_manifest() -> dict[str, object]:
    return {
        "schema": "test.watcom_register_abi.v1",
        "functions": [
            {
                "name": "adlib_mix",
                "oracle_id": "demo.exe:asm_adlib_mix",
                "oracle_name": "asm_adlib_mix",
                "kind": "near",
                "calling_convention": "watcom_register_ax_dx",
                "inputs": [
                    {"location": "ax", "name": "channel", "width": 16},
                    {"location": "dx", "name": "frequency", "width": 16},
                ],
                "returns": [
                    {"location": "ax", "name": "status", "width": 16},
                    {"location": "dx", "name": "latched_frequency", "width": 16},
                ],
                "preserved": ["bp", "ds"],
                "clobbers": ["bx", "cx", "si", "di", "flags"],
            }
        ],
    }


def _watcom_register_abi_mapping() -> dict[str, object]:
    return {
        "schema": "dosunit.mapping.v1",
        "id": "mapping:synthetic-watcom-register",
        "functions": [
            {
                "oracle_id": "demo.exe:asm_adlib_mix",
                "oracle_name": "asm_adlib_mix",
                "candidate_id": "demo.exe:c_adlib_mix",
                "candidate_name": "c_adlib_mix",
                "candidate_entry": {"cs": "0x0000", "ip": "0x0200"},
            }
        ],
    }


def _abi_const(value: int, width: int = 16) -> dict[str, object]:
    return {"op": "const", "value": f"0x{value & ((1 << width) - 1):0{max(1, width // 4)}x}", "width": width}


def _abi_inp(name: str, width: int = 16) -> dict[str, object]:
    return {"op": "input", "name": name, "width": width}


def _abi_add(lhs: dict[str, object], rhs: dict[str, object], width: int = 16) -> dict[str, object]:
    return {"op": "add", "width": width, "args": [lhs, rhs]}


def _abi_sub(lhs: dict[str, object], rhs: dict[str, object], width: int = 16) -> dict[str, object]:
    return {"op": "sub", "width": width, "args": [lhs, rhs]}


def _abi_ne(lhs: dict[str, object], rhs: dict[str, object]) -> dict[str, object]:
    return {"op": "ne", "width": 1, "args": [lhs, rhs]}


def _abi_ite(cond: dict[str, object], yes: int, no: int) -> dict[str, object]:
    return {"op": "ite", "width": 16, "args": [cond, _abi_const(yes), _abi_const(no)]}


def _abi_stack_addr(offset: int) -> dict[str, object]:
    return {
        "op": "add",
        "width": 32,
        "args": [
            {"op": "shl", "width": 32, "args": [{"op": "zext", "width": 32, "args": [_abi_inp("ss")]}, _abi_const(4, 8)]},
            {"op": "zext", "width": 32, "args": [_abi_add(_abi_inp("sp"), _abi_const(offset))]},
        ],
    }


def _abi_data_addr(offset: int) -> dict[str, object]:
    return {
        "op": "add",
        "width": 32,
        "args": [
            {"op": "shl", "width": 32, "args": [{"op": "zext", "width": 32, "args": [_abi_inp("ds")]}, _abi_const(4, 8)]},
            _abi_const(offset, 32),
        ],
    }


def _stack_arg_loop_abi_doc(exe: str, *, function_id: str, name: str, style: str) -> dict[str, object]:
    base = 0x2200 if style == "asm_loop" else 0x2300

    def block(
        *,
        index: int,
        delta: int,
        jumpkind: str,
        outputs: dict[str, object],
        assignments: list[dict[str, object]] | None = None,
        inputs: list[dict[str, object]] | None = None,
        successors: list[int] | None = None,
        text: str = "synthetic",
    ) -> dict[str, object]:
        linear = base + delta
        source: dict[str, object] = {
            "jumpkind": jumpkind,
            "instruction_count": 1,
            "instructions": [
                {
                    "address": {"ip": f"0x{linear & 0xFFFF:04x}", "linear": f"0x{linear:04x}"},
                    "disassembly": text,
                    "size": 1,
                }
            ],
        }
        if successors is not None:
            source["transfer"] = {
                "kind": "direct_successors",
                "jumpkind": jumpkind,
                "successors": [
                    {"linear": f"0x{base + target:04x}", "low16": f"0x{(base + target) & 0xFFFF:04x}"}
                    for target in successors
                ],
            }
        return {
            "id": f"ssa-function:{function_id}:part{index}",
            "function": {"id": function_id, "name": name},
            "part": {"kind": "block", "index": index, "entry_delta": f"0x{delta:04x}"},
            "function_entry": {"cs": "0x0000", "ip": f"0x{base & 0xFFFF:04x}", "linear": f"0x{base:04x}"},
            "entry": {"cs": "0x0000", "ip": f"0x{linear & 0xFFFF:04x}", "linear": f"0x{linear:04x}"},
            "source": source,
            "inputs": inputs or [],
            "assignments": assignments or [],
            "outputs": outputs,
        }

    entry_assignments = [
        {"id": "boost", "op": "loadle", "width": 16, "args": [_abi_inp("memory", 0), _abi_stack_addr(2)]},
        {"id": "has_cx", "op": "ne", "width": 1, "args": [_abi_inp("cx"), _abi_const(0)]},
        {"id": "entry_ip", "op": "ite", "width": 16, "args": [{"ref": "has_cx"}, _abi_const(base + 0x0004), _abi_const(base + 0x0008)]},
    ]
    entry = block(
        index=0,
        delta=0x0000,
        jumpkind="Ijk_Boring",
        inputs=[
            {"name": "memory", "kind": "memory"},
            {"name": "cx", "width": 16},
            {"name": "ss", "width": 16},
            {"name": "sp", "width": 16},
        ],
        assignments=entry_assignments,
        outputs={
            "ax": {"ref": "boost"},
            "bx": _abi_const(2),
            "ip": {"ref": "entry_ip"},
            "si": _abi_const(0x1111),
            "di": _abi_const(0x2222),
        },
        successors=[0x0004, 0x0008],
        text="load stack arg; branch on cx",
    )
    if style == "asm_loop":
        loop_assignments = [
            {"id": "next_ax", "op": "add", "width": 16, "args": [_abi_inp("ax"), _abi_const(1)]},
            {"id": "next_bx", "op": "sub", "width": 16, "args": [_abi_inp("bx"), _abi_const(1)]},
            {"id": "keep_looping", "op": "ne", "width": 1, "args": [{"ref": "next_bx"}, _abi_const(0)]},
            {"id": "loop_ip", "op": "ite", "width": 16, "args": [{"ref": "keep_looping"}, _abi_const(base + 0x0004), _abi_const(base + 0x0008)]},
        ]
        middle = block(
            index=1,
            delta=0x0004,
            jumpkind="Ijk_Boring",
            inputs=[{"name": "ax", "width": 16}, {"name": "bx", "width": 16}],
            assignments=loop_assignments,
            outputs={"ax": {"ref": "next_ax"}, "bx": {"ref": "next_bx"}, "ip": {"ref": "loop_ip"}, "si": _abi_const(0x3333)},
            successors=[0x0004, 0x0008],
            text="asm counted loop",
        )
    elif style == "watcom_c_branch":
        middle = block(
            index=1,
            delta=0x0004,
            jumpkind="Ijk_Boring",
            inputs=[{"name": "ax", "width": 16}],
            outputs={"ax": _abi_add(_abi_inp("ax"), _abi_const(2)), "ip": _abi_const(base + 0x0008), "di": _abi_const(0x4444)},
            successors=[0x0008],
            text="c branch body adds two",
        )
    else:
        raise AssertionError(f"unknown synthetic stack ABI style: {style}")
    ret_assignments = [
        {
            "id": "stored",
            "op": "storele",
            "width": 0,
            "args": [_abi_inp("memory", 0), _abi_data_addr(0x0450), _abi_inp("ax")],
        }
    ]
    ret = block(
        index=2,
        delta=0x0008,
        jumpkind="Ijk_Ret",
        inputs=[
            {"name": "memory", "kind": "memory"},
            {"name": "ax", "width": 16},
            {"name": "ds", "width": 16},
        ],
        assignments=ret_assignments,
        outputs={"ax": _abi_inp("ax"), "memory": {"ref": "stored"}},
        text="store abi-visible memory; ret",
    )
    return {"schema": "dosunit.ssa.v1", "exe": exe, "functions": [entry, middle, ret], "refusals": []}


def _stack_arg_loop_abi_manifest() -> dict[str, object]:
    return {
        "schema": "test.stack_arg_loop_abi.v1",
        "functions": [
            {
                "name": "apply_boost",
                "oracle_id": "demo.exe:asm_apply_boost",
                "oracle_name": "asm_apply_boost",
                "kind": "near",
                "calling_convention": "watcom_register_cx_stack",
                "inputs": [{"location": "cx", "name": "enabled", "width": 16}],
                "stack_args": [{"name": "boost", "width": 16, "entry_sp_offset": "0x0002"}],
                "returns": [{"location": "ax", "name": "result", "width": 16}],
                "preserved": ["bp", "ds"],
                "clobbers": ["bx", "si", "di", "flags"],
                "effects": [
                    {"space": "DS", "segment": "ds", "offset": "0x0450", "size": 2, "name": "last_boosted_value"}
                ],
            }
        ],
    }


def _stack_arg_loop_abi_mapping() -> dict[str, object]:
    return {
        "schema": "dosunit.mapping.v1",
        "id": "mapping:synthetic-stack-loop",
        "functions": [
            {
                "oracle_id": "demo.exe:asm_apply_boost",
                "oracle_name": "asm_apply_boost",
                "candidate_id": "demo.exe:c_apply_boost",
                "candidate_name": "c_apply_boost",
                "candidate_entry": {"cs": "0x0000", "ip": "0x2300"},
            }
        ],
    }


def _manual_loop_ssa_doc(exe: str, *, constant_count: bool) -> dict[str, object]:
    function_id = "demo.exe:manual_loop"
    name = "manual_loop"
    base = 0x1000

    def block(
        *,
        index: int,
        delta: int,
        jumpkind: str,
        outputs: dict[str, object],
        assignments: list[dict[str, object]] | None = None,
        inputs: list[dict[str, object]] | None = None,
        successors: list[int] | None = None,
    ) -> dict[str, object]:
        linear = base + delta
        source: dict[str, object] = {
            "jumpkind": jumpkind,
            "instruction_count": 1,
            "instructions": [
                {
                    "address": {"ip": f"0x{linear & 0xFFFF:04x}", "linear": f"0x{linear:04x}"},
                    "disassembly": "manual",
                    "size": 1,
                }
            ],
        }
        if successors is not None:
            source["transfer"] = {
                "kind": "direct_successors",
                "jumpkind": jumpkind,
                "successors": [
                    {
                        "linear": f"0x{base + successor:04x}",
                        "low16": f"0x{(base + successor) & 0xFFFF:04x}",
                    }
                    for successor in successors
                ],
            }
        return {
            "id": f"ssa-function:{function_id}:part{index}",
            "function": {"id": function_id, "name": name},
            "part": {"kind": "block", "index": index, "entry_delta": f"0x{delta:04x}"},
            "function_entry": {"cs": "0x0000", "ip": f"0x{base & 0xFFFF:04x}", "linear": f"0x{base:04x}"},
            "entry": {"cs": "0x0000", "ip": f"0x{linear & 0xFFFF:04x}", "linear": f"0x{linear:04x}"},
            "source": source,
            "inputs": inputs or [],
            "outputs": outputs,
            "assignments": assignments or [],
        }

    entry_outputs: dict[str, object] = {
        "ax": {"op": "const", "value": "0x0000", "width": 16},
        "ip": {"op": "const", "value": "0x1004", "width": 16},
    }
    if constant_count:
        entry_outputs["cx"] = {"op": "const", "value": "0x0002", "width": 16}

    loop_assignments: list[dict[str, object]] = [
        {
            "id": "v0",
            "op": "sub",
            "width": 16,
            "args": [
                {"op": "input", "name": "cx", "width": 16},
                {"op": "const", "value": "0x0001", "width": 16},
            ],
        },
        {
            "id": "v1",
            "op": "add",
            "width": 16,
            "args": [
                {"op": "input", "name": "ax", "width": 16},
                {"op": "const", "value": "0x0001", "width": 16},
            ],
        },
        {
            "id": "v2",
            "op": "ne",
            "width": 1,
            "args": [
                {"ref": "v0"},
                {"op": "const", "value": "0x0000", "width": 16},
            ],
        },
        {
            "id": "v3",
            "op": "ite",
            "width": 16,
            "args": [
                {"ref": "v2"},
                {"op": "const", "value": "0x1004", "width": 16},
                {"op": "const", "value": "0x1008", "width": 16},
            ],
        },
    ]

    functions = [
        block(index=0, delta=0x0000, jumpkind="Ijk_Boring", outputs=entry_outputs, successors=[0x0004]),
        block(
            index=1,
            delta=0x0004,
            jumpkind="Ijk_Boring",
            inputs=[{"name": "ax", "width": 16}, {"name": "cx", "width": 16}],
            outputs={"ax": {"ref": "v1"}, "cx": {"ref": "v0"}, "ip": {"ref": "v3"}},
            assignments=loop_assignments,
            successors=[0x0004, 0x0008],
        ),
        block(
            index=2,
            delta=0x0008,
            jumpkind="Ijk_Ret",
            inputs=[{"name": "ax", "width": 16}, {"name": "cx", "width": 16}],
            outputs={
                "ax": {"op": "input", "name": "ax", "width": 16},
                "cx": {"op": "input", "name": "cx", "width": 16},
            },
        ),
    ]
    return {"schema": "dosunit.ssa.v1", "exe": exe, "functions": functions}


def _repeated_helper_call_abi_manifest() -> dict[str, object]:
    return {
        "schema": "test.abi.v1",
        "functions": [
            {
                "name": "wrapper",
                "kind": "near",
                "ssa_call_policy": "summary",
                "call_summaries": [
                    {
                        "id": "first_helper",
                        "target_low16": "0x1210",
                        "target_ordinal": 0,
                        "kind": "near",
                        "stack_args": [{"name": "value", "width": 16, "entry_sp_offset": "0x0002"}],
                        "returns": [],
                        "preserved": ["ss"],
                        "clobbers": ["ax", "flags"],
                    },
                    {
                        "id": "second_helper",
                        "target_low16": "0x1210",
                        "target_ordinal": 1,
                        "kind": "near",
                        "stack_args": [{"name": "value", "width": 16, "entry_sp_offset": "0x0002"}],
                        "returns": [],
                        "preserved": ["ss"],
                        "clobbers": ["ax", "flags"],
                    },
                ],
            }
        ],
    }


def _manual_ssa_function(
    name: str,
    instruction_texts: list[str],
    *,
    outputs: dict[str, object],
    inputs: list[dict[str, object]] | None = None,
    assignments: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    instructions: list[dict[str, object]] = []
    for index, text in enumerate(instruction_texts):
        parts = text.split(None, 1)
        mnemonic = parts[0].lower()
        op_str = parts[1].lower() if len(parts) == 2 else ""
        instructions.append(
            {
                "address": {"ip": f"0x{0x0200 + index:04x}", "linear": f"0x{0x1200 + index:04x}"},
                "size": 1,
                "mnemonic": mnemonic,
                "op_str": op_str,
                "disassembly": text.lower(),
            }
        )
    function_id = f"demo.exe:{name}"
    return {
        "id": f"ssa-function:{name}",
        "function": {"id": function_id, "name": name},
        "entry": {"cs": "0x0000", "ip": "0x0200", "linear": "0x1200"},
        "source": {"jumpkind": "Ijk_Ret", "instruction_count": len(instructions), "instructions": instructions},
        "inputs": inputs or [],
        "outputs": outputs,
        "assignments": assignments or [],
    }


def test_candidate_mapping_resolves_by_function_name():
    vector = _leaf_vector()
    mapping = {
        "schema": "dosunit.mapping.v1",
        "oracle_module": "demo.exe",
        "candidate_module": "candidate.exe",
        "functions": [
            {
                "oracle_name": "leaf",
                "candidate_name": "leaf_rebuilt",
                "candidate_entry": {"cs": "0x0001", "ip": "0x0220", "kind": "near"},
            }
        ],
    }

    mapped = apply_candidate_mapping(vector, mapping_document=mapping)

    assert mapped["module"] == "candidate.exe"
    assert mapped["function"]["name"] == "leaf_rebuilt"
    assert mapped["function"]["entry"] == {"cs": "0x0001", "ip": "0x0220", "kind": "near"}


def test_candidate_mapping_missing_is_typed_refusal():
    vector = _leaf_vector()

    with pytest.raises(MappingResolutionError) as exc:
        apply_candidate_mapping(vector, mapping_document={"schema": "dosunit.mapping.v1", "functions": []})

    assert exc.value.reason == "mapping_missing"


def test_make_mapping_document_matches_catalogs_by_name():
    oracle = {
        "schema": "dosunit.functions.v1",
        "module": "orig.exe",
        "functions": [
            {
                "id": "orig.exe:leaf",
                "names": ["leaf"],
                "entry": {"segment_para": "0x0000", "offset": "0x0200"},
                "return_kind": "near",
            }
        ],
    }
    candidate = {
        "schema": "dosunit.functions.v1",
        "module": "rebuilt.exe",
        "functions": [
            {
                "id": "rebuilt.exe:leaf",
                "names": ["leaf"],
                "entry": {"segment_para": "0x0001", "offset": "0x0300"},
                "return_kind": "near",
            }
        ],
    }

    mapping = make_mapping_document(oracle_catalog=oracle, candidate_catalog=candidate)

    assert mapping["summary"]["mapped"] == 1
    assert mapping["functions"][0]["oracle_id"] == "orig.exe:leaf"
    assert mapping["functions"][0]["candidate_entry"]["cs"] == "0x0001"
    assert mapping["functions"][0]["candidate_entry"]["ip"] == "0x0300"


def test_select_vectors_filters_by_function_name_and_limit():
    vectors = {
        "schema": "dosunit.vectors.v1",
        "vectors": [
            _leaf_vector(),
            {
                **_leaf_vector(),
                "function": {"name": "other", "entry": {"cs": "0x0000", "ip": "0x0210", "kind": "near"}},
            },
        ],
    }

    selected = select_vectors(vectors, names=["other"], limit=1)

    assert len(selected["vectors"]) == 1
    assert selected["vectors"][0]["function"]["name"] == "other"


def test_dosunit_record_oracle_and_compare_fixture_passes_and_fails():
    observed = {
        "status": "trapped",
        "regs": {"ax": "0x0001"},
        "sregs": {},
        "flags": {"value": "0x0202", "mask": "0xffff"},
        "memory": [],
        "return": {"kind": "near"},
        "calls": [],
    }
    vector = {
        "schema": "dosunit.vector.v1",
        "module": "demo.exe",
        "function": {"name": "leaf", "entry": {"cs": "auto", "ip": "0x0100", "kind": "near"}},
        "source": {"kind": "manual", "origin": "manual_fixture", "assumptions": []},
        "pre": {"regs": {"sp": "0xff00", "flags": "0x0202"}, "sregs": {"cs": "auto"}, "memory": []},
        "observe": {"regs": ["ax"], "sregs": [], "flags_mask": "0xffff", "memory": [], "calls": True, "return": True},
        "expected": None,
        "backend_fixture": {
            "oracle": observed,
            "candidate": {**observed, "regs": {"ax": "0x0002"}},
        },
    }

    recorded = record_oracle({"schema": "dosunit.vectors.v1", "vectors": [vector]}, backend="fixture")
    assert recorded["vectors"][0]["expected"]["regs"]["ax"] == "0x0001"

    failed = compare_vectors(recorded, backend="fixture")
    assert failed["results"][0]["status"] == "failed"
    assert failed["results"][0]["verdict"]["changed_fields"] == ["regs"]

    ignored = compare_vectors(recorded, backend="fixture", ignore_fields={"regs"})
    assert ignored["results"][0]["status"] == "passed"
    assert ignored["ignore_fields"] == ["regs"]

    recorded["vectors"][0]["backend_fixture"]["candidate"] = observed
    passed = compare_vectors(recorded, backend="fixture")
    assert passed["results"][0]["status"] == "passed"


def test_dosunit_cli_discover_writes_catalog(tmp_path: Path):
    map_path = _write(
        tmp_path / "demo.map",
        "\n".join(
            [
                "seg000 CODE 0000",
                "leaf: seg000 NEAR 0010-0015 R0010-0015 complete",
            ]
        ),
    )
    out_path = tmp_path / "catalog.json"

    rc = dosunit_main(["discover", "--map", str(map_path), "--module", "demo.exe", "--out", str(out_path)])

    assert rc == 0
    catalog = json.loads(out_path.read_text())
    assert catalog["functions"][0]["id"] == "demo.exe:leaf"


def test_dosunit_discover_ida_listing_preserves_function_chunks(tmp_path: Path):
    ida_path = _write(
        tmp_path / "demo.lst",
        "\n".join(
            [
                "seg000:0000 seg000 segment para public 'CODE' use16",
                "seg000:F2F4 _open proc near",
                "seg000:F2F4 ; FUNCTION CHUNK AT seg000:EE35 SIZE 0000000D BYTES",
                "seg000:F485 _open endp",
            ]
        ),
    )

    catalog = discover_functions(ida_listing_path=ida_path, module="demo.exe")

    function = catalog["functions"][0]
    assert function["id"] == "demo.exe:open"
    assert function["ranges"] == [
        {
            "kind": "function_chunk",
            "segment": "seg000",
            "offset": "0xee35",
            "size": 13,
            "end_offset": "0xee41",
            "source": "ida_lst",
        }
    ]


def test_dosunit_cli_make_mapping_and_select_vectors(tmp_path: Path):
    oracle = {
        "schema": "dosunit.functions.v1",
        "module": "orig.exe",
        "functions": [
            {
                "id": "orig.exe:leaf",
                "names": ["leaf"],
                "entry": {"segment_para": "0x0000", "offset": "0x0200"},
                "return_kind": "near",
            }
        ],
    }
    candidate = {
        "schema": "dosunit.functions.v1",
        "module": "rebuilt.exe",
        "functions": [
            {
                "id": "rebuilt.exe:leaf",
                "names": ["leaf"],
                "entry": {"segment_para": "0x0001", "offset": "0x0300"},
                "return_kind": "near",
            }
        ],
    }
    vectors = {"schema": "dosunit.vectors.v1", "vectors": [_leaf_vector()]}
    oracle_path = tmp_path / "oracle.json"
    candidate_path = tmp_path / "candidate.json"
    vectors_path = tmp_path / "vectors.json"
    mapping_path = tmp_path / "mapping.json"
    selected_path = tmp_path / "selected.json"
    oracle_path.write_text(json.dumps(oracle))
    candidate_path.write_text(json.dumps(candidate))
    vectors_path.write_text(json.dumps(vectors))

    assert (
        dosunit_main(
            [
                "make-mapping",
                "--oracle-functions",
                str(oracle_path),
                "--candidate-functions",
                str(candidate_path),
                "--out",
                str(mapping_path),
            ]
        )
        == 0
    )
    assert (
        dosunit_main(
            ["select-vectors", "--vectors", str(vectors_path), "--function", "leaf", "--out", str(selected_path)]
        )
        == 0
    )

    assert json.loads(mapping_path.read_text())["summary"]["mapped"] == 1
    assert len(json.loads(selected_path.read_text())["vectors"]) == 1


def test_dosunit_cli_compare_returns_nonzero_for_refused_vector(tmp_path: Path):
    vectors_path = tmp_path / "vectors.json"
    results_path = tmp_path / "results.json"
    vectors_path.write_text(json.dumps({"schema": "dosunit.vectors.v1", "vectors": [_leaf_vector()]}))

    rc = dosunit_main(["compare", "--backend", "fixture", "--vectors", str(vectors_path), "--out", str(results_path)])

    assert rc == 1
    result = json.loads(results_path.read_text())["results"][0]
    assert result["status"] == "refused"
    assert result["verdict"]["kind"] == "oracle_unavailable"


def test_compare_loaded_data_images_applies_relocations_zero_tail_and_normalizes_code_pointer(tmp_path: Path):
    data_para = 0x0030
    pointer_offset = 0x0010
    reloc_offset = 0x0020
    original_image = bytearray(0x340)
    candidate_image = bytearray(0x340)
    original_image[data_para * 16 : data_para * 16 + 0x40] = bytes(range(0x40))
    candidate_image[data_para * 16 : data_para * 16 + 0x40] = bytes(range(0x40))
    original_image[data_para * 16 + pointer_offset : data_para * 16 + pointer_offset + 2] = (0x0123).to_bytes(
        2, "little"
    )
    candidate_image[data_para * 16 + pointer_offset : data_para * 16 + pointer_offset + 2] = (0x0140).to_bytes(
        2, "little"
    )
    original_image[data_para * 16 + reloc_offset : data_para * 16 + reloc_offset + 2] = (0x0000).to_bytes(2, "little")
    candidate_image[data_para * 16 + reloc_offset : data_para * 16 + reloc_offset + 2] = (0x0001).to_bytes(2, "little")
    original = tmp_path / "original.exe"
    candidate = tmp_path / "candidate.exe"
    relocs = ((reloc_offset, data_para),)
    original.write_bytes(_mz_exe(bytes(original_image), relocs=relocs, minalloc=0x0010))
    candidate.write_bytes(_mz_exe(bytes(candidate_image), relocs=relocs, minalloc=0x0010))
    oracle_catalog = _data_catalog(data_para=data_para, exit_offset=0x0123)
    candidate_catalog = _data_catalog(data_para=data_para, exit_offset=0x0140)

    failed = compare_loaded_data_images(
        oracle_exe=original,
        candidate_exe=candidate,
        oracle_catalog=oracle_catalog,
        candidate_catalog=candidate_catalog,
        ranges=["DATA:0x0000..0x0080"],
        oracle_load_base_para=0x0001,
        candidate_load_base_para=0x0000,
    )
    passed = compare_loaded_data_images(
        oracle_exe=original,
        candidate_exe=candidate,
        oracle_catalog=oracle_catalog,
        candidate_catalog=candidate_catalog,
        ranges=["DATA:0x0000..0x0080"],
        code_pointer_normalizations=["DATA:0x0010:__exit"],
        oracle_load_base_para=0x0001,
        candidate_load_base_para=0x0000,
    )

    assert failed["status"] == "failed"
    assert failed["summary"]["literal_mismatches"] > 0
    failed_report = render_failure_report(failed)
    assert "Failed Data Ranges" in failed_report
    assert "Offset" in failed_report
    assert "oracle" in failed_report
    assert "candidate" in failed_report
    assert passed["status"] == "passed"
    assert passed["summary"]["literal_mismatches"] == 0
    assert passed["normalizations"][0]["oracle_value"] == "0x0123"
    assert passed["normalizations"][0]["candidate_value"] == "0x0140"
    assert passed["ranges"][0]["normalized_bytes"] == 2


def test_dosunit_cli_compare_data_supports_segment_mapping_and_code_pointer_normalization(tmp_path: Path):
    data_para = 0x0030
    original_image = bytearray(0x330)
    candidate_image = bytearray(0x330)
    original_image[data_para * 16 : data_para * 16 + 0x20] = b"A" * 0x20
    candidate_image[data_para * 16 : data_para * 16 + 0x20] = b"A" * 0x20
    original_image[data_para * 16 + 0x0010 : data_para * 16 + 0x0012] = (0x0200).to_bytes(2, "little")
    candidate_image[data_para * 16 + 0x0010 : data_para * 16 + 0x0012] = (0x0210).to_bytes(2, "little")
    original = tmp_path / "original.exe"
    candidate = tmp_path / "candidate.exe"
    original.write_bytes(_mz_exe(bytes(original_image), minalloc=0x0010))
    candidate.write_bytes(_mz_exe(bytes(candidate_image), minalloc=0x0010))
    oracle_catalog = _data_catalog(data_para=data_para, exit_offset=0x0200, data_segment_name="Data1")
    candidate_catalog = _data_catalog(data_para=data_para, exit_offset=0x0210, data_segment_name="DGROUP")
    oracle_path = tmp_path / "oracle.functions.json"
    candidate_path = tmp_path / "candidate.functions.json"
    out_path = tmp_path / "data.results.json"
    oracle_path.write_text(json.dumps(oracle_catalog))
    candidate_path.write_text(json.dumps(candidate_catalog))

    rc = dosunit_main(
        [
            "compare-data",
            "--oracle-exe",
            str(original),
            "--candidate-exe",
            str(candidate),
            "--oracle-functions",
            str(oracle_path),
            "--candidate-functions",
            str(candidate_path),
            "--range",
            "Data1=DGROUP:0x0000..0x0040",
            "--normalize-code-pointer",
            "Data1:0x0010=DGROUP:0x0010:__exit",
            "--out",
            str(out_path),
        ]
    )

    assert rc == 0
    result = json.loads(out_path.read_text())
    assert result["status"] == "passed"
    assert result["ranges"][0]["oracle_segment"] == "Data1"
    assert result["ranges"][0]["candidate_segment"] == "DGROUP"


def _data_catalog(*, data_para: int, exit_offset: int, data_segment_name: str = "DATA") -> dict[str, object]:
    return {
        "schema": "dosunit.functions.v1",
        "module": "demo.exe",
        "segments": [{"name": data_segment_name, "class": "DATA", "paragraph": f"0x{data_para:04x}"}],
        "functions": [
            {
                "id": "demo.exe:__exit",
                "names": ["__exit"],
                "entry": {"segment_para": "0x0000", "offset": f"0x{exit_offset:04x}"},
                "return_kind": "near",
            }
        ],
    }


def test_root_dosunit_wrapper_exposes_cli_help():
    root = Path(__file__).resolve().parents[2]
    result = subprocess.run(
        [sys.executable, str(root / "dosunit.py"), "--help"],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "record-oracle" in result.stdout


def test_kvikdos_harness_builds_for_near_mz_function(tmp_path: Path):
    image = bytearray(0x300)
    image[0x200:0x204] = b"\xb8\x34\x12\xc3"  # mov ax, 0x1234; ret
    exe = tmp_path / "demo.exe"
    exe.write_bytes(_mz_exe(bytes(image)))

    harness = build_harness(_leaf_vector(), exe_path=exe)

    assert harness.exe_bytes[:2] == b"MZ"
    assert harness.observation_linear > 0


@pytest.mark.skipif(
    not os.access("/dev/kvm", os.R_OK | os.W_OK) or not Path("/home/xor/kvikdos/kvikdos.c").exists(),
    reason="real libkvikdos smoke requires writable /dev/kvm and /home/xor/kvikdos/kvikdos.c",
)
def test_libkvikdos_backend_records_real_near_function_oracle(tmp_path: Path):
    image = bytearray(0x300)
    image[0x200:0x204] = b"\xb8\x34\x12\xc3"  # mov ax, 0x1234; ret
    exe = tmp_path / "demo.exe"
    exe.write_bytes(_mz_exe(bytes(image)))

    recorded = record_oracle(
        {"schema": "dosunit.vectors.v1", "vectors": [_leaf_vector()]},
        backend="libkvikdos",
        exe_path=exe,
    )

    result = recorded["results"][0]
    assert result["status"] == "passed"
    assert recorded["vectors"][0]["expected"]["status"] == "returned"
    assert recorded["vectors"][0]["expected"]["regs"]["ax"] == "0x1234"
    assert recorded["vectors"][0]["expected"]["regs"]["sp"] == "0xff02"


@pytest.mark.skipif(
    not os.access("/dev/kvm", os.R_OK | os.W_OK) or not Path("/home/xor/kvikdos/kvikdos.c").exists(),
    reason="real libkvikdos smoke requires writable /dev/kvm and /home/xor/kvikdos/kvikdos.c",
)
def test_libkvikdos_session_snapshot_restore_roundtrip(tmp_path: Path):
    image = bytearray(0x300)
    image[0x200:0x204] = b"\xb8\x34\x12\xc3"  # mov ax, 0x1234; ret
    exe = tmp_path / "demo.exe"
    exe.write_bytes(_mz_exe(bytes(image)))
    harness = build_harness(_leaf_vector(), exe_path=exe)

    with KvikdosSession() as session:
        session.run_harness(harness.exe_bytes)
        before = session.read_memory(harness.observation_linear, 4)
        snapshot = session.snapshot_create()
        try:
            session.write_memory(harness.observation_linear, b"BAD!")
            assert session.read_memory(harness.observation_linear, 4) == b"BAD!"
            session.snapshot_restore(snapshot)
            assert session.read_memory(harness.observation_linear, 4) == before
        finally:
            session.snapshot_destroy(snapshot)


@pytest.mark.skipif(
    not os.access("/dev/kvm", os.R_OK | os.W_OK) or not Path("/home/xor/kvikdos/kvikdos.c").exists(),
    reason="real libkvikdos smoke requires writable /dev/kvm and /home/xor/kvikdos/kvikdos.c",
)
def test_libkvikdos_backend_observes_segmented_ds_memory(tmp_path: Path):
    image = bytearray(0x500)
    image[0x200:0x204] = b"\xa3\x00\x03\xc3"  # mov [0x0300], ax; ret
    exe = tmp_path / "demo.exe"
    exe.write_bytes(_mz_exe(bytes(image)))
    vector = _leaf_vector()
    vector["pre"]["regs"]["ax"] = "0x1234"  # type: ignore[index]
    vector["observe"]["memory"] = [{"space": "DS", "offset": "0x0300", "size": "0x0002"}]  # type: ignore[index]

    recorded = record_oracle(
        {"schema": "dosunit.vectors.v1", "vectors": [vector]},
        backend="libkvikdos",
        exe_path=exe,
    )

    assert recorded["results"][0]["status"] == "passed"
    assert recorded["vectors"][0]["expected"]["memory"][0]["bytes"] == "3412"


@pytest.mark.skipif(
    not os.access("/dev/kvm", os.R_OK | os.W_OK) or not Path("/home/xor/kvikdos/kvikdos.c").exists(),
    reason="real libkvikdos smoke requires writable /dev/kvm and /home/xor/kvikdos/kvikdos.c",
)
def test_libkvikdos_compare_uses_candidate_mapping(tmp_path: Path):
    original_image = bytearray(0x300)
    original_image[0x200:0x204] = b"\xb8\x11\x11\xc3"  # mov ax, 0x1111; ret
    candidate_image = bytearray(0x330)
    candidate_image[0x200:0x204] = b"\xb8\x22\x22\xc3"  # wrong same-layout function
    candidate_image[0x210:0x214] = b"\xb8\x11\x11\xc3"  # mapped rebuilt function
    original = tmp_path / "original.exe"
    candidate = tmp_path / "candidate.exe"
    original.write_bytes(_mz_exe(bytes(original_image)))
    candidate.write_bytes(_mz_exe(bytes(candidate_image)))
    vector = _leaf_vector()
    oracle = record_oracle(
        {"schema": "dosunit.vectors.v1", "vectors": [vector]},
        backend="libkvikdos",
        exe_path=original,
    )
    mapping = {
        "schema": "dosunit.mapping.v1",
        "oracle_module": "demo.exe",
        "candidate_module": "candidate.exe",
        "functions": [{"oracle_name": "leaf", "candidate_entry": {"cs": "0x0000", "ip": "0x0210", "kind": "near"}}],
    }

    result = compare_vectors(oracle, backend="libkvikdos", candidate_path=candidate, mapping_document=mapping)

    assert result["results"][0]["status"] == "passed"


@pytest.mark.skipif(
    not os.access("/dev/kvm", os.R_OK | os.W_OK) or not Path("/home/xor/kvikdos/kvikdos.c").exists(),
    reason="real libkvikdos smoke requires writable /dev/kvm and /home/xor/kvikdos/kvikdos.c",
)
def test_branch_generated_vector_replays_on_rebuilt_function_boundary(tmp_path: Path):
    branch_code = b"\x3d\x01\x00\x74\x04\xb8\x22\x22\xc3\xb8\x11\x11\xc3"  # cmp ax, 1; je taken; mov ax, 0x2222; ret; taken: mov ax, 0x1111; ret
    original_image = bytearray(0x320)
    original_image[0x200 : 0x200 + len(branch_code)] = branch_code
    candidate_image = bytearray(0x280)
    candidate_image[0x200:0x204] = b"\xb8\x99\x99\xc3"  # wrong same-layout address
    candidate_image[0x250 : 0x250 + len(branch_code)] = branch_code
    original = tmp_path / "original.exe"
    candidate = tmp_path / "candidate.exe"
    original.write_bytes(_mz_exe(bytes(original_image)))
    candidate.write_bytes(_mz_exe(bytes(candidate_image)))
    catalog = _edge_catalog("demo.exe:branchy", "branchy", offset=0x0200, size=len(branch_code))

    generated = generate_vectors(
        functions_catalog=catalog, exe_path=original, strategy="edge", max_vectors_per_function=1
    )
    oracle = record_oracle(generated, backend="libkvikdos", exe_path=original)
    mapping = {
        "schema": "dosunit.mapping.v1",
        "oracle_module": "demo.exe",
        "candidate_module": "candidate.exe",
        "functions": [{"oracle_name": "branchy", "candidate_entry": {"cs": "0x0000", "ip": "0x0250", "kind": "near"}}],
    }
    result = compare_vectors(oracle, backend="libkvikdos", candidate_path=candidate, mapping_document=mapping)

    assert generated["vectors"][0]["source"]["coverage"]["binary"] == "oracle"
    assert generated["vectors"][0]["source"]["coverage"]["label"] == "taken"
    assert oracle["vectors"][0]["expected"]["regs"]["ax"] == "0x1111"
    assert result["results"][0]["status"] == "passed"
