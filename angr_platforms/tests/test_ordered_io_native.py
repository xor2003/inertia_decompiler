"""Native MZ and PE32 controls for the declared ordered-I/O caller premise.

Real executable fixtures require conditional equality under the explicit model,
observable counterexamples for event mutations, and closed unbound admission.
"""

from __future__ import annotations

import importlib
import json
import struct
import sys
from argparse import Namespace
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest

pytestmark = [pytest.mark.resource_serial, pytest.mark.xdist_group("ordered-io-native")]

REPO = Path(__file__).resolve().parents[2]
MODEL_ID = "dosunit.ordered_io.scalar_in_out.v1"
PREMISE_NAME = "unproved_ordered_io_environment"


# --------------------------------------------------------------------------
# Fixtures: real MZ and PE32 bytes (same layouts as existing helpers).
#
# real16 caller ``e8 01 00 c3``: near call rel16=+1 -> offset 4; ret.
# PE32 caller ``e8 01 00 00 00 c3``: near call rel32=+1 -> offset 6; ret.
# callee ``ec 31 c0 c3``: ``in al/ax/eax, dx``; ``xor a-reg, a-reg``; ret —
# the port read's value is dead, so a pass proves the dead-read event itself
# is retained and compared, not liveness-dropped.
# --------------------------------------------------------------------------

def _mz_exe(image: bytes) -> bytes:
    """MZ whose load module is exactly ``image`` (mirrors _mz_exe helper)."""
    header_size = 0x20
    file_size = header_size + len(image)
    blocks, lastsize = divmod(file_size, 512)
    if lastsize:
        blocks += 1
    header = bytearray(header_size)
    header[0:2] = b"MZ"
    header[0x02:0x04] = lastsize.to_bytes(2, "little")
    header[0x04:0x06] = blocks.to_bytes(2, "little")
    header[0x08:0x0A] = (header_size // 16).to_bytes(2, "little")
    header[0x0A:0x0C] = (0x1000).to_bytes(2, "little")
    header[0x0C:0x0E] = (0xFFFF).to_bytes(2, "little")
    header[0x0E:0x10] = (0x0080).to_bytes(2, "little")
    header[0x10:0x12] = (0xFFFE).to_bytes(2, "little")
    header[0x18:0x1A] = (0x1C).to_bytes(2, "little")
    return bytes(header) + image


def _pe32_bytes(code: bytes) -> bytes:
    """i386 PE whose virtual .text section ends at the last code byte."""
    data = bytearray(0x400)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x14C, 1, 0, 0, 0, 0xE0, 0x102)
    struct.pack_into("<H", data, 0x98, 0x10B)
    for offset, value in ((4, 0x200), (16, 0x1000), (20, 0x1000), (28, 0x400000),
                          (32, 0x1000), (36, 0x200), (56, 0x2000), (60, 0x200),
                          (72, 0x100000), (76, 0x1000), (80, 0x100000), (84, 0x1000), (92, 16)):
        struct.pack_into("<I", data, 0x98 + offset, value)
    struct.pack_into("<H", data, 0x98 + 68, 3)
    struct.pack_into("<8sIIIIIIHHI", data, 0x178, b".text\0\0\0", len(code), 0x1000,
                     0x200, 0x200, 0, 0, 0, 0, 0x60000020)
    data[0x200:0x200 + len(code)] = code
    return bytes(data)


def _edge_function(function_id: str, name: str, *, offset: int, size: int) -> dict[str, object]:
    """One catalog entry for a module-relative near function."""
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


def _mz_catalog(functions: list[tuple[str, int, int]]) -> dict[str, object]:
    """A dosunit.functions.v1 catalog over (name, offset, size) rows."""
    return {
        "schema": "dosunit.functions.v1",
        "id": "functions:test",
        "module": "demo.exe",
        "program_kind": "mz_exe",
        "diagnostics": [],
        "functions": [
            _edge_function(f"demo.exe:{name}", name, offset=offset, size=size)
            for name, offset, size in functions
        ],
    }


MZ_CALLER = bytes.fromhex("e80100c3")
MZ_MID = bytes.fromhex("e80100c3")
PE_CALLER = bytes.fromhex("e801000000c3")
CALLEE_IO = bytes.fromhex("ec31c0c3")
CALLEE_IO_EQUIV = bytes.fromhex("ec33c0c3")
CALLEE_NO_READ = bytes.fromhex("31c0c3")
CALLEE_EXTRA_READ = bytes.fromhex("ecec31c0c3")
CALLEE_WRITE = bytes.fromhex("ee31c0c3")

ENTRY = 0x401000


def _mz_two_level(callee: bytes) -> tuple[bytes, dict[str, object]]:
    code = MZ_CALLER + callee
    return _mz_exe(code), _mz_catalog([("caller", 0, 4), ("callee", 4, len(callee))])


def _mz_three_level(callee: bytes) -> tuple[bytes, dict[str, object]]:
    code = MZ_CALLER + MZ_MID + callee
    return _mz_exe(code), _mz_catalog(
        [("caller", 0, 4), ("mid", 4, 4), ("leaf", 8, len(callee))]
    )


def _pe_two_level(callee: bytes) -> tuple[bytes, dict[str, tuple[int, int]]]:
    code = PE_CALLER + callee
    return _pe32_bytes(code), {
        "f": (ENTRY, ENTRY + len(PE_CALLER) - 1),
        "callee": (ENTRY + len(PE_CALLER), ENTRY + len(code) - 1),
    }


def _pe_three_level(callee: bytes) -> tuple[bytes, dict[str, tuple[int, int]]]:
    code = PE_CALLER + PE_CALLER + callee
    step = len(PE_CALLER)
    return _pe32_bytes(code), {
        "f": (ENTRY, ENTRY + step - 1),
        "mid": (ENTRY + step, ENTRY + 2 * step - 1),
        "leaf": (ENTRY + 2 * step, ENTRY + len(code) - 1),
    }


def _compare16(
    oracle: Path, candidate: Path, catalog_o: dict, catalog_c: dict, *, bound: bool
) -> dict[str, Any]:
    """Run the public real16 compare with an explicit optional binding."""
    from tools.dosunit.real16_binary_compare import compare_binary16

    kwargs: dict[str, Any] = {}
    if bound:
        kwargs["ordered_io_environment"] = MODEL_ID
    report = compare_binary16(
        oracle, candidate, catalog_o, catalog_c,
        selected=("caller",), solver_timeout_ms=30000, max_function_ms=30000,
        **kwargs,
    )
    (oracle.parent / "report.json").write_text(json.dumps(report, indent=2))
    return report


def _write_mz(tmp_path: Path, oracle: bytes, candidate: bytes) -> tuple[Path, Path]:
    o, c = tmp_path / "oracle.exe", tmp_path / "candidate.exe"
    o.write_bytes(oracle)
    c.write_bytes(candidate)
    return o, c


def _assert_conditional_consumed(report: dict[str, Any]) -> None:
    """A conditional verdict must prove event equality and carry the premise."""
    assert report["status"] == "conditional", report["proof"]
    premise_block = report.get("ordered_io_environment")
    assert isinstance(premise_block, dict), report.keys()
    assert premise_block["premise"]["kind"] == "declared_ordered_io_environment"
    assert premise_block["premise"]["proved"] is False
    rows = report["proof"]["verdicts"]
    assert rows and all(row["status"] == "conditional" for row in rows), rows
    for row in rows:
        assert PREMISE_NAME in row.get("assumptions", []), row
    backend = report.get("backend", {}).get("function_proofs") or {}
    assert any(
        isinstance(proof, dict) and proof.get("environment")
        for proof in backend.values()
    ), backend


def _assert_refused(report: dict[str, Any]) -> None:
    assert report["status"] not in {"proved", "conditional"}, report["proof"]


@pytest.mark.parametrize("callee", [CALLEE_IO, CALLEE_IO_EQUIV],
                         ids=["in_dead_read", "in_dead_read_equiv_xor"])
def test_mz_io_callee_conditional(tmp_path: Path, callee: bytes) -> None:
    """Identical/equivalent IN callee discharges conditionally when bound."""
    oracle_img, catalog = _mz_two_level(CALLEE_IO)
    candidate_img, cand_catalog = _mz_two_level(callee)
    o, c = _write_mz(tmp_path, oracle_img, candidate_img)
    report = _compare16(o, c, catalog, cand_catalog, bound=True)
    _assert_conditional_consumed(report)


def test_mz_nested_caller_io_conditional(tmp_path: Path) -> None:
    """The premise must propagate caller -> mid -> leaf(IN), not only one hop."""
    oracle_img, catalog = _mz_three_level(CALLEE_IO)
    o, c = _write_mz(tmp_path, oracle_img, oracle_img)
    report = _compare16(o, c, catalog, catalog, bound=True)
    _assert_conditional_consumed(report)


def test_mz_io_unbound_refused(tmp_path: Path) -> None:
    """The identical I/O pair without any binding must stay unproved."""
    oracle_img, catalog = _mz_two_level(CALLEE_IO)
    o, c = _write_mz(tmp_path, oracle_img, oracle_img)
    report = _compare16(o, c, catalog, catalog, bound=False)
    _assert_refused(report)


@pytest.mark.parametrize(
    "callee",
    [CALLEE_NO_READ, CALLEE_EXTRA_READ, CALLEE_WRITE],
    ids=["removed_read", "extra_read", "reversed_direction"],
)
def test_mz_io_mutated_callee_fails(tmp_path: Path, callee: bytes) -> None:
    """Dropping, duplicating or redirecting the event cannot pass conditional."""
    oracle_img, catalog = _mz_two_level(CALLEE_IO)
    candidate_img, cand_catalog = _mz_two_level(callee)
    o, c = _write_mz(tmp_path, oracle_img, candidate_img)
    report = _compare16(o, c, catalog, cand_catalog, bound=True)
    row = report["proof"]["verdicts"][0]
    assert row["status"] == "counterexample", row
    assert row["detail"] == "observable_mismatch", row


@pytest.mark.parametrize(
    "binding",
    ["dosunit.ordered_io.scalar_in_out.v2", "ordered_scalar_port_io",
     {"model": "ordered_scalar_port_io"}],
    ids=["wrong_version", "bare_model_name", "dict_binding"],
)
def test_mz_malformed_binding_refuses(tmp_path: Path, binding: object) -> None:
    """Malformed or incompatible bindings refuse before lowering."""
    from tools.dosunit.model import DosUnitError
    from tools.dosunit.real16_binary_compare import compare_binary16

    oracle_img, catalog = _mz_two_level(CALLEE_IO)
    o, c = _write_mz(tmp_path, oracle_img, oracle_img)
    with pytest.raises((DosUnitError, ValueError)):
        compare_binary16(o, c, catalog, catalog, selected=("caller",),
                         ordered_io_environment=binding)


# --------------------------------------------------------------------------
# PE32 public drivers (bc5 + msc8): isolated module lanes, real .lst maps.
# --------------------------------------------------------------------------

DRIVER_MODULES = (
    "flat32_adapter", "flat32_catalog", "flat32_cfg", "flat32_fast_pe",
    "flat32_region", "flat32_verdict", "z3cmp32",
)
SEAM_NAMES = (
    "_load_lifter_project", "_lower_function", "_vex_live_statement_indices",
    "REG_BY_OFFSET", "SSA_REGISTER_WIDTHS", "INTERNAL_STATE_REGS",
    "HIGH_HALF_REGS", "RAW_OUTPUT_REGS", "BYTE_REGISTER_ACCESS",
    "_lower_expr", "_read_register", "_write_register",
    "_register_write_target", "_finish_irsb_lowering",
    "_prepare_layout_normalized_functions", "_quick_compare_functions",
    "_can_add_dynamic_successor_range",
)
_MISSING: Any = object()


@contextmanager
def _driver_lane(name: str) -> Iterator[dict[str, Any]]:
    """Install one driver dir's modules and restore every global it disturbs.

    Each production driver has same-named modules, so imports are isolated
    and every touched module and adapter seam is restored afterward.
    """
    import tools.dosunit.straightline_ssa as ssa_module

    production = REPO / "artifacts" / f"{name}-z3cmp32"
    directories = [production]
    directories = [d for d in directories if d.is_dir()]
    saved_path = list(sys.path)
    saved_modules = {mod: sys.modules.get(mod, _MISSING) for mod in DRIVER_MODULES}
    saved_seams = {seam: getattr(ssa_module, seam, _MISSING) for seam in SEAM_NAMES}
    for mod in DRIVER_MODULES:
        sys.modules.pop(mod, None)
    for directory in reversed(directories):
        sys.path.insert(0, str(directory))
    try:
        imported = {
            mod: importlib.import_module(mod)
            for mod in DRIVER_MODULES
            if any((d / f"{mod}.py").is_file() for d in directories)
        }
        yield imported
    finally:
        sys.path[:] = saved_path
        for mod in DRIVER_MODULES:
            sys.modules.pop(mod, None)
        for mod, previous in saved_modules.items():
            if previous is not _MISSING:
                sys.modules[mod] = previous
        for seam, previous in saved_seams.items():
            if previous is _MISSING:
                if hasattr(ssa_module, seam):
                    delattr(ssa_module, seam)
            else:
                setattr(ssa_module, seam, previous)


def _lst_lines(functions: Mapping[str, tuple[int, int]]) -> str:
    lines = []
    for name, (start, last) in sorted(functions.items(), key=lambda item: item[1][0]):
        lines.append(f".text:{start:08x} {name} proc")
        lines.append(f".text:{last:08x} {name} endp")
    return "\n".join(lines) + "\n"


def _run_driver(
    modules: dict[str, Any],
    tmp_path: Path,
    oracle: tuple[bytes, dict[str, tuple[int, int]]],
    candidate: tuple[bytes, dict[str, tuple[int, int]]],
    monkeypatch: pytest.MonkeyPatch,
    *,
    bound: bool,
    binding: object = None,
) -> dict[str, Any]:
    oracle_exe, candidate_exe = tmp_path / "oracle.exe", tmp_path / "candidate.exe"
    oracle_lst, candidate_lst = tmp_path / "oracle.lst", tmp_path / "candidate.lst"
    oracle_exe.write_bytes(oracle[0])
    candidate_exe.write_bytes(candidate[0])
    oracle_lst.write_text(_lst_lines(oracle[1]))
    candidate_lst.write_text(_lst_lines(candidate[1]))
    driver = modules["z3cmp32"]
    monkeypatch.setattr(driver, "nm_symbols", lambda _path: {})
    (tmp_path / "out").mkdir(exist_ok=True)
    (tmp_path / "cache").mkdir(exist_ok=True)
    args = Namespace(
        oracle_exe=oracle_exe, candidate_exe=candidate_exe,
        oracle_lst=oracle_lst, candidate_lst=candidate_lst, candidate_syms=None,
        cache_dir=tmp_path / "cache", functions="f", mode="region",
        output_regs="eax,edx,esp", scan_limit=0x2000, timeout_ms=15000,
        region_max_blocks=128, normalize_globals=False, assume_paired_calls=False,
        out_dir=tmp_path / "out", entry_esp_range=None, recursive=False,
        ordered_io_environment=(MODEL_ID if bound else None) if binding is None else binding,
    )
    with modules["flat32_adapter"].installed(region=True):
        report = driver.compare(args)
    (tmp_path / "report.json").write_text(json.dumps(report, indent=2))
    return report


def _row(report: dict[str, Any]) -> dict[str, Any]:
    assert report["summary"]["total"] == 1, report
    return report["results"][0]


def _assert_row_conditional(row: dict[str, Any], report: dict[str, Any]) -> None:
    assert row["status"] == "conditional", row
    assumptions = row.get("assumptions") or {}
    assert PREMISE_NAME in assumptions, row
    premise = assumptions[PREMISE_NAME]
    assert premise["kind"] == "declared_ordered_io_environment"
    assert row.get("environment_premise", {}).get("premise", {}).get("proved") is False
    contract = report.get("proof_contract") or {}
    assert contract.get("ordered_io_premise") == premise, contract.keys()


def _assert_row_refused(row: dict[str, Any]) -> None:
    assert row["status"] not in {"passed", "conditional"}, row


@pytest.mark.parametrize("driver", ["msc8", "bc5"], ids=["msc8", "bc5"])
@pytest.mark.parametrize("callee", [CALLEE_IO, CALLEE_IO_EQUIV],
                         ids=["in_dead_read", "in_dead_read_equiv_xor"])
def test_pe32_io_callee_conditional(
    driver: str, callee: bytes, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Both public drivers publish a conditional verdict under the binding."""
    with _driver_lane(driver) as modules:
        report = _run_driver(
            modules, tmp_path, _pe_two_level(CALLEE_IO), _pe_two_level(callee),
            monkeypatch, bound=True,
        )
    _assert_row_conditional(_row(report), report)


@pytest.mark.parametrize("driver", ["msc8", "bc5"], ids=["msc8", "bc5"])
def test_pe32_nested_caller_io_conditional(
    driver: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Premise propagates f -> mid -> leaf(IN) through nested composition."""
    with _driver_lane(driver) as modules:
        report = _run_driver(
            modules, tmp_path, _pe_three_level(CALLEE_IO), _pe_three_level(CALLEE_IO),
            monkeypatch, bound=True,
        )
    _assert_row_conditional(_row(report), report)


@pytest.mark.parametrize("driver", ["msc8", "bc5"], ids=["msc8", "bc5"])
def test_pe32_io_unbound_refused(
    driver: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Identical I/O pair without a binding keeps the closed-environment gate."""
    with _driver_lane(driver) as modules:
        report = _run_driver(
            modules, tmp_path, _pe_two_level(CALLEE_IO), _pe_two_level(CALLEE_IO),
            monkeypatch, bound=False,
        )
    _assert_row_refused(_row(report))


@pytest.mark.parametrize("driver", ["msc8", "bc5"], ids=["msc8", "bc5"])
@pytest.mark.parametrize(
    "callee",
    [CALLEE_NO_READ, CALLEE_EXTRA_READ, CALLEE_WRITE],
    ids=["removed_read", "extra_read", "reversed_direction"],
)
def test_pe32_io_mutated_callee_fails(
    driver: str, callee: bytes, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Dropped/duplicated/redirected events fail honestly, never conditional."""
    with _driver_lane(driver) as modules:
        report = _run_driver(
            modules, tmp_path, _pe_two_level(CALLEE_IO), _pe_two_level(callee),
            monkeypatch, bound=True,
        )
    row = _row(report)
    assert row["status"] == "failed", row
    assert row["reason"] == "observable_mismatch", row


@pytest.mark.parametrize("driver", ["msc8", "bc5"], ids=["msc8", "bc5"])
def test_pe32_malformed_binding_refuses(
    driver: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A wrong model identity fails closed at the driver intake."""
    with _driver_lane(driver) as modules, pytest.raises(ValueError):
        _run_driver(
            modules, tmp_path, _pe_two_level(CALLEE_IO), _pe_two_level(CALLEE_IO),
            monkeypatch, bound=True, binding="dosunit.ordered_io.scalar_in_out.v2",
        )
