"""Normal-pipeline lane for the staged flat32 binary comparators.

Layer: tests.
Responsibility: run both staged flat32 drivers (MSC8 and BC5) through the
shared proof helpers — ``compare_functions_with_calls`` for checked
direct-call composition and ``compare_reblocked_cfg`` for matched
reblocked-CFG induction — under each driver's own adapter seams.

The two artifact directories contain modules with colliding top-level names
(``flat32_adapter``, ``flat32_catalog``, ``flat32_cfg``, ``flat32_region``,
``flat32_verdict``, ``flat32_fast_pe``, ``z3cmp32``), so they cannot coexist
on ``sys.path`` in one process.  The ``lane`` fixture installs exactly one
driver directory per test, then restores ``sys.path``, ``sys.modules`` and
every global ``straightline_ssa`` seam the adapters patch, so xdist workers
running items sequentially cannot leak driver state across tests.

All comparisons lift real i386 bytes through angr/PyVEX and prove with real
Z3.  No text recovery, no name-based semantics, no unproved relocation map:
the strict full-memory default is the only accepted unconditional proof.
"""

from __future__ import annotations

import importlib
import os
import subprocess
import sys
from argparse import Namespace
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import angr
import pytest

from tools.dosunit import straightline_ssa as S
from tools.dosunit.flat32_call_composition import compare_functions_with_calls
from tools.dosunit.flat32_cfg_regions import compare_reblocked_cfg

REPO_ROOT = Path(__file__).resolve().parents[2]
DRIVER_DIRS = {
    "msc8": REPO_ROOT / "artifacts" / "msc8-z3cmp32",
    "bc5": REPO_ROOT / "artifacts" / "bc5-z3cmp32",
}

# Top-level module names each driver dir provides; they collide across dirs
# and with anything already imported, so the fixture swaps them atomically.
DRIVER_MODULES: tuple[str, ...] = (
    "flat32_adapter",
    "flat32_catalog",
    "flat32_cfg",
    "flat32_fast_pe",
    "flat32_region",
    "flat32_verdict",
    "z3cmp32",
)

# Union of every ``straightline_ssa`` global either adapter's installed()
# monkey-patches.  Snapshot/restore is a dynamic seam boundary by design.
SEAM_NAMES: tuple[str, ...] = (
    "_load_lifter_project",
    "_lower_function",
    "_vex_live_statement_indices",
    "REG_BY_OFFSET",
    "SSA_REGISTER_WIDTHS",
    "INTERNAL_STATE_REGS",
    "HIGH_HALF_REGS",
    "RAW_OUTPUT_REGS",
    "BYTE_REGISTER_ACCESS",
    "_lower_expr",
    "_read_register",
    "_write_register",
    "_register_write_target",
    "_finish_irsb_lowering",
    "_prepare_layout_normalized_functions",
    "_quick_compare_functions",
    "_can_add_dynamic_successor_range",
)

_MISSING: Any = object()

BASE = 0x100000
OTHER_BASE = 0x200000
ORACLE_BASE = 0x12345000
CANDIDATE_BASE = 0x23456000

# caller: mov eax,[esp+4]; call 0x0d; add eax,2; ret   (13 bytes)
# callee at 0x0d: add eax,5; ret                       (4 bytes)
CALLER = "8b442404 e804000000 83c002 c3"
CALLEE = "83c005 c3"
CODE = f"{CALLER} {CALLEE}"

# test eax,eax; jz ret / dec eax; mov [esp+4],eax; jnz body / ret
LOOP = "85c0 7407 48 89442404 75f9 c3"
CHAIN_LOOP = "85c0 7409 48 eb00 89442404 75f7 c3"
GUARD_CORRUPT = "85db 7407 48 89442404 75f9 c3"  # test ebx,ebx not eax
STORE_CORRUPT = "85c0 7407 48 89442408 75f9 c3"  # [esp+8] not [esp+4]
RETURN_CORRUPT = "85c0 7407 48 89442404 75f9 c20400"  # ret 4 not ret

# Initial header test vs trailing test: zero iterations differ from one.
PRETEST_LOOP = "85c974044049ebf8c3"
POSTTEST_LOOP = "404985c97402ebf8c3"


@dataclass(frozen=True)
class DriverLane:
    """One staged driver's modules installed as the live top-level names."""

    name: str
    directory: Path
    adapter: Any
    catalog: Any
    cfg: Any
    region: Any
    verdict: Any
    z3cmp32: Any


@contextmanager
def _driver_lane(name: str) -> Iterator[DriverLane]:
    """Install one driver dir's modules and restore every global it disturbs."""
    directory = DRIVER_DIRS[name]
    saved_path = list(sys.path)
    saved_modules: dict[str, Any] = {mod: sys.modules.get(mod, _MISSING) for mod in DRIVER_MODULES}
    saved_seams: dict[str, Any] = {seam: getattr(S, seam, _MISSING) for seam in SEAM_NAMES}
    for mod in DRIVER_MODULES:
        sys.modules.pop(mod, None)
    sys.path.insert(0, str(directory))
    try:
        imported = {
            mod: importlib.import_module(mod)
            for mod in DRIVER_MODULES
            if (directory / f"{mod}.py").is_file()
        }
        yield DriverLane(
            name=name,
            directory=directory,
            adapter=imported["flat32_adapter"],
            catalog=imported["flat32_catalog"],
            cfg=imported["flat32_cfg"],
            region=imported["flat32_region"],
            verdict=imported["flat32_verdict"],
            z3cmp32=imported["z3cmp32"],
        )
    finally:
        sys.path[:] = saved_path
        for mod in DRIVER_MODULES:
            sys.modules.pop(mod, None)
        for mod, previous in saved_modules.items():
            if previous is not _MISSING:
                sys.modules[mod] = previous
        for seam, previous in saved_seams.items():
            if previous is _MISSING:
                if hasattr(S, seam):
                    delattr(S, seam)
            else:
                setattr(S, seam, previous)


@pytest.fixture(params=["msc8", "bc5"], ids=["msc8", "bc5"])
def lane(request: pytest.FixtureRequest) -> Iterator[DriverLane]:
    """Run each test once under each staged driver's isolated module set."""
    with _driver_lane(str(request.param)) as installed_lane:
        yield installed_lane


@pytest.fixture
def bc5_lane() -> Iterator[DriverLane]:
    """Install only the BC5 driver for public-driver coverage."""
    with _driver_lane("bc5") as installed_lane:
        yield installed_lane


def _project(code: str, base: int) -> angr.Project:
    """Load real i386 bytes as a flat shellcode project."""
    return angr.load_shellcode(bytes.fromhex(code.replace(" ", "")), arch="x86", load_address=base)


def _call_functions(base: int, callee_size: int = 4) -> dict[int, int]:
    """Declared complete byte ranges for the caller/callee fixture."""
    return {base: 0x0D, base + 0x0D: callee_size}


def _compare_calls(
    lane: DriverLane,
    oracle_code: str,
    candidate_code: str,
    *,
    oracle_functions: dict[int, int] | None = None,
    candidate_functions: dict[int, int] | None = None,
    outputs: tuple[str, ...] | None = None,
) -> dict[str, Any]:
    """Compose both sides under this driver's adapter seams and compare."""
    with lane.adapter.installed(region=True):
        return compare_functions_with_calls(
            _project(oracle_code, BASE),
            _project(candidate_code, BASE),
            oracle_entry=BASE,
            candidate_entry=BASE,
            oracle_functions=oracle_functions or _call_functions(BASE),
            candidate_functions=candidate_functions or _call_functions(BASE),
            outputs=outputs or lane.adapter.GPRS,
            timeout_ms=10000,
        )


def _compare_loops(
    lane: DriverLane,
    oracle_code: str,
    candidate_code: str,
    *,
    outputs: tuple[str, ...] | None = None,
    timeout_ms: int = 10000,
) -> dict[str, Any]:
    """Run the reblocked matched-CFG proof on loops at distinct load bases."""
    oracle = _project(oracle_code, ORACLE_BASE)
    candidate = _project(candidate_code, CANDIDATE_BASE)
    return compare_reblocked_cfg(
        (oracle, candidate),
        (ORACLE_BASE, len(bytes.fromhex(oracle_code))),
        (CANDIDATE_BASE, len(bytes.fromhex(candidate_code))),
        outputs or lane.adapter.OUTPUT_REGS,
        timeout_ms,
    )


def test_direct_call_composition_proves(lane: DriverLane) -> None:
    """A complete f->callee direct call composes and proves under both drivers."""
    result = _compare_calls(lane, CODE, CODE)
    assert result["status"] == "passed", result
    assert result["oracle_inlined_calls"] == 1
    assert result["return_targets_proved"] == 2


@pytest.mark.parametrize(
    "callee",
    [
        "83c006 c3",  # changed return value: eax+6 not eax+5
        "c74424082a000000 83c005 c3",  # extra callee stack store [esp+8]
        "83c005 c20400",  # changed cleanup: ret 4 not ret
    ],
    ids=["return_value", "callee_store", "stack_cleanup"],
)
def test_changed_callee_rejected(lane: DriverLane, callee: str) -> None:
    """Changed callee return, store or stack cleanup must not prove."""
    candidate_code = f"{CALLER} {callee}"
    result = _compare_calls(
        lane,
        CODE,
        candidate_code,
        candidate_functions={BASE: 0x0D, BASE + 0x0D: len(bytes.fromhex(callee))},
    )
    assert result["status"] == "failed", result


@pytest.mark.parametrize(
    ("caller_code", "functions", "reason_prefix"),
    [
        (CODE, {BASE: 0x0D}, "call_target_unmapped"),
        (
            f"{CALLER} e8fbffffff c3",
            {BASE: 0x0D, BASE + 0x0D: 6},
            "recursive_call",
        ),
        (
            "8b442404 ffd0 83c002 c3 83c005 c3",
            {BASE: 0x0D, BASE + 0x0D: 4},
            "call_indirect_target",
        ),
    ],
    ids=["unmapped_target", "recursive_callee", "indirect_call"],
)
def test_unsupported_calls_refuse(
    lane: DriverLane, caller_code: str, functions: dict[int, int], reason_prefix: str
) -> None:
    """Unmapped, recursive and indirect calls refuse; none can silently pass."""
    result = _compare_calls(
        lane,
        caller_code,
        caller_code,
        oracle_functions=functions,
        candidate_functions=functions,
    )
    assert result["status"] == "refused", result
    assert str(result["reason"]).startswith(reason_prefix)


def test_narrow_outputs_still_observe_abi_contract(lane: DriverLane) -> None:
    """outputs=("eax",) cannot hide a clobbered ebx/esp or a changed return."""
    clobber_ebx = f"{CALLER} bb07000000 83c005 c3"  # callee mov ebx,7
    result = _compare_calls(
        lane,
        CODE,
        clobber_ebx,
        candidate_functions={BASE: 0x0D, BASE + 0x0D: 9},
        outputs=("eax",),
    )
    assert result["status"] == "failed", result

    ret4 = f"{CALLER} 83c005 c20400"  # callee ret 4: esp differs
    result = _compare_calls(
        lane,
        CODE,
        ret4,
        candidate_functions={BASE: 0x0D, BASE + 0x0D: 6},
        outputs=("eax",),
    )
    assert result["status"] == "failed", result

    assert _compare_calls(lane, CODE, CODE, outputs=("eax",))["status"] == "passed"


def test_reblocked_loop_proves_across_load_bases(lane: DriverLane) -> None:
    """Identical and jmp-chain-split loops prove at distinct load bases."""
    result = _compare_loops(lane, LOOP, LOOP)
    assert result["status"] == "passed", result
    assert result["reason"] == "reblocked_cfg_induction"
    assert _compare_loops(lane, LOOP, CHAIN_LOOP)["status"] == "passed"


@pytest.mark.parametrize(
    "candidate",
    [GUARD_CORRUPT, STORE_CORRUPT, RETURN_CORRUPT],
    ids=["guard", "store", "return"],
)
def test_reblocked_corruptions_rejected(lane: DriverLane, candidate: str) -> None:
    """Changed loop guard, store target or return behavior fails the proof."""
    result = _compare_loops(lane, LOOP, candidate)
    assert result["status"] is lane.verdict.Status.REFUSED, result
    assert any(row["status"] is lane.verdict.Status.FAILED for row in result["block_verdicts"]), result


def test_pretest_posttest_loops_never_equal(lane: DriverLane) -> None:
    """Zero-iteration vs one-iteration entry semantics must never pass."""
    oracle = _project(PRETEST_LOOP, ORACLE_BASE)
    candidate = _project(POSTTEST_LOOP, CANDIDATE_BASE)
    result = compare_reblocked_cfg(
        (oracle, candidate),
        (ORACLE_BASE, len(bytes.fromhex(PRETEST_LOOP))),
        (CANDIDATE_BASE, len(bytes.fromhex(POSTTEST_LOOP))),
        lane.adapter.OUTPUT_REGS,
        10000,
    )
    assert result["status"] != "passed", result


def test_adapter_install_restores_global_seams(lane: DriverLane) -> None:
    """installed(region=True) restores every patched S seam by identity."""
    before = {seam: getattr(S, seam, _MISSING) for seam in SEAM_NAMES}
    with lane.adapter.installed(region=True):
        assert S.REG_BY_OFFSET is lane.adapter.REG32
        assert S.RAW_OUTPUT_REGS is lane.adapter.GPRS
    for seam in SEAM_NAMES:
        previous = before[seam]
        if previous is _MISSING:
            assert not hasattr(S, seam), seam
        else:
            assert getattr(S, seam) is previous, seam
    assert lane.adapter.CONTROL_TARGETS is None


@pytest.mark.parametrize(
    ("candidate_value", "expected"),
    [(7, "passed"), (8, "failed")],
    ids=["equal_callee", "changed_callee_return"],
)
def test_bc5_driver_proves_caller_through_unselected_callee(
    bc5_lane: DriverLane,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    candidate_value: int,
    expected: str,
) -> None:
    """Public BC5 driver: a selected caller proves through its unselected callee."""
    images = []
    paths = [tmp_path / "original.bin", tmp_path / "candidate.bin"]
    base = 0x401000
    for path, value in zip(paths, [7, candidate_value], strict=True):
        image = bytearray(0x26)
        image[:6] = bytes.fromhex("e81b000000c3")  # f: call +0x1b; ret
        image[0x20:0x26] = b"\xb8" + value.to_bytes(4, "little") + b"\xc3"
        path.write_bytes(image)
        images.append(
            angr.Project(
                str(path),
                auto_load_libs=False,
                main_opts={
                    "backend": "blob",
                    "arch": "x86",
                    "base_addr": base,
                    "entry_point": base,
                },
            )
        )
    driver = bc5_lane.z3cmp32
    monkeypatch.setattr(
        driver, "load32_verified", lambda path, _cache: images[paths.index(path)]
    )
    monkeypatch.setattr(
        driver,
        "cached_lst_functions",
        lambda _path, _cache: {
            "f": (base, base + 5),
            "callee": (base + 0x20, base + 0x25),
        },
    )
    monkeypatch.setattr(
        driver,
        "nm_symbols",
        lambda _path: {
            "f": bc5_lane.catalog.Symbol(base, 6, "T"),
            "callee": bc5_lane.catalog.Symbol(base + 0x20, 6, "T"),
        },
    )
    args = Namespace(
        oracle_exe=paths[0],
        candidate_exe=paths[1],
        oracle_lst=tmp_path / "o.lst",
        candidate_lst=None,
        candidate_syms=None,
        cache_dir=tmp_path / "cache",
        functions="f",
        mode="region",
        output_regs="eax,esp",
        scan_limit=256,
        timeout_ms=10000,
        region_max_blocks=128,
        normalize_globals=False,
        assume_paired_calls=False,
        out_dir=tmp_path,
    )
    with bc5_lane.adapter.installed(region=True):
        result = driver.compare(args)
    row = result["results"][0]
    assert row["status"] == expected, result
    if expected == "passed":
        assert row["proof_method"] == "checked_direct_call_composition"
        assert row["return_targets_proved"] == 2
    assert result["summary"]["total"] == 1


@pytest.mark.parametrize("track", ("msc8", "bc5"))
def test_adapter_uses_relocated_source_root(tmp_path: Path, track: str) -> None:
    """A frozen adapter must not redirect shared imports to the live checkout."""
    root = tmp_path / "snapshot"
    adapter = root / "artifacts" / DRIVER_DIRS[track].name / "flat32_adapter.py"
    adapter.parent.mkdir(parents=True)
    adapter.write_bytes((DRIVER_DIRS[track] / "flat32_adapter.py").read_bytes())
    for package in ("tools", "angr_platforms"):
        (root / package).symlink_to(REPO_ROOT / package, target_is_directory=True)
    probe = (
        "import runpy,sys; runpy.run_path(sys.argv[1]); "
        "assert sys.path[0] == sys.argv[2], repr(sys.path[:3])"
    )
    result = subprocess.run(
        [sys.executable, "-c", probe, str(adapter), str(root)],
        capture_output=True, text=True, check=False, timeout=60,
        env={**os.environ, "PYTHON_JIT": "1", "PYTHONHASHSEED": "0"},
    )
    assert result.returncode == 0, result.stderr
