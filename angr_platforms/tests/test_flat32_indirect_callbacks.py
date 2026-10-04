"""M5 staged controls: finite acyclic near-indirect callbacks in flat32 calls.

Layer: tests.
Responsibility: prove that a ``call r/m32`` whose destination is selected by
live caller state composes through the shared call-composition engine only
when the composed ``ip`` term is a finite ``ite`` selector whose leaves all
name declared function entries — and that every weakening (missing target,
unconstrained target, recursive edge, corrupt return frame, changed callee,
changed selector arm) either produces a real behavioral mismatch or a typed
refusal, through both public PE32 drivers (MSC8 and BC5).

"""


# driver modules are dynamically loaded, so Any annotations are inherent.

from __future__ import annotations

import struct
import sys
from argparse import Namespace
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import angr
import pytest


def _repo_root() -> Path:
    """Find the checkout root from either the live tree or the staged overlay."""
    here = Path(__file__).resolve()
    for parent in (here.parent, *here.parents):
        if (parent / "tools" / "dosunit" / "straightline_ssa.py").is_file():
            return parent
    raise RuntimeError(f"cannot locate repo root from {here}")


REPO_ROOT = _repo_root()
for _path in (str(REPO_ROOT), str(REPO_ROOT / "angr_platforms" / "tests")):
    if _path not in sys.path:
        sys.path.insert(0, _path)

import tools.dosunit  # noqa: F401  (parent package before staged children)
from tools.dosunit.flat32_call_composition import (
    compare_functions_with_calls,
    summarize_with_calls,
)
from tools.dosunit.flat32_call_contracts import CallCompositionLimits

DRIVER_DIRS: dict[str, Path] = {
    "msc8": REPO_ROOT / "artifacts" / "msc8-z3cmp32",
    "bc5": REPO_ROOT / "artifacts" / "bc5-z3cmp32",
}

# Top-level module names each driver dir provides; they collide across dirs
# and with anything already imported, so a lane swaps them atomically.
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
# monkey-patches; snapshot/restore is a dynamic seam boundary by design.
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

from tools.dosunit import straightline_ssa as S


@contextmanager
def _driver_lane(name: str) -> Iterator[Any]:
    """Install one driver dir's modules and restore every global it disturbs."""
    import importlib

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
        yield {"lane_name": name, **imported}
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
def lane(request: pytest.FixtureRequest) -> Iterator[dict[str, Any]]:
    """Run each driver test once under each staged driver's isolated modules."""
    with _driver_lane(str(request.param)) as imported:
        yield imported


# --------------------------------------------------------------------------
# Fixtures: input-selected callback dispatchers and their callees.
#
# cmov selector (one block):  ecx = A; edx = B; if ([esp+4]==0) ecx = edx
#   mov eax,[esp+4]; mov edx,B; mov ecx,A; test eax,eax; cmovz ecx,edx
#   call ecx; add eax,2; ret
# Branch selector (join block): both arms merge at a shared call site
#   mov eax,[esp+4]; test eax,eax; jz .else; mov ecx,A; jmp .join
#   .else: mov ecx,B; jmp .join; nop; .join: call ecx; add eax,2; ret
# --------------------------------------------------------------------------

BASE = 0x401000
CB_A = BASE + 0x40
CB_B = BASE + 0x50
CB_C = BASE + 0x60

def _imm32(address: int) -> str:
    """Little-endian hex for a ``mov r32,imm32`` immediate operand."""
    return address.to_bytes(4, "little").hex()


F_CMOV = (
    "8b442404"  # mov eax,[esp+4]
    + f"ba{_imm32(CB_B)}"  # mov edx,CB_B
    + f"b9{_imm32(CB_A)}"  # mov ecx,CB_A
    + "85c0"  # test eax,eax
    + "0f44ca"  # cmovz ecx,edx
    + "ffd1"  # call ecx
    + "83c002"  # add eax,2
    + "c3"  # ret
)

F_BRANCH = (
    "8b442404"  # mov eax,[esp+4]
    + "85c0"  # test eax,eax
    + "7407"  # jz .else(+0x0f)
    + f"b9{_imm32(CB_A)}"  # mov ecx,CB_A
    + "eb08"  # jmp .join(+0x17)
    + f"b9{_imm32(CB_B)}"  # .else: mov ecx,CB_B
    + "eb01"  # jmp .join(+0x17)
    + "90"  # nop
    + "ffd1"  # .join: call ecx
    + "83c002"  # add eax,2
    + "c3"  # ret
)

# Three-way nested selector: ecx = C; if (eax==0) ecx=A; if (edx==0) ecx=B
F_CMOV3 = (
    "8b442404"  # mov eax,[esp+4]
    + "8b542408"  # mov edx,[esp+8]
    + f"be{_imm32(CB_A)}"  # mov esi,CB_A
    + f"bf{_imm32(CB_B)}"  # mov edi,CB_B
    + f"b9{_imm32(CB_C)}"  # mov ecx,CB_C
    + "85c0"  # test eax,eax
    + "0f44ce"  # cmovz ecx,esi
    + "85d2"  # test edx,edx
    + "0f44cf"  # cmovz ecx,edi
    + "ffd1"  # call ecx
    + "83c002"  # add eax,2
    + "c3"  # ret
)

# Unconstrained target: the selector register is an input memory load.
F_LOAD = (
    "8b4c2404"  # mov ecx,[esp+4]
    + "ffd1"  # call ecx
    + "83c002"  # add eax,2
    + "c3"  # ret
)

CB_A_BODY = "83c005 c3"  # add eax,5; ret
CB_A_EQUIV = "8d4005 c3"  # lea eax,[eax+5]; ret
CB_B_BODY = "83c807 c3"  # or eax,7; ret
CB_B_CHANGED = "83c808 c3"  # or eax,8; ret
CB_B_CORRUPT = "c704242a000000 c3"  # mov dword [esp],0x2a; ret
CB_C_BODY = "83c803 c3"  # or eax,3; ret


def _hex(code: str) -> bytes:
    return bytes.fromhex(code.replace(" ", ""))


def _image(f: str, cb_a: str = CB_A_BODY, cb_b: str = CB_B_BODY, cb_c: str = CB_C_BODY) -> bytes:
    """Lay out caller + three callee slots at fixed offsets inside one image."""
    image = _hex(f).ljust(0x40, b"\x90")
    image += _hex(cb_a).ljust(0x10, b"\x90")
    image += _hex(cb_b).ljust(0x10, b"\x90")
    image += _hex(cb_c).ljust(0x10, b"\x90")
    return image


def _functions(f: str, cb_a: str = CB_A_BODY, cb_b: str = CB_B_BODY, cb_c: str = CB_C_BODY) -> dict[int, int]:
    return {
        BASE: len(_hex(f)),
        CB_A: len(_hex(cb_a)),
        CB_B: len(_hex(cb_b)),
        CB_C: len(_hex(cb_c)),
    }


def _project(image: bytes) -> angr.Project:
    """Load real i386 bytes as a flat shellcode project at the fixture base."""
    return angr.load_shellcode(image, arch="x86", load_address=BASE)


def _compare(
    adapter: Any,
    oracle_image: bytes,
    candidate_image: bytes,
    *,
    oracle_functions: dict[int, int],
    candidate_functions: dict[int, int],
    limits: CallCompositionLimits | None = None,
) -> dict[str, Any]:
    """Compose both sides under this driver's adapter seams and compare."""
    with adapter.installed(region=True):
        return compare_functions_with_calls(
            _project(oracle_image),
            _project(candidate_image),
            oracle_entry=BASE,
            candidate_entry=BASE,
            oracle_functions=oracle_functions,
            candidate_functions=candidate_functions,
            outputs=("eax", "ebx", "ecx", "edx", "esi", "edi", "esp"),
            timeout_ms=15000,
            limits=limits,
            oracle_labels={CB_A: "cb_a", CB_B: "cb_b", CB_C: "cb_c"},
            candidate_labels={CB_A: "cb_a", CB_B: "cb_b", CB_C: "cb_c"},
        )


def _indirect_sites(verdict: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        site
        for side in ("oracle", "candidate")
        for site in verdict["call_sites"][side]
        if site.get("indirect")
    ]


# --------------------------------------------------------------------------
# Unit-level controls through compare_functions_with_calls.
# --------------------------------------------------------------------------


def test_cmov_selector_two_targets_prove(lane: dict[str, Any]) -> None:
    """A cmov-selected callback proves with each target inlined and proved."""
    verdict = _compare(
        lane["flat32_adapter"], _image(F_CMOV), _image(F_CMOV),
        oracle_functions=_functions(F_CMOV), candidate_functions=_functions(F_CMOV),
    )
    assert verdict["status"] == "passed", verdict
    assert verdict["oracle_inlined_calls"] == 2
    assert verdict["candidate_inlined_calls"] == 2
    assert verdict["return_targets_proved"] == 4
    sites = _indirect_sites(verdict)
    assert {site["target"] for site in sites} == {hex(CB_A), hex(CB_B)}
    assert {site["arm"] for site in sites} == {1, 2}
    # The call site shares one block/callsite; the fallthrough is the byte
    # after ``call ecx`` (offset 0x13, two bytes).
    assert {site["fallthrough"] for site in sites} == {hex(BASE + 0x15)}


def test_branch_selector_two_targets_prove(lane: dict[str, Any]) -> None:
    """A branch-selected callback composes per path and merges full states."""
    verdict = _compare(
        lane["flat32_adapter"], _image(F_BRANCH), _image(F_BRANCH),
        oracle_functions=_functions(F_BRANCH), candidate_functions=_functions(F_BRANCH),
    )
    assert verdict["status"] == "passed", verdict
    sites = _indirect_sites(verdict)
    assert {site["target"] for site in sites} == {hex(CB_A), hex(CB_B)}


def test_nested_three_target_selector_proves(lane: dict[str, Any]) -> None:
    """A nested ite selector admits three leaves, each proved under its path."""
    functions = _functions(F_CMOV3)
    verdict = _compare(
        lane["flat32_adapter"], _image(F_CMOV3), _image(F_CMOV3),
        oracle_functions=functions, candidate_functions=functions,
    )
    assert verdict["status"] == "passed", verdict
    assert verdict["oracle_inlined_calls"] == 3
    sites = _indirect_sites(verdict)
    assert {site["target"] for site in sites} == {hex(CB_A), hex(CB_B), hex(CB_C)}
    assert {site["arm"] for site in sites} == {1, 2, 3}


def test_equivalent_edited_callback_passes(lane: dict[str, Any]) -> None:
    """An equivalent cb_a edit (lea vs add) keeps the composed proof."""
    functions = _functions(F_CMOV)
    verdict = _compare(
        lane["flat32_adapter"], _image(F_CMOV), _image(F_CMOV, cb_a=CB_A_EQUIV),
        oracle_functions=functions,
        candidate_functions=_functions(F_CMOV, cb_a=CB_A_EQUIV),
    )
    assert verdict["status"] == "passed", verdict


def test_changed_one_callee_effect_fails(lane: dict[str, Any]) -> None:
    """Changing only cb_b's effect produces a real mismatch, not a pass."""
    verdict = _compare(
        lane["flat32_adapter"], _image(F_CMOV), _image(F_CMOV, cb_b=CB_B_CHANGED),
        oracle_functions=_functions(F_CMOV),
        candidate_functions=_functions(F_CMOV, cb_b=CB_B_CHANGED),
    )
    assert verdict["status"] == "failed", verdict


def test_changed_one_selector_arm_fails(lane: dict[str, Any]) -> None:
    """Redirecting the cmov arm B->A changes behavior and must fail."""
    f_arm = F_CMOV.replace(f"ba{_imm32(CB_B)}", f"ba{_imm32(CB_A)}")
    verdict = _compare(
        lane["flat32_adapter"], _image(F_CMOV), _image(f_arm),
        oracle_functions=_functions(F_CMOV), candidate_functions=_functions(f_arm),
    )
    assert verdict["status"] == "failed", verdict


def test_omitted_feasible_target_refuses(lane: dict[str, Any]) -> None:
    """A reachable leaf missing from declared functions refuses, not drops."""
    candidate_functions = _functions(F_CMOV)
    del candidate_functions[CB_B]
    verdict = _compare(
        lane["flat32_adapter"], _image(F_CMOV), _image(F_CMOV),
        oracle_functions=_functions(F_CMOV), candidate_functions=candidate_functions,
    )
    assert verdict["status"] == "refused", verdict
    assert str(verdict["reason"]).startswith("call_target_unmapped")


def test_unconstrained_target_refuses(lane: dict[str, Any]) -> None:
    """A memory-loaded call target has no finite set and must refuse."""
    verdict = _compare(
        lane["flat32_adapter"], _image(F_LOAD), _image(F_LOAD),
        oracle_functions=_functions(F_LOAD), candidate_functions=_functions(F_LOAD),
    )
    assert verdict["status"] == "refused", verdict
    assert str(verdict["reason"]).startswith("call_indirect_target")


def test_recursive_callback_refuses(lane: dict[str, Any]) -> None:
    """A selector arm that calls the caller itself refuses as a cycle."""
    f_rec = F_CMOV.replace(f"ba{_imm32(CB_B)}", f"ba{_imm32(BASE)}")
    verdict = _compare(
        lane["flat32_adapter"], _image(f_rec), _image(f_rec),
        oracle_functions=_functions(f_rec), candidate_functions=_functions(f_rec),
    )
    assert verdict["status"] == "refused", verdict
    assert str(verdict["reason"]).startswith("recursive_call")


def test_corrupt_return_frame_refuses(lane: dict[str, Any]) -> None:
    """A callee overwriting its return slot refuses with selector evidence."""
    functions = _functions(F_CMOV, cb_b=CB_B_CORRUPT)
    verdict = _compare(
        lane["flat32_adapter"], _image(F_CMOV, cb_b=CB_B_CORRUPT),
        _image(F_CMOV, cb_b=CB_B_CORRUPT),
        oracle_functions=functions, candidate_functions=functions,
    )
    assert verdict["status"] == "refused", verdict
    assert str(verdict["reason"]).startswith("call_return_target_mismatch")
    failure = verdict.get("return_proof_failure")
    assert failure is not None, verdict
    assert failure["target"] == hex(CB_B)
    assert failure["selector"] is not None


def test_selector_leaf_bound_refuses(lane: dict[str, Any]) -> None:
    """The per-site leaf bound stays a typed refusal, never a silent pass."""
    functions = _functions(F_CMOV)
    limits = CallCompositionLimits(max_indirect_call_targets=1)
    verdict = _compare(
        lane["flat32_adapter"], _image(F_CMOV), _image(F_CMOV),
        oracle_functions=functions, candidate_functions=functions, limits=limits,
    )
    assert verdict["status"] == "refused", verdict
    assert verdict["reason"] == "call_indirect_target_limit"


def test_summarize_publishes_indirect_call_provenance(lane: dict[str, Any]) -> None:
    """The one-side summary carries typed indirect call-site evidence."""
    functions = _functions(F_CMOV)
    with lane["flat32_adapter"].installed(region=True):
        document = summarize_with_calls(
            _project(_image(F_CMOV)),
            entry=BASE,
            functions=functions,
            outputs=("eax",),
            labels={CB_A: "cb_a", CB_B: "cb_b", CB_C: "cb_c"},
        )
    sites = [site for site in document["call_sites"] if site.get("indirect")]
    assert len(sites) == 2
    assert {site["callee"] for site in sites} == {"cb_a", "cb_b"}
    # One block carries the selector and the call: block start is the
    # function entry; the callsite is the terminal ``call ecx`` IMark.
    assert {site["call_block"] for site in sites} == {hex(BASE)}
    assert {site["callsite"] for site in sites} == {hex(BASE + 0x13)}
    assert document["inlined_calls"] == 2
    assert document["return_targets_proved"] == 2


# --------------------------------------------------------------------------
# Driver-level controls: actual PE32 + lst through both public drivers.
# --------------------------------------------------------------------------

PE_IMAGE = 0x400000
PE_TEXT = PE_IMAGE + 0x1000


def _pe32(sections: list[tuple[bytes, int, int, int, int, bytes]]) -> bytes:
    """Minimal PE32: each ``(name, vsize, rva, rawptr, characteristics, data)``."""
    file = bytearray(0x600)
    file[:2] = b"MZ"
    struct.pack_into("<I", file, 0x3C, 0x80)
    file[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", file, 0x84, 0x14C, len(sections), 0, 0, 0, 0xE0, 0x102)
    opt = 0x98
    struct.pack_into("<H", file, opt, 0x10B)
    size_of_image = 0x1000 * (1 + len(sections))
    for offset, value in (
        (4, 0x200),
        (16, 0x1000),
        (20, 0x1000),
        (28, PE_IMAGE),
        (32, 0x1000),
        (36, 0x200),
        (56, size_of_image),
        (60, 0x200),
        (72, 0x100000),
        (76, 0x1000),
        (80, 0x100000),
        (84, 0x1000),
        (92, 16),
    ):
        struct.pack_into("<I", file, opt + offset, value)
    struct.pack_into("<H", file, opt + 68, 3)
    struct.pack_into("<H", file, opt + 70, 0x140)
    for index, (name, vsize, rva, rawptr, characteristics, data) in enumerate(sections):
        struct.pack_into(
            "<8sIIIIIIHHI",
            file,
            opt + 0xE0 + 40 * index,
            name,
            vsize,
            rva,
            len(data),
            rawptr,
            0,
            0,
            0,
            0,
            characteristics,
        )
        file[rawptr : rawptr + len(data)] = data
    return bytes(file)


def _lst_lines(functions: Mapping[str, tuple[int, int]]) -> str:
    """IDA-style .lst proc/endp lines for the declared function map."""
    lines = []
    for name, (start, last) in sorted(functions.items(), key=lambda item: item[1][0]):
        lines.append(f".text:{start:08x} {name} proc")
        lines.append(f".text:{last:08x} {name} endp")
    return "\n".join(lines) + "\n"


# PE32 fixture addresses: caller at section start, callees at fixed offsets.
PE_F = PE_TEXT
PE_A = PE_TEXT + 0x40
PE_B = PE_TEXT + 0x50
PE_C = PE_TEXT + 0x60

F_PE_CMOV = (
    "8b442404"
    + f"ba{_imm32(PE_B)}"
    + f"b9{_imm32(PE_A)}"
    + "85c0"
    + "0f44ca"
    + "ffd1"
    + "83c002"
    + "c3"
)


def _pe_fixture(
    f: str = F_PE_CMOV,
    cb_a: str = CB_A_BODY,
    cb_b: str = CB_B_BODY,
) -> tuple[bytes, dict[str, tuple[int, int]]]:
    """Build a real PE32 image plus the declared ``(start, last)`` boundaries."""
    body = _hex(f).ljust(0x40, b"\x90")
    body += _hex(cb_a).ljust(0x10, b"\x90")
    body += _hex(cb_b).ljust(0x10, b"\x90")
    body += b"\x90" * 0x10
    boundaries = {
        "f": (PE_F, PE_F + len(_hex(f)) - 1),
        "cb_a": (PE_A, PE_A + len(_hex(cb_a)) - 1),
        "cb_b": (PE_B, PE_B + len(_hex(cb_b)) - 1),
    }
    pe = _pe32([(b".text", len(body), 0x1000, 0x200, 0x60000020, body)])
    return pe, boundaries


def _write_driver_inputs(
    tmp_path: Path,
    oracle: tuple[bytes, dict[str, tuple[int, int]]],
    candidate: tuple[bytes, dict[str, tuple[int, int]]],
) -> tuple[Path, Path, Path, Path]:
    oracle_exe = tmp_path / "oracle.exe"
    candidate_exe = tmp_path / "candidate.exe"
    oracle_lst = tmp_path / "oracle.lst"
    candidate_lst = tmp_path / "candidate.lst"
    oracle_exe.write_bytes(oracle[0])
    candidate_exe.write_bytes(candidate[0])
    oracle_lst.write_text(_lst_lines(oracle[1]))
    candidate_lst.write_text(_lst_lines(candidate[1]))
    return oracle_exe, candidate_exe, oracle_lst, candidate_lst


def _driver_args(
    tmp_path: Path,
    oracle_exe: Path,
    candidate_exe: Path,
    oracle_lst: Path,
    candidate_lst: Path,
) -> Namespace:
    (tmp_path / "out").mkdir(exist_ok=True)
    (tmp_path / "cache").mkdir(exist_ok=True)
    return Namespace(
        oracle_exe=oracle_exe,
        candidate_exe=candidate_exe,
        oracle_lst=oracle_lst,
        candidate_lst=candidate_lst,
        candidate_syms=None,
        cache_dir=tmp_path / "cache",
        functions="f",
        mode="region",
        output_regs="eax,edx,esp",
        scan_limit=0x2000,
        timeout_ms=15000,
        region_max_blocks=128,
        normalize_globals=False,
        assume_paired_calls=False,
        out_dir=tmp_path / "out",
    )


def _run_driver(
    modules: dict[str, Any],
    tmp_path: Path,
    oracle: tuple[bytes, dict[str, tuple[int, int]]],
    candidate: tuple[bytes, dict[str, tuple[int, int]]],
    monkeypatch: pytest.MonkeyPatch,
) -> dict[str, Any]:
    """Write real PE32/lst inputs and run the public driver compare."""
    oracle_exe, candidate_exe, oracle_lst, candidate_lst = _write_driver_inputs(
        tmp_path, oracle, candidate
    )
    driver = modules["z3cmp32"]
    # nm on a symbol-less hand-built PE yields nothing usable; keep the
    # function map lst-derived so the run does not depend on system binutils.
    monkeypatch.setattr(driver, "nm_symbols", lambda _path: {})
    args = _driver_args(tmp_path, oracle_exe, candidate_exe, oracle_lst, candidate_lst)
    with modules["flat32_adapter"].installed(region=True):
        return driver.compare(args)


def test_driver_pe32_indirect_callbacks_prove(
    lane: dict[str, Any], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Both public drivers prove a PE32 caller through a cmov callback pair."""
    report = _run_driver(lane, tmp_path, _pe_fixture(), _pe_fixture(), monkeypatch)
    assert report["summary"]["total"] == 1
    row = report["results"][0]
    assert row["status"] == "passed", row
    assert row["proof_method"] == "checked_direct_call_composition"
    assert row["return_targets_proved"] == 4
    sites = _indirect_sites(row) if "call_sites" in row else []
    if sites:
        assert {site["target"] for site in sites} == {hex(PE_A), hex(PE_B)}


def test_driver_pe32_changed_callee_fails(
    lane: dict[str, Any], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Stale callee bytes under an identical caller must fail, not pass."""
    report = _run_driver(
        lane, tmp_path, _pe_fixture(), _pe_fixture(cb_b=CB_B_CHANGED), monkeypatch
    )
    row = report["results"][0]
    assert row["status"] == "failed", row


def _calls_attempt(row: dict[str, Any]) -> dict[str, Any]:
    """The nested checked-call-composition verdict the driver retry retained."""
    attempts = row.get("additional_proof_attempts") or {}
    calls = attempts.get("calls")
    assert isinstance(calls, dict), row
    return calls


def test_driver_pe32_omitted_target_refuses(
    lane: dict[str, Any], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A feasible callee dropped from both lst maps refuses the mapping."""
    oracle_pe, oracle_bounds = _pe_fixture()
    candidate_pe, candidate_bounds = _pe_fixture()
    del oracle_bounds["cb_b"]
    del candidate_bounds["cb_b"]
    report = _run_driver(
        lane, tmp_path,
        (oracle_pe, oracle_bounds), (candidate_pe, candidate_bounds), monkeypatch,
    )
    row = report["results"][0]
    assert row["status"] == "refused", row
    assert str(_calls_attempt(row)["reason"]).startswith("call_target_unmapped")


def test_driver_pe32_corrupt_frame_refuses(
    lane: dict[str, Any], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A callee that corrupts its return slot refuses through both drivers."""
    oracle_pe, oracle_bounds = _pe_fixture(cb_b=CB_B_CORRUPT)
    candidate_pe, candidate_bounds = _pe_fixture(cb_b=CB_B_CORRUPT)
    report = _run_driver(
        lane, tmp_path,
        (oracle_pe, oracle_bounds), (candidate_pe, candidate_bounds), monkeypatch,
    )
    row = report["results"][0]
    assert row["status"] == "refused", row
    assert str(_calls_attempt(row)["reason"]).startswith("call_return_target")
