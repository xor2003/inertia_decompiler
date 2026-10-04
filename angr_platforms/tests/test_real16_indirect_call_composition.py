"""Focused real16 bounded finite indirect-call regressions on actual MZ bytes.

Each fixture lowers real machine code to fresh full-state SSA documents and
exercises ``compare_real16_with_calls`` plus the public ``compare_binary16``
driver.  The caller builds a real-mode far pointer on its own stack (or in DS
data) and issues ``lcall [bp]``; the composed ``control_ip`` term is symbolic,
so admission requires the solver to close the target relation over every
admitted CS alias — metadata alone never admits a target.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.append(str(Path(__file__).resolve().parent))

from test_dosunit_tool import _edge_function, _mz_exe
from test_real16_call_composition import _lower

import tools.dosunit.real16_call_indirect as real16_call_indirect
from tools.dosunit.real16_binary_compare import compare_binary16
from tools.dosunit.real16_call_composition import compare_real16_with_calls
from tools.dosunit.real16_call_contracts import Real16CallLimits

# _load_lifter_project uses linear base_addr=0x1000, hence selector 0x0100.
# Captured native function entries independently confirm base + image offset.
IMAGE_LOAD_BASE = 0x1000
LOAD_SELECTOR = IMAGE_LOAD_BASE >> 4
CALLER = 0x200
CALLEE = 0x240
CALLEE2 = 0x340


def _lcall_bp_caller(seg: int, off: int, *, tail: bytes = b"\xc3") -> bytes:
    """push seg; push off; mov bp,sp; lcall [bp]; ret — symbolic far target."""
    body = bytes(
        [0x68, seg & 0xFF, (seg >> 8) & 0xFF, 0x68, off & 0xFF, (off >> 8) & 0xFF,
         0x89, 0xE5, 0xFF, 0x5E, 0x00]
    ) + tail
    assert len(body) <= 0x10, "fallthrough must stay inside the entry-alias window"
    image = bytearray(0x400)
    image[CALLER : CALLER + len(body)] = body
    return bytes(image)


def _unconstrained_caller() -> bytes:
    """lcall [0x500]; ret — far pointer read straight from DS inputs."""
    image = bytearray(0x400)
    image[CALLER : CALLER + 5] = bytes.fromhex("ff1e0005c3")
    return bytes(image)


def _image(caller: bytes, bodies: dict[int, bytes]) -> bytes:
    image = bytearray(caller)
    for offset, body in bodies.items():
        image[offset : offset + len(body)] = body
    return bytes(image)


def _catalog(*, callee_body: bytes = bytes.fromhex("bb0100cb"),
             callee_size: int | None = None, caller_size: int | None = None,
             omit_callee: bool = False, second_callee: bool = False) -> list[dict[str, object]]:
    size = callee_size if callee_size is not None else len(callee_body)
    functions: list[dict[str, object]] = [
        _edge_function("demo.exe:caller", "caller", offset=CALLER,
                       size=caller_size if caller_size is not None else 12),
    ]
    if not omit_callee:
        functions.append(
            _edge_function("demo.exe:callee", "callee", offset=CALLEE, size=size)
        )
    if second_callee:
        functions.append(
            _edge_function("demo.exe:callee2", "callee2", offset=CALLEE2, size=4)
        )
    return functions


def _lower_pair(
    tmp_path: Path,
    oracle_caller: bytes,
    candidate_caller: bytes,
    oracle_bodies: dict[int, bytes],
    candidate_bodies: dict[int, bytes],
    oracle_catalog: list[dict[str, object]],
    candidate_catalog: list[dict[str, object]],
) -> tuple[dict, dict]:
    oracle = _lower(
        tmp_path, _image(oracle_caller, oracle_bodies), oracle_catalog, "oracle"
    )
    candidate = _lower(
        tmp_path, _image(candidate_caller, candidate_bodies), candidate_catalog,
        "candidate",
    )
    return oracle, candidate


def _default_pair(
    tmp_path: Path, *, callee_body: bytes = bytes.fromhex("bb0100cb"),
    candidate_callee_body: bytes | None = None,
    candidate_seg: int = LOAD_SELECTOR, candidate_off: int = CALLEE,
    candidate_catalog: list[dict[str, object]] | None = None,
    candidate_bodies: dict[int, bytes] | None = None,
) -> tuple[dict, dict]:
    oracle_caller = _lcall_bp_caller(LOAD_SELECTOR, CALLEE)
    candidate_caller = _lcall_bp_caller(candidate_seg, candidate_off)
    oracle_bodies = {CALLEE: callee_body}
    bodies = dict(candidate_bodies) if candidate_bodies is not None else {
        CALLEE: candidate_callee_body if candidate_callee_body is not None else callee_body
    }
    return _lower_pair(
        tmp_path, oracle_caller, candidate_caller, oracle_bodies, bodies,
        _catalog(callee_body=callee_body),
        candidate_catalog if candidate_catalog is not None else _catalog(
            callee_body=bodies.get(CALLEE, callee_body)
        ),
    )


def test_far16_indirect_call_self_passes(tmp_path: Path) -> None:
    """Identical far-indirect callers prove through the real callee body."""
    oracle, candidate = _default_pair(tmp_path)
    result = compare_real16_with_calls(
        oracle, candidate, "demo.exe:caller", timeout_ms=20000
    )
    assert result["status"] == "passed", result
    assert result["calls"]["indirect_call_sites"] == 2
    assert result["calls"]["indirect_targets_proved"] == 2
    assert result["calls"]["return_targets_proved"] == 2
    assert result["calls"]["cs_preserved_proved"] == 2
    callees = {item["function"] for item in result["dependencies"][0]["callees"]}
    assert "demo.exe:callee" in callees, result["dependencies"]


def test_far16_indirect_call_public_obligation(tmp_path: Path) -> None:
    """The public compare_binary16 driver proves the complete obligation."""
    image = _image(_lcall_bp_caller(LOAD_SELECTOR, CALLEE), {CALLEE: bytes.fromhex("bb0100cb")})
    oracle, candidate = tmp_path / "oracle.exe", tmp_path / "candidate.exe"
    oracle.write_bytes(_mz_exe(image))
    candidate.write_bytes(_mz_exe(image))
    catalog = {
        "schema": "dosunit.functions.v1", "id": "functions:test", "module": "demo.exe",
        "program_kind": "mz_exe", "functions": _catalog(), "diagnostics": [],
    }
    report = compare_binary16(oracle, candidate, catalog, catalog, selected=("caller",))
    assert report["status"] == "proved", {"proof": report["proof"], "backend": report["backend"]}
    verdict = report["proof"]["verdicts"][0]
    assert verdict["method"] == "ssa_z3_complete_call_inlining"
    calls = report["backend"]["direct_calls"]["demo.exe:caller"]
    assert calls["calls"]["indirect_call_sites"] == 2


def test_changed_far_selector_pointer_is_observable(tmp_path: Path) -> None:
    """Equal callee linears do not erase changed pointer memory or caller RET."""
    oracle, candidate = _default_pair(tmp_path, candidate_seg=(IMAGE_LOAD_BASE + CALLEE) >> 4, candidate_off=0x0000)
    result = compare_real16_with_calls(
        oracle, candidate, "demo.exe:caller", timeout_ms=20000
    )
    assert result["status"] == "failed", result
    assert any(item.get("reg") == "control_ip" for item in result["mismatches"]), result


def test_equivalent_changed_callee_encoding_passes(tmp_path: Path) -> None:
    """A differently-encoded callee with equal effects still proves."""
    oracle, candidate = _default_pair(
        tmp_path, candidate_callee_body=bytes.fromhex("c7c30100cb")  # mov bx,1 via C7 /0; retf
    )
    result = compare_real16_with_calls(
        oracle, candidate, "demo.exe:caller", timeout_ms=20000
    )
    assert result["status"] == "passed", result


def test_changed_callee_flags_is_counterexample(tmp_path: Path) -> None:
    """Equal BX values do not hide flags changed by XOR/INC versus MOV."""
    oracle, candidate = _default_pair(
        tmp_path, candidate_callee_body=bytes.fromhex("33db43cb")
    )
    result = compare_real16_with_calls(
        oracle, candidate, "demo.exe:caller", timeout_ms=20000
    )
    assert result["status"] == "failed", result
    assert any(item.get("reg") == "flags" for item in result["mismatches"]), result


def test_changed_target_arm_is_counterexample(tmp_path: Path) -> None:
    """A candidate selector reaching a different callee cannot pass."""
    oracle, candidate = _default_pair(
        tmp_path,
        candidate_seg=LOAD_SELECTOR + ((CALLEE2 - CALLEE) >> 4),
        candidate_bodies={CALLEE: bytes.fromhex("bb0100cb"), CALLEE2: bytes.fromhex("bb0200cb")},
        candidate_catalog=_catalog(second_callee=True),
    )
    result = compare_real16_with_calls(
        oracle, candidate, "demo.exe:caller", timeout_ms=20000
    )
    assert result["status"] == "failed", result


def test_missing_target_refuses(tmp_path: Path) -> None:
    """A target outside the admitted callee set refuses to close coverage."""
    oracle, candidate = _default_pair(
        tmp_path,
        candidate_catalog=_catalog(omit_callee=True),
    )
    result = compare_real16_with_calls(
        oracle, candidate, "demo.exe:caller", timeout_ms=20000
    )
    assert result["status"] == "refused", result
    assert result["reason"] in {"call_target_unresolved", "call_target_unmapped"}, result


def test_public_missing_target_is_not_proved(tmp_path: Path) -> None:
    """The public driver cannot discharge an obligation with no callee."""
    oracle_image = _image(
        _lcall_bp_caller(LOAD_SELECTOR, CALLEE), {CALLEE: bytes.fromhex("bb0100cb")}
    )
    oracle, candidate = tmp_path / "oracle.exe", tmp_path / "candidate.exe"
    oracle.write_bytes(_mz_exe(oracle_image))
    candidate.write_bytes(_mz_exe(oracle_image))
    oracle_catalog = {
        "schema": "dosunit.functions.v1", "id": "functions:test", "module": "demo.exe",
        "program_kind": "mz_exe", "functions": _catalog(), "diagnostics": [],
    }
    candidate_catalog = {
        **oracle_catalog, "functions": _catalog(omit_callee=True),
    }
    report = compare_binary16(
        oracle, candidate, oracle_catalog, candidate_catalog, selected=("caller",)
    )
    assert report["status"] != "proved", report["proof"]


def test_unconstrained_target_refuses(tmp_path: Path) -> None:
    """A far pointer read from raw input memory never closes coverage."""
    oracle = _lower(
        tmp_path, _unconstrained_caller(), _catalog(omit_callee=True, caller_size=5), "oracle"
    )
    image = _image(_lcall_bp_caller(LOAD_SELECTOR, CALLEE), {CALLEE: bytes.fromhex("bb0100cb")})
    candidate = _lower(tmp_path, image, _catalog(), "candidate")
    result = compare_real16_with_calls(
        oracle, candidate, "demo.exe:caller", timeout_ms=20000
    )
    assert result["status"] == "refused", result
    assert result["reason"] in {"call_target_unresolved", "call_target_unmapped"}, result


def test_callee_store_may_alias_return_frame_refuses(tmp_path: Path) -> None:
    """Unconstrained DS:[0600] can alias SS return memory, so RETF is unproved."""
    oracle, candidate = _default_pair(
        tmp_path,
        candidate_callee_body=bytes.fromhex("c70600060100bb0100cb"),  # mov [0x600],1; mov bx,1; retf
        candidate_catalog=_catalog(callee_body=bytes.fromhex("c70600060100bb0100cb")),
        candidate_bodies={CALLEE: bytes.fromhex("c70600060100bb0100cb")},
    )
    result = compare_real16_with_calls(
        oracle, candidate, "demo.exe:caller", timeout_ms=20000
    )
    assert result["status"] == "refused", result
    assert result["reason"] == "return_target_unproved", result


def test_changed_callee_memory_effect_is_counterexample(tmp_path: Path) -> None:
    """SS:[BP+2] is pointer scratch above the RETF frame below BP."""
    # The caller leaves BP at its pushed pointer. RETF consumes BP-4/BP-2;
    # its later near RET consumes BP. Only the unused selector at BP+2 changes.
    body = bytes.fromhex("c746020100bb0100cb")  # mov word [bp+2],1; mov bx,1; retf
    oracle, candidate = _default_pair(tmp_path, candidate_callee_body=body)
    result = compare_real16_with_calls(
        oracle, candidate, "demo.exe:caller", timeout_ms=20000
    )
    assert result["status"] == "failed", result
    assert result["calls"]["return_targets_proved"] == 2, result
    assert any(item.get("reg") == "memory" for item in result["mismatches"]), result


def test_changed_callee_register_effect_is_counterexample(tmp_path: Path) -> None:
    """bx=2 instead of bx=1 rejects the pair."""
    oracle, candidate = _default_pair(
        tmp_path, candidate_callee_body=bytes.fromhex("bb0200cb")
    )
    result = compare_real16_with_calls(
        oracle, candidate, "demo.exe:caller", timeout_ms=20000
    )
    assert result["status"] == "failed", result


@pytest.mark.parametrize(
    "callee_body",
    [
        bytes.fromhex("bb0100c3"),       # near RET cannot restore a far frame
        bytes.fromhex("bb0100ca0200"),   # RETF 2 leaves an unbalanced frame
    ],
)
def test_corrupt_far_return_frame_refuses_or_fails(tmp_path: Path, callee_body: bytes) -> None:
    """A callee that does not restore the actual far frame cannot pass."""
    oracle, candidate = _default_pair(tmp_path, candidate_callee_body=callee_body)
    result = compare_real16_with_calls(
        oracle, candidate, "demo.exe:caller", timeout_ms=20000
    )
    assert result["status"] != "passed", result


def test_near_indirect_call_refuses(tmp_path: Path) -> None:
    """call ax cannot close a finite target set across the CS alias interval."""
    image = bytearray(0x400)
    image[CALLER : CALLER + 6] = bytes.fromhex("bb4002ffd0c3")  # mov bx,0x240; call bx; ret
    image[CALLEE : CALLEE + 4] = bytes.fromhex("bb0100c3")
    oracle = _lower(tmp_path, bytes(image), _catalog(caller_size=6), "oracle")
    candidate = _lower(tmp_path, bytes(image), _catalog(caller_size=6), "candidate")
    result = compare_real16_with_calls(
        oracle, candidate, "demo.exe:caller", timeout_ms=20000
    )
    assert result["status"] == "refused", result
    assert result["reason"] == "call_target_unresolved", result


def test_stale_callee_bytes_refuse(tmp_path: Path) -> None:
    """A catalog range that truncates the real callee body refuses."""
    oracle, candidate = _default_pair(
        tmp_path, candidate_catalog=_catalog(callee_size=2)
    )
    result = compare_real16_with_calls(
        oracle, candidate, "demo.exe:caller", timeout_ms=20000
    )
    assert result["status"] == "refused", result
    assert result["reason"] in {
        "function_range_incomplete", "lowering_refusals_present",
        "call_target_unmapped",
    }, result


def test_indirect_recursion_refuses(tmp_path: Path) -> None:
    """A proved target equal to the caller entry refuses as a cycle."""
    oracle, candidate = _default_pair(
        tmp_path, candidate_seg=LOAD_SELECTOR, candidate_off=CALLER
    )
    result = compare_real16_with_calls(
        oracle, candidate, "demo.exe:caller", timeout_ms=20000
    )
    assert result["status"] == "refused", result
    assert result["reason"] == "recursive_call_cycle", result


def test_indirect_target_cap_refuses(tmp_path: Path) -> None:
    """A zero finite-target cap refuses even a provably single target."""
    oracle, candidate = _default_pair(tmp_path)
    result = compare_real16_with_calls(
        oracle, candidate, "demo.exe:caller", timeout_ms=20000,
        limits=Real16CallLimits(max_indirect_call_targets=0),
    )
    assert result["status"] == "refused", result
    assert result["reason"] == "compose_budget_exceeded", result
    assert result["detail"]["counter"] == "indirect_call_targets", result


def test_indirect_target_cap_boundary_admits_exact_fit(tmp_path: Path) -> None:
    """The live-target cap is inclusive: one proved arm under a cap of one."""
    oracle, candidate = _default_pair(tmp_path)
    result = compare_real16_with_calls(
        oracle, candidate, "demo.exe:caller", timeout_ms=20000,
        limits=Real16CallLimits(max_indirect_call_targets=1),
    )
    assert result["status"] == "passed", result
    assert result["calls"]["indirect_targets_proved"] == 2


def test_candidate_cap_boundary_admits_exact_fit(tmp_path: Path) -> None:
    """A catalog at exactly the candidate bound still admits the selector."""
    oracle, candidate = _default_pair(tmp_path)
    result = compare_real16_with_calls(
        oracle, candidate, "demo.exe:caller", timeout_ms=20000,
        limits=Real16CallLimits(max_indirect_call_candidates=2),
    )
    assert result["status"] == "passed", result
    assert result["calls"]["indirect_call_sites"] == 2


def test_oversized_catalog_refuses_before_solver(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A catalog above the candidate bound refuses before any solving.

    The bound is enforced while the entry index is discovered — before
    sorting, membership-term construction, and ``prove_terms_equal`` — so the
    refusal precedes every solver query in the indirect path rather than
    merely bounding the live-arm count after coverage work.
    """
    solver_calls: list[tuple] = []
    real_prove = real16_call_indirect.prove_terms_equal

    def _spy(*args: object, **kwargs: object) -> object:
        solver_calls.append(args)
        return real_prove(*args, **kwargs)

    monkeypatch.setattr(real16_call_indirect, "prove_terms_equal", _spy)
    oracle = _lower(
        tmp_path,
        _image(
            _lcall_bp_caller(LOAD_SELECTOR, CALLEE),
            {CALLEE: bytes.fromhex("bb0100cb"), 0x380: b"\xc3"},
        ),
        [*(_catalog()), _edge_function("demo.exe:pad", "pad", offset=0x380, size=1)],
        "oracle",
    )
    _, candidate = _default_pair(tmp_path)
    result = compare_real16_with_calls(
        oracle, candidate, "demo.exe:caller", timeout_ms=20000,
        limits=Real16CallLimits(max_indirect_call_candidates=2),
    )
    assert result["status"] == "refused", result
    assert result["reason"] == "compose_budget_exceeded", result
    assert result["detail"]["counter"] == "indirect_call_candidates", result
    assert solver_calls == [], "refusal must precede indirect-path solver use"


def test_inlined_call_budget_refuses(tmp_path: Path) -> None:
    """The shared inlined-call budget still bounds indirect composition."""
    oracle, candidate = _default_pair(tmp_path)
    result = compare_real16_with_calls(
        oracle, candidate, "demo.exe:caller", timeout_ms=20000,
        limits=Real16CallLimits(max_inlined_calls=0),
    )
    assert result["status"] == "refused", result
    assert result["reason"] == "compose_budget_exceeded", result
