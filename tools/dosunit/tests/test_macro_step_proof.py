"""Staged macro-step regression: original M4 unroll-2 family on both widths.

Layer: staged tests.
Responsibility: run the staged finite-frontier macro-step proof over the real
intake bytes — real16 MZ through the production ``_document`` lowering and
flat32 real-byte/PE lanes through both ``_driver_lane`` drivers — with the
required baseline-red, positive-green, semantic-negative, corrupt-coverage/
endpoint, budget and neighboring-baseline controls. No test here claims a
production function fix or a whole-program equivalence.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import angr
import pytest
from tools.dosunit.tests.test_dosunit_tool import _edge_function
from tools.dosunit.tests.test_flat32_comparator_lane import DriverLane, _driver_lane
from tools.dosunit.tests.test_flat32_loaded_byte_boundaries import pe32_bytes
from tools.dosunit.tests.test_real16_call_composition import _lower

from tools.dosunit.compare.flat32_macro_proof import compare_macro_cfg
from tools.dosunit.compare.macro_step_contracts import (
    MacroDirection,
    MacroEndpointKind,
    MacroStepLimits,
    MacroStepProof,
    MacroStepReason,
    MacroStepRefusal,
)
from tools.dosunit.compare.macro_step_pairing import propose_macro_steps
from tools.dosunit.compare.paired_region_graph import RegionExitKind, RegionNode
from tools.dosunit.contracts.proof_contracts import ProofStatus
from tools.dosunit.contracts.proof_scope import ProofScope
from tools.dosunit.compare.real16_call_contracts import Real16CallLimits, prove_terms_equal
from tools.dosunit.compare.real16_macro_proof import compare_real16_macro
from tools.dosunit.compare.real16_region_proof import compare_real16_regions
from tools.dosunit.ssa.region_path_terms import endpoint_consistency_term, guard_true

# jcxz ret / lea bx,[bx+1]; dec cx; jmp body / ret
ORACLE16 = bytes.fromhex("e3068d5f0149ebf8c3")
# same loop unrolled by two with an intermediate zero guard
CANDIDATE16 = bytes.fromhex("e30c8d5f0149e3068d5f0149ebf2c3")
ZERO16 = bytes.fromhex("8d5f0149e3068d5f0149ebf4c3")
ODD16 = bytes.fromhex("e30a8d5f01498d5f0149ebf4c3")
STRIDE16 = bytes.fromhex("e30c8d5f0149e3068d5f0249ebf2c3")  # lea bx,[bx+2]
DIRECTION16 = bytes.fromhex("e30c8d5f0149e3068d5fff49ebf2c3")  # lea bx,[bx-1]
SIGNED16 = bytes.fromhex("e30c8d5f0149e30678088d5f0149ebf2c3")  # js guard mid
SUBREG16 = bytes.fromhex("e30d8d5f0149e3078d5f01fec9ebf1c3")  # dec cl not dec cx
STORE16 = bytes.fromhex("e30f8d5f0149e3098d5f0149895e04ebefc3")  # mov [bp+4],bx
RETCLEAN16 = bytes.fromhex("e30c8d5f0149e3068d5f0149ebf2c20200")  # ret 2
STUTTER16 = bytes.fromhex("e30c8d5f0149e3068d5f0149ebf8c3")  # back-edge to mid

LOOP16 = bytes.fromhex("85c074064889460475fa c3".replace(" ", ""))
SPLIT16 = bytes.fromhex("85c0740848eb0089460475f8 c3".replace(" ", ""))

# jecxz ret / lea ebx,[ebx+1]; lea ecx,[ecx-1]; jmp body / ret
ORACLE32 = bytes.fromhex("e3088d5b018d49ffebf6c3")
CANDIDATE32 = bytes.fromhex("e3108d5b018d49ffe3088d5b018d49ffebeec3")
ZERO32 = bytes.fromhex("8d5b018d49ffe3088d5b018d49ffebf0c3")
ODD32 = bytes.fromhex("e30e8d5b018d49ff8d5b018d49ffebf0c3")
STRIDE32 = bytes.fromhex("e3108d5b018d49fee3088d5b018d49feebeec3")
DIRECTION32 = bytes.fromhex("e3108d5b018d4901e3088d5b018d4901ebeec3")
SIGNED32 = bytes.fromhex("e3108d5b018d49ffe308780b8d5b018d49ffebeec3")  # js
SUBREG32 = bytes.fromhex("e3108d5b01fec990e3088d5b01fec990ebeec3")  # dec cl
STORE32 = bytes.fromhex("e3108d5b018d49ffe308895dfc8d49ffebeec3")  # mov [ebp-4],ebx
RETCLEAN32 = bytes.fromhex("e3108d5b018d49ffe3088d5b018d49ffebeec20400")  # ret 4
FLAGRET32 = bytes.fromhex("e3108d5b018d49ffe3088d5b018d49ffebeef9c3")  # stc;ret
STUTTER32 = bytes.fromhex("e3108d5b018d49ffe3088d5b018d49ffebf8c3")

LOOP32 = bytes.fromhex("85c07407488944240475f9 c3".replace(" ", ""))
CHAIN32 = bytes.fromhex("85c0740948eb008944240475f7 c3".replace(" ", ""))

ORACLE_BASE = 0x12345000
CANDIDATE_BASE = 0x23456000
PE_BASE = 0x401000
TIMEOUT = 60000


def _document16(tmp_path: Path, code: bytes, tag: str) -> dict:
    """Lower one MZ image with the same catalog the production rows use."""
    image = bytearray(0x300)
    image[0x200:0x200 + len(code)] = code
    return _lower(tmp_path, bytes(image), [
        _edge_function("demo.exe:loop", "loop", offset=0x200, size=len(code)),
    ], tag)


def _macro16(
    tmp_path: Path, oracle: bytes, candidate: bytes, *, timeout_ms: int = TIMEOUT,
    macro_limits: MacroStepLimits | None = None, limits: Real16CallLimits | None = None,
) -> MacroStepProof:
    """Compare two real16 MZ documents through the staged macro-step proof."""
    left = _document16(tmp_path, oracle, "oracle")
    right = _document16(tmp_path, candidate, "candidate")
    return compare_real16_macro(left, right, "demo.exe:loop", timeout_ms=timeout_ms,
                                macro_limits=macro_limits, limits=limits)


def _flat_projects(oracle_code: bytes, candidate_code: bytes) -> tuple[angr.Project, angr.Project]:
    """Shellcode projects at distinct physical bases like the lane tests."""
    import angr

    return (
        angr.load_shellcode(oracle_code, arch="x86", load_address=ORACLE_BASE),
        angr.load_shellcode(candidate_code, arch="x86", load_address=CANDIDATE_BASE),
    )


def _macro32(
    lane: DriverLane, oracle_code: bytes, candidate_code: bytes, *,
    macro_limits: MacroStepLimits | None = None,
) -> dict[str, Any]:
    """Run the staged flat32 macro proof under one installed driver lane."""
    projects = _flat_projects(oracle_code, candidate_code)
    return compare_macro_cfg(
        projects,
        (ORACLE_BASE, len(oracle_code)),
        (CANDIDATE_BASE, len(candidate_code)),
        lane.adapter.OUTPUT_REGS, TIMEOUT, macro_limits=macro_limits,
    )


def _pe_projects(
    tmp_path: Path, lane: DriverLane, oracle_code: bytes, candidate_code: bytes,
) -> tuple[angr.Project, angr.Project]:
    """Actual PE32 images loaded through the driver's native loader."""
    oracle_path = tmp_path / "oracle.exe"
    candidate_path = tmp_path / "candidate.exe"
    oracle_path.write_bytes(pe32_bytes(oracle_code))
    candidate_path.write_bytes(pe32_bytes(candidate_code))
    return lane.adapter.load32(oracle_path), lane.adapter.load32(candidate_path)


@pytest.mark.parametrize("driver", ["msc8", "bc5"])
def test_flat32_baseline_region_proof_is_bijective_refusal(driver: str) -> None:
    """Baseline red: row-level pairing refuses the unequal-step family."""
    from tools.dosunit.compare.flat32_cfg_regions import compare_reblocked_cfg

    with _driver_lane(driver) as lane:
        projects = _flat_projects(ORACLE32, CANDIDATE32)
        result = compare_reblocked_cfg(
            projects, (ORACLE_BASE, len(ORACLE32)),
            (CANDIDATE_BASE, len(CANDIDATE32)), lane.adapter.OUTPUT_REGS, TIMEOUT,
        )
        assert result["status"] is lane.verdict.Status.REFUSED
        assert result["reason"] == "cfg_not_bijective"


def test_real16_baseline_region_proof_is_unknown(tmp_path: Path) -> None:
    """Baseline red: real16 row pairing cannot cover the unrolled candidate."""
    left = _document16(tmp_path, ORACLE16, "oracle")
    right = _document16(tmp_path, CANDIDATE16, "candidate")
    baseline = compare_real16_regions(left, right, "demo.exe:loop", timeout_ms=TIMEOUT)
    assert baseline.status is ProofStatus.UNKNOWN


def test_real16_original_unroll2_proves(tmp_path: Path) -> None:
    """Green: original intake MZ candidate proves as 1-to-2 macro-transitions."""
    proof = _macro16(tmp_path, ORACLE16, CANDIDATE16, timeout_ms=TIMEOUT)
    assert proof.status is ProofStatus.PROVED, proof
    assert proof.proof_scope == ProofScope.CUTPOINT_SIMULATION.value
    assert proof.direction is not None
    assert proof.counters.materialized_count > 0
    assert proof.counters.failure_count == 0
    rows = proof.transitions
    assert any(row.oracle_segments != row.candidate_segments for row in rows)
    assert all(row.oracle_members and row.candidate_members for row in rows)


@pytest.mark.parametrize("driver", ["msc8", "bc5"])
def test_flat32_original_unroll2_proves(driver: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """Both drivers prove unequal-step induction without mutable installation."""
    with _driver_lane(driver) as lane:
        def forbidden(*args: object, **kwargs: object) -> None:
            pytest.fail("macro induction installed mutable adapter state")

        monkeypatch.setattr(lane.adapter, "installed", forbidden)
        result = _macro32(lane, ORACLE32, CANDIDATE32)
        assert result["status"] is lane.verdict.Status.PASSED, result
        assert result["proof_scope"] is ProofScope.CUTPOINT_SIMULATION
        assert result["reason"] == "macro_step_cfg_induction"
        assert result["counters"]["materialized_count"] > 0


@pytest.mark.parametrize("driver", ["msc8", "bc5"])
def test_flat32_actual_pe_images_prove(driver: str, tmp_path: Path) -> None:
    """Green: the same family through real PE32 bytes and native load32."""
    with _driver_lane(driver) as lane:
        oracle, candidate = _pe_projects(tmp_path, lane, ORACLE32, CANDIDATE32)
        result = compare_macro_cfg(
            (oracle, candidate), (PE_BASE, len(ORACLE32)),
            (PE_BASE, len(CANDIDATE32)), lane.adapter.OUTPUT_REGS, TIMEOUT,
        )
        assert result["status"] is lane.verdict.Status.PASSED, result


@pytest.mark.parametrize(
    "candidate",
    [ZERO16, ODD16, STRIDE16, DIRECTION16, SIGNED16, SUBREG16, STORE16,
     RETCLEAN16, STUTTER16],
    ids=["zero_entry", "lost_odd_guard", "stride", "direction", "signedness",
         "subregister_wrap", "hidden_store", "ret_cleanup", "one_sided_stutter"],
)
def test_real16_semantic_mutations_cannot_pass(tmp_path: Path, candidate: bytes) -> None:
    """Each real16 mutation must refuse or stay UNKNOWN, never prove."""
    proof = _macro16(tmp_path, ORACLE16, candidate, timeout_ms=TIMEOUT)
    assert proof.status is not ProofStatus.PROVED, proof


@pytest.mark.parametrize(
    "candidate",
    [ZERO32, ODD32, STRIDE32, DIRECTION32, SIGNED32, SUBREG32, STORE32,
     RETCLEAN32, FLAGRET32, STUTTER32],
    ids=["zero_entry", "lost_odd_guard", "stride", "direction", "signedness",
         "subregister_wrap", "hidden_store", "ret_cleanup", "return_flags",
         "one_sided_stutter"],
)
@pytest.mark.parametrize("driver", ["msc8"])
def test_flat32_semantic_mutations_cannot_pass(driver: str, candidate: bytes) -> None:
    """Each flat32 mutation must refuse under the staged macro proof."""
    with _driver_lane(driver) as lane:
        result = _macro32(lane, ORACLE32, candidate)
        assert result["status"] is not lane.verdict.Status.PASSED, result


@pytest.mark.parametrize("driver", ["msc8", "bc5"])
def test_flat32_distinct_pe_images_not_promoted(driver: str, tmp_path: Path) -> None:
    """Distinct initialized PE images stay unproved; no whole-program claim."""
    with _driver_lane(driver) as lane:
        oracle, candidate = _pe_projects(tmp_path, lane, ORACLE32, STRIDE32)
        result = compare_macro_cfg(
            (oracle, candidate), (PE_BASE, len(ORACLE32)),
            (PE_BASE, len(STRIDE32)), lane.adapter.OUTPUT_REGS, TIMEOUT,
        )
        assert result["status"] is not lane.verdict.Status.PASSED, result


def test_corrupt_endpoint_marker_cannot_discharge() -> None:
    """A wrong-head endpoint discharge is solver-refuted, never normalized."""
    wrong_head = {"op": "const", "width": 32, "value": "0x9999"}
    term = endpoint_consistency_term(wrong_head, 0x200, guard_true())
    assert prove_terms_equal(term, guard_true(), 5000) is not ProofStatus.PROVED


def test_unpaired_continuing_head_is_refused_not_tokenized() -> None:
    """A frontier that never revisits the cut refuses with a typed reason."""
    oracle_nodes = {
        0: RegionNode(0, (0, 2), RegionExitKind.BORING),
        2: RegionNode(2, (), RegionExitKind.RETURN),
    }
    candidate_nodes = {
        0: RegionNode(0, (4, 2), RegionExitKind.BORING),
        4: RegionNode(4, (4, 2), RegionExitKind.BORING),
        2: RegionNode(2, (), RegionExitKind.RETURN),
    }
    with pytest.raises(MacroStepRefusal) as raised:
        propose_macro_steps(
            oracle_nodes, candidate_nodes, 0, 0, deadline_seconds=10.0,
        )
    assert raised.value.reason in (
        MacroStepReason.MACRO_DEPTH,
        MacroStepReason.MACRO_PATH_LIMIT,
        MacroStepReason.MACRO_ENDPOINT,
    )


def test_dropped_frontier_path_breaks_coverage_completeness(tmp_path: Path) -> None:
    """A guard set missing one feasible path cannot discharge coverage."""
    import time

    import tools.dosunit.compare.macro_step_pairing as macro_step_pairing
    import tools.dosunit.compare.real16_macro_proof as real16_macro_proof
    import tools.dosunit.compare.real16_macro_rows as real16_macro_rows
    from tools.dosunit.compare.paired_region_graph import collapse_regions
    from tools.dosunit.compare.real16_call_contracts import ComposeSession
    from tools.dosunit.compare.real16_call_evidence import group_lookup
    from tools.dosunit.compare.real16_region_transitions import region_nodes

    left = _document16(tmp_path, ORACLE16, "oracle")
    contexts, ctx = group_lookup(left, "demo.exe:loop")
    session = ComposeSession.with_deadline(Real16CallLimits(), 30000)
    partition = collapse_regions(region_nodes(ctx, session), ctx.entry_linear)
    budget = macro_step_pairing._SearchBudget(
        MacroStepLimits(), time.monotonic() + 30,
    )
    paths = macro_step_pairing._expand_frontier(
        partition, frozenset({ctx.entry_linear}), budget,
    )
    assert len(paths) == 2  # continuing body path plus return path
    states = [
        real16_macro_rows.compose_concat(session, contexts, ctx, (path,), 12000)
        for path in paths
    ]
    sessions = (session, session)
    full = real16_macro_proof._coverage(
        "oracle", [guard for _state, guard in states], sessions, [], 30000,
    )
    assert full[0].completeness is ProofStatus.PROVED
    dropped = real16_macro_proof._coverage(
        "oracle", [states[0][1]], sessions, [], 30000,
    )
    assert dropped[0].completeness is not ProofStatus.PROVED
    assert dropped[2] > 0


def test_oracle_only_frontier_path_has_empty_pairing() -> None:
    """A path with no endpoint-compatible concat is retained as unpaired."""
    oracle_nodes = {
        0: RegionNode(0, (0, 2), RegionExitKind.BORING),
        2: RegionNode(2, (), RegionExitKind.RETURN),
    }
    candidate_nodes = dict(oracle_nodes)
    search = propose_macro_steps(
        oracle_nodes, candidate_nodes, 0, 0, deadline_seconds=10.0,
    )
    for proposal in search.proposals:
        assert proposal.direction in (
            MacroDirection.ORACLE_SLOWER, MacroDirection.CANDIDATE_SLOWER,
        )
        assert all(pair.fast_path.end_kind in set(MacroEndpointKind)
                   for pair in proposal.pairings)


def test_search_state_cap_is_unknown_not_success(tmp_path: Path) -> None:
    """A zero-state budget yields UNKNOWN with typed exhaustion counters."""
    proof = _macro16(
        tmp_path, ORACLE16, CANDIDATE16, timeout_ms=TIMEOUT,
        macro_limits=MacroStepLimits(max_states=0),
    )
    assert proof.status is ProofStatus.UNKNOWN
    assert proof.search_refusal is MacroStepReason.MACRO_STATE_LIMIT


def test_compose_budget_cannot_be_assumed(tmp_path: Path) -> None:
    """The production composition budget refusal still propagates honestly."""
    proof = _macro16(
        tmp_path, ORACLE16, CANDIDATE16, timeout_ms=TIMEOUT,
        limits=Real16CallLimits(max_compositions=0),
    )
    assert proof.status is ProofStatus.UNKNOWN


@pytest.mark.parametrize("driver", ["msc8"])
def test_flat32_identity_neighbor_unchanged(driver: str) -> None:
    """Neighbor: production identity and chain-split proofs stay unchanged.

    The staged macro-step layer is entry-cut identity only: these loops have
    an interior back-edge that never revisits the entry cut, so the staged
    slice must fail closed with a typed refusal rather than prove or drop
    the cycle. The production reblocked proofs remain the green neighbors.
    """
    from tools.dosunit.compare.flat32_cfg_regions import compare_reblocked_cfg

    with _driver_lane(driver) as lane:
        for code_pair in ((LOOP32, LOOP32), (LOOP32, CHAIN32)):
            projects = _flat_projects(*code_pair)
            baseline = compare_reblocked_cfg(
                projects, (ORACLE_BASE, len(code_pair[0])),
                (CANDIDATE_BASE, len(code_pair[1])), lane.adapter.OUTPUT_REGS, TIMEOUT,
            )
            assert baseline["status"] is lane.verdict.Status.PASSED
            staged = _macro32(lane, *code_pair)
            assert staged["status"] is not lane.verdict.Status.PASSED
            assert staged["reason"] != "macro_step_cfg_induction"


def test_real16_reblocking_neighbor_unchanged(tmp_path: Path) -> None:
    """Neighbor: production split-loop reblocking proof is unchanged."""
    left = _document16(tmp_path, LOOP16, "original")
    right = _document16(tmp_path, SPLIT16, "candidate")
    proved = compare_real16_regions(left, right, "demo.exe:loop", timeout_ms=TIMEOUT)
    assert proved.status is ProofStatus.PROVED


@pytest.mark.parametrize("driver", ["msc8"])
def test_flat32_macro_identity_and_permutation_paths(driver: str) -> None:
    """Macro proof on identical loops keeps K=1 pairing with zero failures."""
    with _driver_lane(driver) as lane:
        result = _macro32(lane, ORACLE32, ORACLE32)
        assert result["status"] is lane.verdict.Status.PASSED, result
        assert result["counters"]["failure_count"] == 0
