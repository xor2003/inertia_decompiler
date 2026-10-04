"""Public compare-binary16 recursive joint-proof boundary tests.

Layer: Tests.
Responsibility: prove the ordinary ``compare_binary16`` path exposes the
image-bound recursive joint proof only as visibly conditional component
evidence bound to its proved initialized-entry domain, keeps every requested
function in the denominator, refuses missing/stale/incomplete proposals,
unsupported entry domains and exhausted budgets, and never promotes
conditional environment scope to ``passed``. Uses actual MZ bytes, real
lowering and the production joint checker.
"""
from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

import pytest
from test_dosunit_tool import _edge_function, _mz_exe

from tools.dosunit.real16_binary_compare import compare_binary16
from tools.dosunit.real16_recursive_compare import Real16RecursiveRequest
from tools.dosunit.recursive_proofs.recursive_joint_contracts import (
    EnvironmentScopeMember,
    Real16EnvironmentScope,
)

BOOTSTRAP = bytes.fromhex("e8fd01c3")  # call 0x200; ret
# jcxz +7; lea di,[bx+1]; dec cx; call -9 (recursive); ret
RECURSIVE = "e3078d5f0149e8f7ffc3"
# Equivalent reordered mid-block effects; identical layout.
RECURSIVE_EQUIVALENT = "e307498d5f01e8f7ffc3"
SELECTED = ("bootstrap", "recursive")
ENVIRONMENT_OPEN = "external_and_asynchronous_event_scope"


def _image(code_hex: str) -> bytes:
    """Bootstrap at image start, recursive body at 0x200."""
    image = bytearray(0x300)
    image[: len(BOOTSTRAP)] = BOOTSTRAP
    image[0x200 : 0x200 + len(bytes.fromhex(code_hex))] = bytes.fromhex(code_hex)
    return bytes(image)


def _catalog(*, recursive_size: int, include_recursive: bool = True) -> dict[str, Any]:
    """Declare the entry trampoline and the recursive body as plain functions."""
    functions = [_edge_function("bootstrap", "bootstrap", offset=0, size=len(BOOTSTRAP))]
    if include_recursive:
        functions.append(
            _edge_function("recursive", "recursive", offset=0x200, size=recursive_size)
        )
    return {
        "schema": "dosunit.functions.v1",
        "id": "functions:test",
        "module": "demo.exe",
        "program_kind": "mz_exe",
        "functions": functions,
        "diagnostics": [],
    }


def _pair(
    tmp_path: Path,
    tag: str,
    oracle_hex: str,
    candidate_hex: str,
    *,
    oracle_size: int | None = None,
    candidate_size: int | None = None,
    include_candidate_recursive: bool = True,
) -> tuple[Path, Path, dict[str, Any], dict[str, Any]]:
    """Write both MZ executables and their public function catalogs."""
    oracle = tmp_path / f"{tag}o.exe"
    candidate = tmp_path / f"{tag}c.exe"
    oracle.write_bytes(_mz_exe(_image(oracle_hex)))
    candidate.write_bytes(_mz_exe(_image(candidate_hex)))
    return (
        oracle,
        candidate,
        _catalog(recursive_size=oracle_size or len(bytes.fromhex(oracle_hex))),
        _catalog(
            recursive_size=candidate_size or len(bytes.fromhex(candidate_hex)),
            include_recursive=include_candidate_recursive,
        ),
    )


def _run(
    tmp_path: Path,
    tag: str,
    oracle_hex: str,
    candidate_hex: str,
    *,
    recursive: Real16RecursiveRequest | None = None,
    oracle_size: int | None = None,
    candidate_size: int | None = None,
    include_candidate_recursive: bool = True,
) -> dict[str, Any]:
    """Invoke the ordinary public comparator; never the checker directly."""
    oracle, candidate, oracle_catalog, candidate_catalog = _pair(
        tmp_path,
        tag,
        oracle_hex,
        candidate_hex,
        oracle_size=oracle_size,
        candidate_size=candidate_size,
        include_candidate_recursive=include_candidate_recursive,
    )
    return compare_binary16(
        oracle,
        candidate,
        oracle_catalog,
        candidate_catalog,
        selected=SELECTED,
        recursive=recursive,
    )


def _verdicts(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Index the typed per-function verdicts by their required keys."""
    return {verdict["id"]["key"]: verdict for verdict in report["proof"]["verdicts"]}


def test_request_shape_is_typed_and_bounded() -> None:
    """Malformed requests fail intake instead of silently becoming proposals."""
    with pytest.raises(ValueError, match="nonnegative millisecond"):
        Real16RecursiveRequest(timeout_ms=-1)
    with pytest.raises(ValueError, match="attempted roots"):
        Real16RecursiveRequest(max_roots=0)
    scope = Real16EnvironmentScope(
        members=tuple(EnvironmentScopeMember),
        original_hash="0" * 64,
        candidate_hash="1" * 64,
    )
    with pytest.raises(ValueError, match="cannot both"):
        Real16RecursiveRequest(closed_machine=True, declared_scope=scope)


def test_missing_candidate_function_stays_unproved(tmp_path: Path) -> None:
    """A recursive root absent from the candidate catalog cannot admit."""
    report = _run(
        tmp_path,
        "miss",
        RECURSIVE,
        RECURSIVE,
        recursive=Real16RecursiveRequest(closed_machine=True),
        include_candidate_recursive=False,
    )
    assert report["status"] != "proved"
    assert _verdicts(report)["recursive"]["status"] == "unknown"
    recursive_joint = report["recursive_joint"]
    assert recursive_joint["attempted"] and recursive_joint["status"] == "unknown"
    assert recursive_joint["reason"] == "recursive_admission_incomplete"


def test_truncated_candidate_block_layout_refuses(tmp_path: Path) -> None:
    """A candidate body missing its final block cannot match the layout."""
    report = _run(
        tmp_path,
        "trblk",
        RECURSIVE,
        RECURSIVE,
        recursive=Real16RecursiveRequest(closed_machine=True),
        candidate_size=len(bytes.fromhex(RECURSIVE)) - 1,
    )
    assert report["status"] != "proved"
    recursive_joint = report["recursive_joint"]
    assert recursive_joint["status"] == "unknown"
    assert recursive_joint["reason"] == "recursive_admission_incomplete"
    reasons = {attempt["reason"] for attempt in recursive_joint["attempts"]}
    # The truncated body leaves the jcxz target undeclared during the walk.
    assert "joint_call_graph_incomplete" in reasons


def test_changed_call_target_is_an_undeclared_callee(tmp_path: Path) -> None:
    """A recursive call retargeted outside every function stays a refusal."""
    changed = "e3078d5f0149e8f8ffc3"  # call -8: mid-body, undeclared target
    report = _run(
        tmp_path,
        "tgt",
        RECURSIVE,
        changed,
        recursive=Real16RecursiveRequest(closed_machine=True),
    )
    assert report["status"] != "proved"
    recursive_joint = report["recursive_joint"]
    assert recursive_joint["status"] == "unknown"
    reasons = {attempt["reason"] for attempt in recursive_joint["attempts"]}
    assert "joint_call_graph_incomplete" in reasons


def test_exhausted_budget_refuses_without_rows(tmp_path: Path) -> None:
    """A zero shared deadline cannot accidentally admit or prove anything."""
    report = _run(
        tmp_path,
        "dl",
        RECURSIVE,
        RECURSIVE,
        recursive=Real16RecursiveRequest(timeout_ms=0, closed_machine=True),
    )
    assert report["status"] != "proved"
    recursive_joint = report["recursive_joint"]
    assert recursive_joint["status"] == "unknown"
    assert recursive_joint["reason"] == "recursive_deadline_exhausted"


def test_stale_executable_bytes_cannot_bind(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A bound load whose file hash differs from the sealed digest refuses."""
    oracle, candidate, oracle_catalog, candidate_catalog = _pair(
        tmp_path, "stale", RECURSIVE, RECURSIVE
    )
    stale_bytes = _mz_exe(bytes(bytearray(0x400)))

    def stale_bind(data: bytes, *, load_segment: int, limits: Any = None) -> Any:
        from tools.dosunit.recursive_proofs.loaded_byte_image_binding import bind_real16_mz

        return bind_real16_mz(stale_bytes, load_segment=load_segment, limits=limits)

    monkeypatch.setattr(
        "tools.dosunit.real16_recursive_compare.bind_real16_mz", stale_bind
    )
    report = compare_binary16(
        oracle,
        candidate,
        oracle_catalog,
        candidate_catalog,
        selected=SELECTED,
        recursive=Real16RecursiveRequest(closed_machine=True),
    )
    assert report["status"] != "proved"
    recursive_joint = report["recursive_joint"]
    assert recursive_joint["status"] == "unknown"
    assert recursive_joint["reason"] == "recursive_executable_bytes_stale"


def test_unbound_premise_leaves_environment_open(tmp_path: Path) -> None:
    """A declared scope bound to different binaries is a stale premise."""
    stale_scope = Real16EnvironmentScope(
        members=tuple(EnvironmentScopeMember),
        original_hash="0" * 64,
        candidate_hash="1" * 64,
        provenance="forged-fixture",
    )
    report = _run(
        tmp_path,
        "stalepr",
        RECURSIVE,
        RECURSIVE,
        recursive=Real16RecursiveRequest(declared_scope=stale_scope, timeout_ms=300_000),
    )
    assert report["status"] != "proved"
    recursive_joint = report["recursive_joint"]
    assert recursive_joint["status"] == "conditional", recursive_joint
    assert ENVIRONMENT_OPEN in recursive_joint["remaining_requirements"]
    assert _verdicts(report)["recursive"]["status"] == "unknown"
    assert ENVIRONMENT_OPEN in recursive_joint["assumptions"]


def test_changed_base_case_stays_unproved(tmp_path: Path) -> None:
    """A different loop-exit condition is a semantic difference, not a layout one."""
    changed = "74078d5f0149e8f7ffc3"  # jz +7 instead of jcxz +7
    report = _run(
        tmp_path,
        "base",
        RECURSIVE,
        changed,
        recursive=Real16RecursiveRequest(closed_machine=True, timeout_ms=300_000),
    )
    assert report["status"] != "proved"
    assert _verdicts(report)["recursive"]["status"] == "unknown"
    assert report["recursive_joint"]["status"] == "unknown"


def test_changed_progress_stays_unproved(tmp_path: Path) -> None:
    """A recursive step that does not decrease its counter cannot discharge."""
    changed = "e3078d5f0141e8f7ffc3"  # inc cx instead of dec cx
    report = _run(
        tmp_path,
        "prog",
        RECURSIVE,
        changed,
        recursive=Real16RecursiveRequest(closed_machine=True, timeout_ms=300_000),
    )
    assert report["status"] != "proved"
    assert _verdicts(report)["recursive"]["status"] == "unknown"
    assert report["recursive_joint"]["status"] == "unknown"


def test_identical_recursive_component_is_visibly_conditional(tmp_path: Path) -> None:
    """The component positive stays separate from arbitrary-entry member obligations."""
    report = _run(
        tmp_path,
        "same",
        RECURSIVE,
        RECURSIVE,
        recursive=Real16RecursiveRequest(closed_machine=True, timeout_ms=300_000),
    )
    assert report["schema"] == "dosunit.binary16_compare.v1"
    assert report["status"] != "proved"
    verdicts = _verdicts(report)
    assert len(verdicts) == 2  # original requested denominator retained
    member = verdicts["recursive"]
    assert member["status"] == "unknown"
    assert member["method"] != "image_bound_recursive_joint"
    member_assumptions = tuple(report["recursive_joint"]["assumptions"])
    for member_name in (item.value for item in EnvironmentScopeMember):
        assert any(assumption.startswith(member_name) for assumption in member_assumptions)
    assert any(
        report["inputs"]["oracle"]["sha256"] in assumption
        and report["inputs"]["candidate"]["sha256"] in assumption
        for assumption in member_assumptions
    )
    # The joint only proves the initialized-image entry domain; the public
    # obligation's arbitrary-entry domain stays an explicit open assumption.
    assert any(
        assumption.startswith("supported_entry_domain:initialized_mz_image(")
        and report["inputs"]["oracle"]["sha256"] in assumption
        for assumption in member_assumptions
    )
    assert any(
        assumption.startswith("entry_scalars_proved(ss=")
        and ",cs=" in assumption
        and "sp_alignment=" in assumption
        for assumption in member_assumptions
    )
    assert any(
        assumption.startswith("initialized_loaded_byte_relation(")
        for assumption in member_assumptions
    )
    assert any(
        assumption.startswith("arbitrary_entry_states_not_proved(")
        for assumption in member_assumptions
    )
    assert verdicts["bootstrap"]["status"] == "unknown"
    recursive_joint = report["recursive_joint"]
    assert recursive_joint["attempted"] and recursive_joint["status"] == "conditional"
    assert recursive_joint["members"] == ["recursive"]
    assert recursive_joint["joint"]["binary_equivalence_proved"] is False
    assert recursive_joint["counters"]["failure_count"] == 0
    domain_scope = recursive_joint["domain_scope"]
    assert domain_scope["kind"] == "initialized_mz_image"
    assert domain_scope["initialized_loaded_relation"] is True
    assert domain_scope["arbitrary_entry_states_proved"] is False
    assert domain_scope["original_sha256"] == report["inputs"]["oracle"]["sha256"]
    assert domain_scope["candidate_sha256"] == report["inputs"]["candidate"]["sha256"]


def test_undeclared_machine_scope_stays_an_open_assumption(tmp_path: Path) -> None:
    """Without a declared premise the environment obligation remains visible."""
    report = _run(
        tmp_path,
        "open",
        RECURSIVE,
        RECURSIVE,
        recursive=Real16RecursiveRequest(timeout_ms=300_000),
    )
    assert report["status"] != "proved"
    member = _verdicts(report)["recursive"]
    assert member["status"] == "unknown"
    assert ENVIRONMENT_OPEN in report["recursive_joint"]["assumptions"]
    assert ENVIRONMENT_OPEN in report["recursive_joint"]["remaining_requirements"]


def test_equivalent_changed_body_is_visibly_conditional(tmp_path: Path) -> None:
    """A reordered-but-equivalent recursive body discharges to conditional."""
    report = _run(
        tmp_path,
        "reord",
        RECURSIVE,
        RECURSIVE_EQUIVALENT,
        recursive=Real16RecursiveRequest(closed_machine=True, timeout_ms=300_000),
    )
    assert report["status"] != "proved"
    member = _verdicts(report)["recursive"]
    assert member["status"] == "unknown"
    assert member["method"] != "image_bound_recursive_joint"
    assert report["recursive_joint"]["status"] == "conditional", report["recursive_joint"]


def _pair_with_stack_alias(tmp_path: Path, tag: str) -> tuple[Path, Path, dict[str, Any], dict[str, Any]]:
    """MZ whose declared stack segment aliases the loaded code image."""
    oracle, candidate, oracle_catalog, candidate_catalog = _pair(
        tmp_path, tag, RECURSIVE, RECURSIVE
    )
    for path in (oracle, candidate):
        data = bytearray(path.read_bytes())
        data[14:16] = struct.pack("<H", 0x0020)  # stack_ss lands inside the image
        path.write_bytes(bytes(data))
    return oracle, candidate, oracle_catalog, candidate_catalog


def test_stack_selector_aliasing_image_refuses_domain(tmp_path: Path) -> None:
    """An initialized-image domain that cannot be proved keeps rows unknown.

    The joint's entry domain is what makes the component result honest on
    public rows; when the loader scalars are inconsistent the adapter must
    refuse at the domain boundary rather than report a name-matched pass.
    """
    oracle, candidate, oracle_catalog, candidate_catalog = _pair_with_stack_alias(tmp_path, "ssal")
    report = compare_binary16(
        oracle,
        candidate,
        oracle_catalog,
        candidate_catalog,
        selected=SELECTED,
        recursive=Real16RecursiveRequest(closed_machine=True),
    )
    assert report["status"] != "proved"
    recursive_joint = report["recursive_joint"]
    assert recursive_joint["status"] == "unknown"
    assert recursive_joint["reason"] == "recursive_domain_receipt_refused"
    assert recursive_joint["nested_reason"] == "image_bound_entry_scalar_domain_unproved"
    assert _verdicts(report)["recursive"]["status"] == "unknown"


def test_entry_not_reaching_component_refuses_domain(tmp_path: Path) -> None:
    """An entry trampoline that never calls the component cannot admit.

    Same component bytes both sides, but the bootstrap spins in place, so the
    image-bound entry/frame prerequisites cannot be proved — the public row
    must stay unknown instead of inheriting a name-matched result.
    """
    oracle, candidate, oracle_catalog, candidate_catalog = _pair(
        tmp_path, "noentry", RECURSIVE, RECURSIVE
    )
    body = bytes.fromhex(RECURSIVE)
    for path in (oracle, candidate):
        # Entry bytes become ``jmp $`` followed by padding; the body is intact.
        image = bytearray(0x300)
        image[:3] = bytes.fromhex("ebfec3")
        image[0x200 : 0x200 + len(body)] = body
        path.write_bytes(_mz_exe(bytes(image)))
    report = compare_binary16(
        oracle,
        candidate,
        oracle_catalog,
        candidate_catalog,
        selected=SELECTED,
        recursive=Real16RecursiveRequest(closed_machine=True),
    )
    assert report["status"] != "proved"
    recursive_joint = report["recursive_joint"]
    assert recursive_joint["status"] == "unknown"
    assert recursive_joint["reason"] == "recursive_domain_receipt_refused"
    assert _verdicts(report)["recursive"]["status"] == "unknown"
