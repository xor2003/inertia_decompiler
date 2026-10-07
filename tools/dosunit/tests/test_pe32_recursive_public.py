"""Public PE32 recursive_joint opt-in through both flat32 drivers.

Layer: tests.
Responsibility: exercise the typed recursive opt-in of both actual comparator
drivers over genuine generated PE32 images — real CLE loading, native
relifting and Z3 joint discharge — covering a positive self pair, an
equivalent changed body, base/progress corruptions, undeclared and
mismatched access domains, an exhausted shared budget and preserved ordinary
row/accounting. The pure-Python request, domain-parsing, pairing and early
refusal contracts run without native lifting or solver work.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import pytest
from tools.dosunit.tests.recursive_proof_fixtures.flat32_pe_recursive_inputs import (
    BASE_CASE_FLIPPED,
    DATA_BASE,
    ENTRY,
    PROGRESS_FLIPPED,
    STACK_HI,
    default_access_domain,
    pe32_recursive_bytes,
)
from tools.dosunit.tests.recursive_proof_fixtures.flat_call_continuation_inputs import TWO_FLAT_CALLS
from tools.dosunit.tests.test_flat32_comparator_lane import _driver_lane

from tools.dosunit.compare.pe32_recursive_compare import (
    REQUEST_BUDGET_MS,
    Pe32RecursiveOutcome,
    Pe32RecursiveReason,
    Pe32RecursiveRequest,
    add_recursive_arguments,
    check_recursive_request,
    parse_pe32_access_domain,
    prove_pe32_recursive_compare,
    recursive_request_from_args,
)
from tools.dosunit.contracts.proof_contracts import ProofStatus
from tools.dosunit.recursive_proofs.flat32_image_bound_domain import Flat32AccessDomain
from tools.dosunit.recursive_proofs.flat32_image_bound_joint_proof import Flat32ModelRequirement
from tools.dosunit.recursive_proofs.recursive_joint_contracts import JointReason

_DRIVERS: tuple[str, ...] = ("msc8", "bc5")
_ACCESS = default_access_domain()

# ``and eax,eax`` lifts identically to ``test eax,eax``: the same lazy-flag
# writes plus an identity ``eax := eax``, so this is an equivalent changed
# body with equal extent and control shape — not a same-bytes self-pair.
EQUIVALENT_BODY: bytes = bytes.fromhex("e3114921c07407e8f4ffffffeb05e8edffffffc3")


def _request(*, access: Flat32AccessDomain = _ACCESS,
             timeout_ms: int = REQUEST_BUDGET_MS, provenance: str = "") -> Pe32RecursiveRequest:
    """Build the declared request over the fixture's writable .data stack."""
    return Pe32RecursiveRequest(access, timeout_ms=timeout_ms, provenance=provenance)


def test_request_rejects_untyped_and_missing_domain() -> None:
    """The access-domain premise is required and never defaulted."""
    with pytest.raises(ValueError):
        Pe32RecursiveRequest(access=None)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        Pe32RecursiveRequest(access={"stack": "nope"})  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        _request(timeout_ms=-1)
    with pytest.raises(ValueError):
        _request(timeout_ms=True)
    with pytest.raises(ValueError):
        _request(provenance=17)  # type: ignore[arg-type]


def test_access_domain_parser_validates_shape() -> None:
    """The shared parser admits only five base-0 integer fields."""
    domain = parse_pe32_access_domain("0x402000:0x403000:0x402800:0x402f00:64")
    assert domain == Flat32AccessDomain(0x402000, 0x403000, 0x402800, 0x402F00, 64)
    for bad in ("", "1:2:3:4", "1:2:3:4:5:6", "a:b:c:d:e", "0x3000:0x2000:0x2800:0x2f00:4"):
        with pytest.raises(ValueError):
            parse_pe32_access_domain(bad)


def test_recursive_request_from_args_contracts() -> None:
    """The opt-in is absent, typed, or CLI-shaped; wrong shapes fail closed."""
    assert recursive_request_from_args(argparse.Namespace()) is None
    assert recursive_request_from_args(argparse.Namespace(recursive=False)) is None
    request = _request(timeout_ms=1234)
    assert recursive_request_from_args(argparse.Namespace(recursive=request)) is request
    args = argparse.Namespace(recursive=True, recursive_access_domain=_ACCESS,
                              recursive_timeout_ms=999)
    resolved = recursive_request_from_args(args)
    assert resolved == Pe32RecursiveRequest(_ACCESS, timeout_ms=999)
    args = argparse.Namespace(recursive=True,
                              recursive_access_domain="0x402000:0x403000:0x402800:0x402f00:64")
    resolved = recursive_request_from_args(args)
    assert resolved == Pe32RecursiveRequest(
        Flat32AccessDomain(0x402000, 0x403000, 0x402800, 0x402F00, 64))
    with pytest.raises(ValueError):
        recursive_request_from_args(argparse.Namespace(recursive=True))
    with pytest.raises(ValueError):
        recursive_request_from_args(argparse.Namespace(recursive="yes"))


def test_cli_arguments_normalize_or_fail_the_parse() -> None:
    """The shared CLI options build the typed request or reject the invocation."""
    parser = argparse.ArgumentParser()
    add_recursive_arguments(parser)
    args = parser.parse_args([])
    check_recursive_request(parser, args)
    assert args.recursive is None
    args = parser.parse_args(
        ["--recursive", "--recursive-access-domain",
         "0x402000:0x403000:0x402800:0x402f00:64"])
    check_recursive_request(parser, args)
    assert args.recursive == Pe32RecursiveRequest(
        Flat32AccessDomain(0x402000, 0x403000, 0x402800, 0x402F00, 64))
    args = parser.parse_args(["--recursive"])
    with pytest.raises(SystemExit):
        check_recursive_request(parser, args)


def _attempt(
    oracle_functions: dict[str, tuple[int, int]],
    candidate_functions: dict[str, tuple[int, int]],
    *,
    unresolved: tuple[str, ...] = (),
    timeout_ms: int = 60_000,
) -> Pe32RecursiveOutcome:
    """Run the pure-Python intake path with unreachable executable names."""
    return prove_pe32_recursive_compare(
        oracle_exe=Path("/nonexistent-oracle.exe"),
        candidate_exe=Path("/nonexistent-candidate.exe"),
        oracle_functions=oracle_functions,
        candidate_functions=candidate_functions,
        request=_request(timeout_ms=timeout_ms),
        unresolved_names=unresolved,
    )


def test_pairing_accounts_for_every_selected_name() -> None:
    """Unpaired, unresolved, divergent and malformed selections stay refused."""
    outcome = _attempt(
        {"f": (ENTRY, 16), "g": (ENTRY + 0x20, 8), "m": (ENTRY + 0x40, "bad")},  # type: ignore[dict-item]
        {"f": (ENTRY, 16), "h": (ENTRY + 0x20, 8), "m": (ENTRY + 0x40, "bad")},  # type: ignore[dict-item]
        unresolved=("z",),
    )
    assert outcome.attempted and outcome.status is ProofStatus.UNKNOWN
    # ``f`` pairs cleanly, so intake reaches binding and refuses on the
    # unreachable file; every refused name is still accounted.
    assert outcome.reason is Pe32RecursiveReason.LOAD
    reasons = {attempt.name: attempt.reason for attempt in outcome.attempts}
    assert reasons["g"] is Pe32RecursiveReason.UNPAIRED
    assert reasons["h"] is Pe32RecursiveReason.UNPAIRED
    assert reasons["z"] is Pe32RecursiveReason.UNPAIRED
    assert reasons["m"] is Pe32RecursiveReason.DECLARATION
    divergent = _attempt({"f": (ENTRY, 16)}, {"f": (ENTRY, 24)})
    assert divergent.reason is Pe32RecursiveReason.ADMISSION
    assert {attempt.name: attempt.reason for attempt in divergent.attempts} == {
        "f": Pe32RecursiveReason.COORDINATES}
    empty = _attempt({}, {}, unresolved=("z",))
    assert empty.reason is Pe32RecursiveReason.ADMISSION
    assert [attempt.name for attempt in empty.attempts] == ["z"]
    document = outcome.to_document()
    assert document["schema"] == "dosunit.pe32_compare.recursive_joint.v1"
    assert document["members"] == [] and document["domain_scope"] is None
    assert document["counters"]["failure_count"] == 1
    assert {row["name"] for row in document["attempts"]} == {"g", "h", "m", "z"}
    json.dumps(document)


def test_load_and_format_refusals_are_typed(tmp_path: Path) -> None:
    """Missing, non-MZ and ELF inputs refuse before any native work."""
    functions = {"f": (ENTRY, len(TWO_FLAT_CALLS))}
    outcome = _attempt(functions, functions)
    assert outcome.reason is Pe32RecursiveReason.LOAD
    elf = tmp_path / "elf.exe"
    elf.write_bytes(b"\x7fELF" + b"\x01" * 60)
    outcome = prove_pe32_recursive_compare(
        oracle_exe=elf, candidate_exe=elf, oracle_functions=functions,
        candidate_functions=functions, request=_request())
    assert outcome.reason is Pe32RecursiveReason.FORMAT
    assert outcome.status is ProofStatus.UNKNOWN


def test_exhausted_total_budget_refuses(tmp_path: Path) -> None:
    """A zero shared deadline refuses before image loading completes."""
    image = tmp_path / "image.exe"
    image.write_bytes(b"MZ" + b"\0" * 256)
    functions = {"f": (ENTRY, len(TWO_FLAT_CALLS))}
    outcome = prove_pe32_recursive_compare(
        oracle_exe=image, candidate_exe=image, oracle_functions=functions,
        candidate_functions=functions, request=_request(timeout_ms=0))
    assert outcome.attempted and outcome.status is ProofStatus.UNKNOWN
    assert outcome.reason is Pe32RecursiveReason.DEADLINE
    assert outcome.counters.failure_count == 1


def _image(directory: Path, name: str, code: bytes) -> tuple[Path, Path]:
    """Write genuine PE32 bytes and exact function-boundary listings."""
    image = directory / f"{name}.exe"
    image.write_bytes(pe32_recursive_bytes(code))
    listing = directory / f"{name}.lst"
    listing.write_text(
        f".text:{ENTRY:08X} f proc\n"
        f".text:{ENTRY + len(code) - 1:08X} f endp\n"
    )
    return image, listing


def test_standalone_recursive_lowering_never_installs_register_globals(tmp_path, monkeypatch):
    """Exercise the public adapter directly, outside either driver's installation."""
    import tools.dosunit.compare.straightline_ssa as engine

    oracle, _ = _image(tmp_path, "standalone-oracle", TWO_FLAT_CALLS)
    candidate, _ = _image(tmp_path, "standalone-candidate", TWO_FLAT_CALLS)
    original_map, original_reader = engine.REG_BY_OFFSET, engine._read_register
    original_lower = engine._lower_irsb
    calls = []

    def checked_lower(irsb, **kwargs):
        assert engine.REG_BY_OFFSET is original_map
        assert engine._read_register is original_reader
        assert kwargs["architecture"].control_register == "eip"
        calls.append(irsb.addr)
        return original_lower(irsb, **kwargs)

    monkeypatch.setattr(engine, "_lower_irsb", checked_lower)
    functions = {"f": (ENTRY, len(TWO_FLAT_CALLS))}
    outcome = prove_pe32_recursive_compare(oracle_exe=oracle, candidate_exe=candidate,
                                          oracle_functions=functions, candidate_functions=functions,
                                          request=_request())
    assert outcome.status is ProofStatus.CONDITIONAL
    assert calls
    assert engine.REG_BY_OFFSET is original_map


def _compare(driver: str, directory: Path, candidate_code: bytes, *,
             oracle_code: bytes = TWO_FLAT_CALLS, recursive: object = None,
             mode: str = "leaf", functions: str = "f") -> dict[str, Any]:
    """Run one production driver on actual PE files with a declared request."""
    directory.mkdir(parents=True, exist_ok=True)
    oracle, oracle_lst = _image(directory, "oracle", oracle_code)
    candidate, candidate_lst = _image(directory, "candidate", candidate_code)
    args = argparse.Namespace(
        oracle_exe=oracle, oracle_lst=oracle_lst, candidate_exe=candidate,
        candidate_lst=candidate_lst, candidate_lst_end_kind="last-instruction", candidate_syms=None,
        cache_dir=directory / "cache", functions=functions, mode=mode,
        output_regs="eax,edx,esp", scan_limit=0x1000, timeout_ms=30000,
        region_max_blocks=128, normalize_globals=False,
        assume_paired_calls=False, entry_esp_range=None,
        recursive=recursive, out_dir=directory / "out",
    )
    args.out_dir.mkdir(parents=True, exist_ok=True)
    with _driver_lane(driver) as lane, lane.adapter.installed(region=mode in {"region", "auto"}):
        return lane.z3cmp32.compare(args)


def _joint(report: dict[str, Any]) -> dict[str, Any]:
    """Return the serialized separate component report."""
    joint = report["recursive_joint"]
    assert isinstance(joint, dict)
    return joint


@pytest.mark.parametrize("driver", _DRIVERS)
def test_public_pe32_recursive_self_component_conditional(driver: str, tmp_path: Path) -> None:
    """A self pair discharges the initialized component, staying conditional."""
    report = _compare(driver, tmp_path, TWO_FLAT_CALLS, recursive=_request(), mode="leaf")
    joint = _joint(report)
    assert joint["attempted"] is True
    assert joint["status"] == ProofStatus.CONDITIONAL.value
    assert joint["reason"] == JointReason.CONDITIONAL_MODEL.value
    assert joint["members"] == ["flat32-401000"]
    assert joint["selected"] == [
        {"name": "f", "entry": ENTRY, "size": len(TWO_FLAT_CALLS), "member": "flat32-401000"}]
    assert joint["attempts"] == []
    scope = joint["domain_scope"]
    assert scope["kind"] == "initialized_pe32_image"
    assert scope["access_domain"]["stack_lo"] == DATA_BASE
    assert scope["access_domain"]["stack_hi"] == STACK_HI
    assert scope["access_domain"]["max_frames"] == 64
    assert scope["initialized_loaded_relation"] is True
    assert scope["arbitrary_entry_states_proved"] is False
    assert joint["joint"]["status"] == ProofStatus.CONDITIONAL.value
    assert joint["joint"]["binary_equivalence_proved"] is False
    assert set(joint["remaining_requirements"]) == {
        item.value for item in Flat32ModelRequirement}
    assert any("arbitrary_entry_states_not_proved" in item for item in joint["assumptions"])
    # Ordinary obligations are preserved untouched by the component result.
    assert report["summary"]["total"] == len(report["results"]) == 1
    row = report["results"][0]
    assert row["function"]["name"] == "f" and row["status"] != "passed"


@pytest.mark.parametrize("driver", _DRIVERS)
def test_public_pe32_recursive_equivalent_body_conditional(driver: str, tmp_path: Path) -> None:
    """An equivalent changed body still discharges the component conditionally."""
    report = _compare(driver, tmp_path, EQUIVALENT_BODY, recursive=_request(), mode="leaf")
    joint = _joint(report)
    assert joint["attempted"] is True
    assert joint["status"] == ProofStatus.CONDITIONAL.value
    assert joint["reason"] == JointReason.CONDITIONAL_MODEL.value
    assert joint["members"] == ["flat32-401000"]


@pytest.mark.parametrize("driver", _DRIVERS)
@pytest.mark.parametrize("code", [BASE_CASE_FLIPPED, PROGRESS_FLIPPED],
                         ids=["changed-base", "changed-progress"])
def test_public_pe32_recursive_corruption_never_discharges(driver: str, code: bytes,
                                                           tmp_path: Path) -> None:
    """Same-shape corruptions refuse at admission or discharge a countermodel."""
    report = _compare(driver, tmp_path, code, recursive=_request(), mode="leaf")
    joint = _joint(report)
    assert joint["attempted"] is True
    assert joint["status"] == ProofStatus.UNKNOWN.value
    assert joint["members"] == [] and joint["domain_scope"] is None
    assert joint["counters"]["failure_count"] > 0
    if code is BASE_CASE_FLIPPED:
        # The guarded-edge roles genuinely differ; the component cannot be
        # built and the adapter's typed admission refusal keeps the detail.
        assert joint["reason"] == Pe32RecursiveReason.ADMISSION.value
        assert joint["nested_reason"] == "flat32_component_manifest_mismatch"
    else:
        assert joint["reason"] == JointReason.COUNTERMODEL.value


@pytest.mark.parametrize("driver", _DRIVERS)
def test_public_pe32_recursive_undeclared_domain_fails_closed(driver: str, tmp_path: Path) -> None:
    """A flag without the declared access domain is a hard error, never a guess."""
    with pytest.raises(ValueError):
        _compare(driver, tmp_path, TWO_FLAT_CALLS, recursive=True, mode="leaf")
    with pytest.raises(ValueError):
        _compare(driver, tmp_path, TWO_FLAT_CALLS, recursive="yes", mode="leaf")


@pytest.mark.parametrize("driver", _DRIVERS)
def test_public_pe32_recursive_mismatched_domain_refuses(driver: str, tmp_path: Path) -> None:
    """A stack window overlapping component code cannot close the domain."""
    overlapping = Flat32AccessDomain(ENTRY - 4, ENTRY + 8, ENTRY - 4, ENTRY, 4)
    report = _compare(driver, tmp_path, TWO_FLAT_CALLS,
                      recursive=_request(access=overlapping), mode="leaf")
    joint = _joint(report)
    assert joint["attempted"] is True
    assert joint["status"] == ProofStatus.UNKNOWN.value
    assert joint["members"] == [] and joint["domain_scope"] is None
    assert joint["counters"]["failure_count"] > 0


@pytest.mark.parametrize("driver", _DRIVERS)
def test_public_pe32_recursive_budget_refuses(driver: str, tmp_path: Path) -> None:
    """An exhausted shared deadline keeps the component unproved."""
    report = _compare(driver, tmp_path, TWO_FLAT_CALLS,
                      recursive=_request(timeout_ms=0), mode="leaf")
    joint = _joint(report)
    assert joint["attempted"] is True
    assert joint["status"] == ProofStatus.UNKNOWN.value
    assert joint["reason"] == Pe32RecursiveReason.DEADLINE.value


@pytest.mark.parametrize("driver", _DRIVERS)
def test_public_pe32_ordinary_rows_unchanged_by_opt_in(driver: str, tmp_path: Path) -> None:
    """The opt-in adds only the separate field; absent request emits null."""
    plain = _compare(driver, tmp_path / "plain", TWO_FLAT_CALLS, mode="leaf")
    assert plain["recursive_joint"] is None
    with_joint = _compare(driver, tmp_path / "joint", TWO_FLAT_CALLS,
                          recursive=_request(), mode="leaf")
    assert _joint(with_joint)["attempted"] is True
    for key in ("summary", "results", "requested_functions"):
        assert with_joint[key] == plain[key], key


@pytest.mark.parametrize("driver", _DRIVERS)
def test_public_pe32_recursive_region_mode_preserves_ordinary_refusal(
    driver: str, tmp_path: Path
) -> None:
    """Region mode's ordinary refusal and the conditional component coexist."""
    report = _compare(driver, tmp_path, TWO_FLAT_CALLS, recursive=_request(), mode="region")
    joint = _joint(report)
    assert joint["attempted"] is True
    assert joint["status"] == ProofStatus.CONDITIONAL.value
    assert report["summary"]["total"] == len(report["results"]) == 1
    row = report["results"][0]
    assert row["function"]["name"] == "f" and row["status"] != "passed"
