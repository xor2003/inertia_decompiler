"""Real16 symbolic-control proofs, accounting, and shared resource budgets.

Layer: dosunit regression tests.
Responsibility: exercise the production proof boundary and actual lowered MZ
callers, preserve incomplete-loop refusals, and reject malformed or lost proof
evidence. Deterministic counters check shared DAG work and aggregate budgets.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import pytest

import tools.dosunit.compare.real16_control_boundary as boundary
import tools.dosunit.compare.real16_control_targets as rt
import tools.dosunit.compare.straightline_ssa as cssa
from tools.dosunit.ssa.ssa_constant_terms import constant_bitvector

z3 = pytest.importorskip("z3")

_CALLBACKS = boundary.Z3TermCallbacks(
    inputs=cssa._z3_inputs, term=cssa._z3_term, apply=cssa._z3_apply
)


def _mz_exe(image: bytes) -> bytes:
    """Minimal MZ wrapper, identical to the repository test helper."""
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
    header[0x0E:0x10] = (0x0080).to_bytes(2, "little")
    header[0x10:0x12] = (0xFFFE).to_bytes(2, "little")
    header[0x18:0x1A] = (0x1C).to_bytes(2, "little")
    return bytes(header) + image


def _edge_function(function_id: str, name: str, *, offset: int, size: int) -> dict[str, Any]:
    """Catalog entry, identical to the repository test helper."""
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


def _edge_catalog(function_id: str, name: str, *, offset: int, size: int) -> dict[str, Any]:
    """Single-function catalog, identical to the repository test helper."""
    return {
        "schema": "dosunit.functions.v1",
        "id": "functions:test",
        "module": "demo.exe",
        "program_kind": "mz_exe",
        "functions": [_edge_function(function_id, name, offset=offset, size=size)],
        "diagnostics": [],
    }


def _opt_int(value: Any) -> int | None:
    return cssa._optional_int(value)


def _dfield(node: dict[str, Any], key: str) -> dict[str, Any]:
    value = node.get(key)
    return value if isinstance(value, dict) else {}


def _part_by_entry(document: dict[str, Any], linear: int) -> dict[str, Any]:
    for part in document.get("functions", []) or []:
        if isinstance(part, dict) and _opt_int(_dfield(part, "entry").get("linear")) == linear:
            return part
    raise AssertionError(f"no part at {hex(linear)}")


def _resolved(part: dict[str, Any], term: dict[str, Any]) -> dict[str, Any] | None:
    if not isinstance(term, dict):
        return None
    ref = term.get("ref")
    if isinstance(ref, str):
        assignments = {
            str(item["id"]): item
            for item in part.get("assignments", []) or []
            if isinstance(item, dict) and "id" in item
        }
        resolved = assignments.get(ref)
        return resolved if isinstance(resolved, dict) else None
    return term


def _shifted_call_docs(tmp_path: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Lower the shifted-call pair with the production comparator."""
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
            _edge_function(
                "demo.exe:callee_rebuilt", "callee_rebuilt", offset=0x0230, size=len(candidate_callee)
            ),
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
    oracle = cssa.lower_straightline_ssa_document(
        exe_path=original,
        functions_catalog=original_catalog,
        output_regs=cssa.INTERNAL_STATE_REGS,
        follow_call_fallthrough=False,
    )
    candidate = cssa.lower_straightline_ssa_document(
        exe_path=candidate,
        functions_catalog=candidate_catalog,
        output_regs=cssa.INTERNAL_STATE_REGS,
        follow_call_fallthrough=False,
    )
    return oracle, candidate, mapping


def _countdown_docs(tmp_path: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Lower the bounded-loop countdown pair with the production comparator."""
    image = bytearray(0x240)
    image[0x200:0x214] = bytes.fromhex("558bec31c08b4e0485c97e044049ebf88be55dc3")
    original = tmp_path / "original.exe"
    candidate = tmp_path / "candidate.exe"
    original.write_bytes(_mz_exe(bytes(image)))
    candidate.write_bytes(_mz_exe(bytes(image)))
    catalog = _edge_catalog("demo.exe:countdown", "countdown", offset=0x0200, size=0x14)
    output_regs = ("ax", "bp", "sp", "ip", "ss")
    oracle = cssa.lower_straightline_ssa_document(
        exe_path=original, functions_catalog=catalog, output_regs=output_regs,
        max_blocks_per_function=16,
    )
    candidate_ssa = cssa.lower_straightline_ssa_document(
        exe_path=candidate, functions_catalog=catalog, output_regs=output_regs,
        max_blocks_per_function=16,
    )
    manifest = {
        "schema": "test.abi.v1",
        "functions": [
            {"name": "countdown", "kind": "near", "returns": ["ax"], "preserved": ["bp"]}
        ],
    }
    return oracle, candidate_ssa, manifest


def _stub_proof(verdict: Any, value: int | None, failure: Any = None) -> Any:
    """Fabricated proof result for deterministic (solver-free) boundary tests."""
    return rt.ControlDestinationProof(
        verdict=verdict, value=value, failure=failure,
        stats=rt.ControlProofStats(queries=1, term_nodes=0, solver_time_ms=0, failures=0),
    )


def test_producer_marker_emitted_on_real16(tmp_path: Path) -> None:
    """The comparator emits ``control_domain`` on every real16 block."""
    oracle, _candidate, _mapping = _shifted_call_docs(tmp_path)
    parts = [p for p in oracle.get("functions", []) or [] if isinstance(p, dict)]
    assert parts
    for part in parts:
        fact = _dfield(_dfield(part, "source"), "control_domain")
        assert fact.get("kind") == rt.FETCH_DOMAIN_KIND
        assert fact.get("arch") == rt.REAL16_ARCH_NAME
        head = _opt_int(_dfield(part, "entry").get("linear"))
        assert _opt_int(fact.get("head_linear")) == head
        instructions = [i for i in _dfield(part, "source").get("instructions", []) if isinstance(i, dict)]
        terminal = _opt_int(_dfield(instructions[-1], "address").get("linear"))
        assert _opt_int(fact.get("terminal_linear")) == terminal


def test_flat32_marker_absent() -> None:
    """The marker adapter emits nothing for a non-real16 arch object."""

    class _Flat32:
        name = "amd64"
        bits = 32
        control_address_domain = "flat32_linear"

    assert boundary.fetch_domain_marker(_Flat32(), head_linear=0x1200, terminal_linear=0x1203) is None
    assert boundary.fetch_domain_marker(object(), head_linear=0x1200, terminal_linear=0x1203) is None


def _run_shared_dag_attempt(
    term: dict[str, Any], cs_term: dict[str, Any], *, part: dict[str, Any] | None = None,
) -> tuple[Any, dict[str, int], Any]:
    """Drive one boundary attempt with counting callbacks and a stub verdict."""
    counts = {"term": 0, "apply": 0}

    def term_cb(node: dict[str, Any], **kwargs: Any) -> Any:
        counts["term"] += 1
        return cssa._z3_term(node, **kwargs)

    def apply_cb(op: str, width: int, args: list[Any], z3mod: Any) -> Any:
        counts["apply"] += 1
        return cssa._z3_apply(op, width, args, z3mod)

    part = part or {"inputs": [], "assignments": [], "source": {}}
    ledger = boundary.ControlProofLedger()
    callbacks = boundary.Z3TermCallbacks(inputs=cssa._z3_inputs, term=term_cb, apply=apply_cb)

    def prove(encode: Any, _budget: Any, _z3mod: Any) -> tuple[Any, Any, Any]:
        encode(term)
        encode(cs_term)
        normalized = {"op": "const", "value": "0x1208", "width": 32}
        return normalized, None, _stub_proof(rt.ControlProofVerdict.PROVEN, None)

    outcome = boundary._run_attempt(
        part, [term, cs_term], callbacks=callbacks, ledger=ledger,
        deadline=None, alarm_ms=None, role="test.shared_dag", prove=prove,
    )
    return outcome, counts, ledger


def test_shared_dag_encodes_each_node_once() -> None:
    """A shared subterm across term and cs encodes exactly once."""
    leaf_ax = {"op": "input", "name": "ax", "width": 16}
    leaf_cs = {"op": "input", "name": "cs", "width": 16}
    shared = {"op": "zext", "width": 32, "args": [leaf_ax]}
    term = {"op": "add", "width": 32, "args": [shared, shared]}
    cs_term = {"op": "zext", "width": 32, "args": [leaf_cs]}

    outcome, counts, ledger = _run_shared_dag_attempt(term, cs_term)
    assert outcome.normalized is not None
    # Unique nodes: leaf_ax, shared(zext), add, leaf_cs, zext(cs) = 5.
    assert outcome.encoded_nodes == 5
    assert counts["term"] == 2  # two distinct input leaves only
    # zext(shared)+add+zext(cs) — shared encodes once, not twice.
    assert counts["apply"] == 3
    counters = ledger.counters()
    assert counters.raw_fact_count == 1
    assert counters.normalized_fact_count == 1
    assert counters.classified_fact_count == 1
    assert counters.failure_count == 0


def test_ref_dedup_and_cycle_refusals() -> None:
    """Ref nodes resolve once per assignment; cycles and missing refs refuse."""
    leaf_ax = {"op": "input", "name": "ax", "width": 16}
    cs_term = {"op": "input", "name": "cs", "width": 16}
    body = {"op": "zext", "width": 32, "args": [leaf_ax]}
    part = {"inputs": [], "assignments": [{"id": "v1", **body}], "source": {}}
    # Two distinct {"ref": "v1"} nodes → one encode of the assignment body.
    term = {"op": "add", "width": 32, "args": [{"ref": "v1"}, {"ref": "v1"}]}
    outcome, counts, _ledger = _run_shared_dag_attempt(term, cs_term, part=part)
    assert outcome.normalized is not None
    assert counts["apply"] == 2  # v1's zext + root add
    assert counts["term"] == 2  # ax leaf once + cs leaf

    cyclic_part = {
        "inputs": [],
        "assignments": [{"id": "v1", "op": "add", "width": 32,
                         "args": [{"ref": "v1"}, leaf_ax]}],
        "source": {},
    }
    outcome, _c, ledger = _run_shared_dag_attempt({"ref": "v1"}, cs_term, part=cyclic_part)
    assert outcome.normalized is None
    assert outcome.failure is rt.ControlDomainFailure.TERM_UNENCODABLE

    missing_part = {"inputs": [], "assignments": [], "source": {}}
    outcome, _c, ledger = _run_shared_dag_attempt({"ref": "vMissing"}, cs_term, part=missing_part)
    assert outcome.normalized is None
    assert outcome.failure is rt.ControlDomainFailure.TERM_UNENCODABLE
    assert ledger.counters().raw_fact_count == 1
    assert ledger.counters().classified_fact_count == 0  # refused before any verdict


def test_inline_cycle_and_malformed_refusal() -> None:
    """An inline self-cycle and malformed nodes are typed refusals."""
    cs_term = {"op": "input", "name": "cs", "width": 16}
    cyclic: dict[str, Any] = {"op": "add", "width": 32, "args": []}
    cyclic["args"] = [cyclic, {"op": "input", "name": "ax", "width": 16}]
    outcome, _c, _l = _run_shared_dag_attempt(cyclic, cs_term)
    assert outcome.normalized is None
    assert outcome.failure is rt.ControlDomainFailure.TERM_UNENCODABLE

    malformed_args = {"op": "add", "width": 32, "args": "not-a-list"}
    outcome, _c, _l = _run_shared_dag_attempt(malformed_args, cs_term)
    assert outcome.failure is rt.ControlDomainFailure.TERM_UNENCODABLE

    non_dict_arg = {"op": "add", "width": 32, "args": ["x"]}
    outcome, _c, _l = _run_shared_dag_attempt(non_dict_arg, cs_term)
    assert outcome.failure is rt.ControlDomainFailure.TERM_UNENCODABLE

    bad_width = {"op": "zext", "width": "wide", "args": [{"op": "input", "name": "ax", "width": 16}]}
    outcome, _c, _l = _run_shared_dag_attempt(bad_width, cs_term)
    assert outcome.failure is rt.ControlDomainFailure.TERM_UNENCODABLE


def test_conflicting_input_specs_refuse() -> None:
    """Declared-vs-walked width conflicts refuse before any solver call."""
    cs_term = {"op": "input", "name": "cs", "width": 16}
    term = {"op": "zext", "width": 32, "args": [{"op": "input", "name": "ax", "width": 32}]}
    part = {"inputs": [{"name": "ax", "width": 16}], "assignments": [], "source": {}}
    outcome, _c, ledger = _run_shared_dag_attempt(term, cs_term, part=part)
    assert outcome.normalized is None
    assert outcome.failure is rt.ControlDomainFailure.TERM_UNENCODABLE
    assert ledger.counters().classified_fact_count == 0


def test_deadline_and_budget_refusals() -> None:
    """Past/zero deadlines refuse as BUDGET_EXHAUSTED before any encode work."""
    leaf = {"op": "input", "name": "ax", "width": 16}
    term = {"op": "zext", "width": 32, "args": [leaf]}
    cs_term = {"op": "input", "name": "cs", "width": 16}
    for deadline in (time.monotonic() - 1.0, time.monotonic()):
        outcome, counts, ledger = _run_shared_dag_attempt_deadline(term, cs_term, deadline)
        assert outcome.normalized is None
        assert outcome.failure is rt.ControlDomainFailure.BUDGET_EXHAUSTED
        assert counts["term"] == 0 and counts["apply"] == 0  # no encode ran
        assert ledger.counters().raw_fact_count == 1
        assert ledger.counters().failure_count == 1


def _run_shared_dag_attempt_deadline(
    term: dict[str, Any], cs_term: dict[str, Any], deadline: float
) -> tuple[Any, dict[str, int], Any]:
    counts = {"term": 0, "apply": 0}

    def term_cb(node: dict[str, Any], **kwargs: Any) -> Any:
        counts["term"] += 1
        return cssa._z3_term(node, **kwargs)

    def apply_cb(op: str, width: int, args: list[Any], z3mod: Any) -> Any:
        counts["apply"] += 1
        return cssa._z3_apply(op, width, args, z3mod)

    part = {"inputs": [], "assignments": [], "source": {}}
    ledger = boundary.ControlProofLedger()
    callbacks = boundary.Z3TermCallbacks(inputs=cssa._z3_inputs, term=term_cb, apply=apply_cb)

    def prove(encode, _budget, _z3mod):
        encode(term)
        encode(cs_term)
        return {"op": "const", "value": "0x1208", "width": 32}, None, _stub_proof(
            rt.ControlProofVerdict.PROVEN, None
        )

    outcome = boundary._run_attempt(
        part, [term, cs_term], callbacks=callbacks, ledger=ledger,
        deadline=deadline, alarm_ms=None, role="test.deadline", prove=prove,
    )
    return outcome, counts, ledger


def test_cs_term_walk_bound_applies_to_cs() -> None:
    """A malformed ``cs`` binding refuses at the shared pre-walk, before prove."""
    cs_term = {"ref": "vMissing"}
    term = {"op": "zext", "width": 32, "args": [{"op": "input", "name": "ax", "width": 16}]}
    outcome, counts, _ledger = _run_shared_dag_attempt(term, cs_term)
    assert outcome.normalized is None
    assert outcome.failure is rt.ControlDomainFailure.TERM_UNENCODABLE
    assert counts["term"] == 0  # refused during the shared input walk, not in encode


def test_countdown_real_proof_through_boundary(tmp_path: Path) -> None:
    """End-to-end real proof: candidate part → boundary → normalized const."""
    oracle, _candidate, _manifest = _countdown_docs(tmp_path)
    loop_block = _part_by_entry(oracle, 0x120C)
    outputs = loop_block["outputs"]
    term = _resolved(loop_block, outputs["control_ip"])
    assert term is not None and constant_bitvector(term) is None

    ledger = boundary.ControlProofLedger()
    outcome = boundary.prove_composed_control_term(
        loop_block, term, current_cs=outputs.get("cs"), callbacks=_CALLBACKS, ledger=ledger,
    )
    assert outcome.normalized is not None
    assert constant_bitvector(outcome.normalized) == (0x1208, 32)
    outcome.consume()
    counters = ledger.counters()
    assert counters.raw_fact_count == 1
    assert counters.normalized_fact_count == 1
    assert counters.classified_fact_count == 1
    assert counters.materialized_count == 1
    assert counters.failure_count == 0
    assert counters.closed()
    assert ledger.solver_queries >= 1


def test_countdown_head_branch_proof_through_boundary(tmp_path: Path) -> None:
    """ITE head: both arms prove; predicate retained verbatim in normalization."""
    oracle, _candidate, _manifest = _countdown_docs(tmp_path)
    head = _part_by_entry(oracle, 0x1200)
    outputs = head["outputs"]
    term = _resolved(head, outputs["control_ip"])
    assert term is not None and term.get("op") == "ite"

    ledger = boundary.ControlProofLedger()
    outcome = boundary.prove_composed_control_term(
        head, term, current_cs=outputs.get("cs"), callbacks=_CALLBACKS, ledger=ledger,
    )
    assert outcome.normalized is not None and outcome.normalized.get("op") == "ite"
    assert outcome.normalized["args"][0] == term["args"][0]
    assert constant_bitvector(outcome.normalized["args"][1]) == (0x120C, 32)
    assert constant_bitvector(outcome.normalized["args"][2]) == (0x1210, 32)


def test_unproved_term_classified_not_materialized(tmp_path: Path) -> None:
    """A refused real proof is classified-but-unmaterialized → closed() False."""
    oracle, _candidate, _manifest = _countdown_docs(tmp_path)
    loop_block = _part_by_entry(oracle, 0x120C)
    outputs = loop_block["outputs"]
    term = _resolved(loop_block, outputs["control_ip"])
    assert term is not None
    # Perturb a literal so the term no longer denotes the destination.
    changed = {
        "op": "add", "width": 32,
        "args": [term["args"][0], {"op": "zext", "width": 32,
                                   "args": [{"op": "const", "value": "0x0001", "width": 16}]}],
    }
    ledger = boundary.ControlProofLedger()
    outcome = boundary.prove_composed_control_term(
        loop_block, changed, current_cs=outputs.get("cs"), callbacks=_CALLBACKS, ledger=ledger,
    )
    assert outcome.normalized is None
    counters = ledger.counters()
    assert counters.classified_fact_count == 1
    assert counters.materialized_count == 0
    assert counters.failure_count == 1
    assert not counters.closed()


def test_public_shifted_call_caller_passes(tmp_path: Path) -> None:
    """Public regression (unpatched): region-proven shifted call comparison."""
    oracle, candidate_ssa, mapping = _shifted_call_docs(tmp_path)
    compared = cssa.compare_ssa_documents(
        oracle=oracle, candidate=candidate_ssa, mapping_document=mapping,
        max_solver_inputs=0, max_solver_assignments=0,
    )
    assert compared["region_equality"]["status"] == "passed"
    assert compared["summary"]["failed"] == 0
    assert compared["summary"]["refused"] == 0
    caller = next(r for r in compared["results"] if r["function"]["name"] == "caller")
    assert caller["status"] == "passed", caller
    assert caller["call_compare"]["proof_fact"]["proof"] == "region_equal"


def _mapped_call_docs(tmp_path: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Lower a native caller/callee pair with independently shifted locations."""
    original_image = bytearray(0x300)
    candidate_image = bytearray(0x300)
    original_image[0x200:0x204] = b"\xe8\x2d\x00\xc3"
    original_image[0x230:0x234] = b"\xb8\x34\x12\xc3"
    candidate_image[0x220:0x224] = b"\xe8\x3d\x00\xc3"
    candidate_image[0x260:0x264] = b"\xb8\x34\x12\xc3"
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
            _edge_function("demo.exe:callee", "callee", offset=0x0230, size=4),
        ],
        "diagnostics": [],
    }
    candidate_catalog = {
        "schema": "dosunit.functions.v1",
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
        "functions": [
            {
                "oracle_id": "demo.exe:caller", "oracle_name": "caller",
                "candidate_id": "demo.exe:caller_rebuilt", "candidate_name": "caller_rebuilt",
                "candidate_entry": {"cs": "0x0000", "ip": "0x0220", "kind": "near"},
                "sources": ["fixture"],
            },
            {
                "oracle_id": "demo.exe:callee", "oracle_name": "callee",
                "candidate_id": "demo.exe:callee_rebuilt", "candidate_name": "callee_rebuilt",
                "candidate_entry": {"cs": "0x0000", "ip": "0x0260", "kind": "near"},
                "sources": ["fixture"],
            },
        ],
    }
    oracle = cssa.lower_straightline_ssa_document(
        exe_path=original, functions_catalog=original_catalog, output_regs=("ax",)
    )
    candidate_ssa = cssa.lower_straightline_ssa_document(
        exe_path=candidate, functions_catalog=candidate_catalog, output_regs=("ax",)
    )
    return oracle, candidate_ssa, mapping


def test_public_mapped_direct_call_normalizes(tmp_path: Path) -> None:
    """Public regression: mapped direct-call target normalization."""
    oracle, candidate_ssa, mapping = _mapped_call_docs(tmp_path)
    compared = cssa.compare_ssa_documents(
        oracle=oracle, candidate=candidate_ssa, mapping_document=mapping, max_solver_inputs=0
    )
    caller = next(r for r in compared["results"] if r["function"]["name"] == "caller")
    assert caller["status"] == "passed", caller
    assert caller["call_compare"]["equivalent"] is True


def test_abi_loop_honest_refusal(tmp_path: Path) -> None:
    """Candidate compare routes the proved edge, then honestly refuses the loop.

    The composed symbolic loop-back edge proves its destination under the
    fetch domain, so the refusal advances from ``control_flow_unproved`` to
    ``loop_bound_incomplete`` — the still-missing obligation is a sound loop
    closure, which this slice does not fake.
    """
    oracle, candidate_ssa, manifest = _countdown_docs(tmp_path)
    refused = cssa.compare_ssa_abi_documents(
        oracle=oracle, candidate=candidate_ssa, abi_manifest=manifest
    )
    compared = cssa.compare_ssa_abi_documents(
        oracle=oracle, candidate=candidate_ssa, abi_manifest=manifest, max_loop_unroll=2
    )
    assert refused["summary"]["refused"] == 1
    assert compared["summary"]["refused"] == 1
    result = compared["results"][0]
    assert result["reason"] == "loop_bound_incomplete"
    oracle_summary = result["oracle_summary"]
    assert oracle_summary["reason"] == "loop_bound_incomplete"
    proofs = oracle_summary.get("control_proofs")
    assert isinstance(proofs, dict) and proofs["classified_fact_count"] >= 1
    assert any(
        attempt.get("verdict") == "proven" for attempt in proofs.get("attempts", [])
    )


def test_e8cbff_negative_still_refuses_through_boundary(tmp_path: Path) -> None:
    """Mandatory negative through the real adapter: E8 CB FF never binds 0x1000."""
    image = bytearray(0x40)
    image[0x00:0x04] = b"\x31\xc0\xc3\x90"
    image[0x32:0x36] = b"\xe8\xcb\xff\xc3"
    exe = tmp_path / "wrap.exe"
    exe.write_bytes(_mz_exe(bytes(image)))
    catalog = {
        "schema": "dosunit.functions.v1",
        "module": "wrap.exe",
        "program_kind": "mz_exe",
        "functions": [
            _edge_function("wrap.exe:caller", "caller", offset=0x0032, size=4),
            _edge_function("wrap.exe:callee", "callee", offset=0x0000, size=3),
        ],
        "diagnostics": [],
    }
    doc = cssa.lower_straightline_ssa_document(
        exe_path=exe, functions_catalog=catalog, output_regs=cssa.INTERNAL_STATE_REGS,
        follow_call_fallthrough=False,
    )
    caller = _part_by_entry(doc, 0x1032)
    term = _resolved(caller, caller["outputs"]["control_ip"])
    assert term is not None and constant_bitvector(term) is None
    outcome = boundary.prove_call_bound_output(
        caller, term, output_name="control_ip",
        bound_values={0x1000}, logical_ip=0x0000,
        current_cs=caller["outputs"].get("cs"), callbacks=_CALLBACKS,
    )
    assert outcome.value is None
    assert outcome.verdict is rt.ControlProofVerdict.UNKNOWN_REFUSE
    assert outcome.failure is rt.ControlDomainFailure.TERMINAL_DECODE_MISMATCH
    transfer = caller["source"]["transfer"]
    assert "target" not in transfer
    assert transfer["native_target_refusal"] == "terminal_jump_selector_window_unproved"
    assert outcome.ledger.counters().classified_fact_count == 1
    assert outcome.ledger.counters().materialized_count == 0
    assert outcome.ledger.counters().failure_count == 1
    assert not outcome.ledger.counters().closed()


def test_solver_deadline_rejects_late_unsat(monkeypatch: pytest.MonkeyPatch) -> None:
    """A query finishing after the shared deadline cannot publish a proof."""
    clock = [10.0]
    monkeypatch.setattr(time, "monotonic", lambda: clock[0])

    class SlowSolver:
        def set(self, _name: str, _value: int) -> None:
            pass

        def check(self) -> Any:
            clock[0] = 10.3
            return z3.unsat

    budget = rt.ControlProofBudget(deadline=10.25)
    with pytest.raises(TimeoutError):
        rt._bounded_solver_check(SlowSolver(), budget)


def test_solver_deadline_shrinks_each_query_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every query uses remaining time, even without a signal alarm."""
    clock = [10.0]
    monkeypatch.setattr(time, "monotonic", lambda: clock[0])
    timeouts: list[int] = []

    class TimedSolver:
        def set(self, name: str, value: int) -> None:
            assert name == "timeout"
            timeouts.append(value)

        def check(self) -> Any:
            clock[0] += 0.1
            return z3.sat

    budget = rt.ControlProofBudget(deadline=10.25)
    solver = TimedSolver()
    rt._bounded_solver_check(solver, budget)
    rt._bounded_solver_check(solver, budget)
    assert 240 <= timeouts[0] <= 250
    assert 140 <= timeouts[1] <= 150
    clock[0] = 10.3
    with pytest.raises(TimeoutError):
        rt._bounded_solver_check(solver, budget)
    assert len(timeouts) == 2


def test_refused_control_proof_cannot_be_consumed() -> None:
    """A caller cannot account a refusal as materialized semantic evidence."""
    ledger = boundary.ControlProofLedger()
    result = boundary._refusal(ledger, "test", {}, rt.ControlDomainFailure.TERM_UNENCODABLE)
    with pytest.raises(cssa.DosUnitError):
        result.consume()
    assert ledger.materialized_count == 0


def test_one_consumed_product_does_not_hide_another_unconsumed_product() -> None:
    """Aggregate positive counts cannot conceal a lost second proof product."""
    leaf = {"op": "input", "name": "cs", "width": 16}
    first, _counts, ledger = _run_shared_dag_attempt(leaf, leaf)
    # Create a second valid product on the same ledger, mirroring two outputs.
    ledger.raw_fact_count += 1
    ledger.normalized_fact_count += 1
    ledger.record_verdict(first.proof, role="test.second", domain={}, encoded_nodes=0, produced=True)
    first.consume()
    assert ledger.counters().closed()  # The coarse authoritative invariant alone is insufficient.
    assert ledger.accounting_failure() is boundary.ControlEvidenceFailure.UNMATERIALIZED


def test_public_solver_refuses_unmaterialized_control_evidence(monkeypatch: pytest.MonkeyPatch) -> None:
    """The public solve seam cannot bypass failed accounting via quick equality."""
    failure = boundary.ControlEvidenceFailure.UNMATERIALIZED
    monkeypatch.setattr(cssa, "_prepare_call_normalized_functions", lambda *_args, **_kwargs: ({}, {}, {
        "control_proof_failure": failure,
    }))
    result, solver_ms = cssa._solve_normalized_ssa_pair(
        {}, {}, {}, {}, call_compare={}, skip_binary_equal=False,
        max_solver_assignments=100, max_solver_inputs=100, max_solver_memory_stores=100,
        timeout_ms=100, max_rss_mb=0,
    )
    assert result["status"] == "refused"
    assert result["reason"] == failure.value
    assert solver_ms == 0


def test_abi_summary_refuses_lost_control_product(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A completed native RET cannot hide a classified but lost control product."""
    oracle, _candidate, _mapping = _shifted_call_docs(tmp_path)
    callee = _part_by_entry(oracle, 0x1215)
    original = cssa._compose_abi_state

    def composed(*args: Any, **kwargs: Any) -> Any:
        result = original(*args, **kwargs)
        ledger = boundary.ControlProofLedger(raw_fact_count=1, normalized_fact_count=1)
        ledger.record_verdict(_stub_proof(rt.ControlProofVerdict.PROVEN, 0x1210),
                              role="test.lost", domain={}, encoded_nodes=0, produced=True)
        kwargs["compose_stats"]["control_proofs"] = ledger
        return result

    monkeypatch.setattr(cssa, "_compose_abi_state", composed)
    result = cssa._summarize_abi_function(
        [callee], abi_function={"name": "callee", "kind": "near", "returns": ["ax"]},
        observables={"regs": ["ax"], "whole_memory": False}, data_segment_para=0x100,
        require_complete_paths=True,
    )
    assert result["status"] == "refused"
    assert result["reason"] == boundary.ControlEvidenceFailure.UNMATERIALIZED.value
    assert result["control_proofs"]["classified_fact_count"] == 1
    assert result["control_proofs"]["materialized_count"] == 0
    assert result["control_proofs"]["pending_products"] == 1


def test_branch_arms_share_the_query_budget(tmp_path: Path) -> None:
    """A two-query budget cannot independently fund both conditional arms."""
    oracle, _candidate, _manifest = _countdown_docs(tmp_path)
    head = _part_by_entry(oracle, 0x1200)
    outputs = head["outputs"]
    term = _resolved(head, outputs["control_ip"])
    assert term is not None
    inputs = cssa._z3_inputs({"inputs": head["inputs"]}, {"inputs": []}, z3)
    context = boundary._EncodeContext(
        document=head, inputs=inputs, z3=z3, callbacks=_CALLBACKS,
        assignments={item["id"]: item for item in head["assignments"]},
        deadline=time.monotonic() + 5.0, max_nodes=8192,
    )
    normalized, proof = rt.prove_branch_destinations(
        head, term, current_cs=outputs.get("cs"), encode_term=context.encode,
        z3=z3, budget=rt.ControlProofBudget(max_queries=2),
    )
    assert normalized is None
    assert proof.failure is rt.ControlDomainFailure.BUDGET_EXHAUSTED
    assert proof.stats.queries <= 2


def test_branch_arms_reuse_premise_within_four_query_budget(tmp_path: Path) -> None:
    """One common fetch premise lets both native arms fit four total queries."""
    from tools.dosunit.tests.test_real16_control_target_proof import _encoder, _leaf_specs

    oracle, _candidate, _manifest = _countdown_docs(tmp_path)
    head = _part_by_entry(oracle, 0x1200)
    term = _resolved(head, head["outputs"]["control_ip"])
    assert term is not None
    current_cs = head["outputs"]["cs"]
    inputs = cssa._z3_inputs(
        {"inputs": _leaf_specs(head, term, current_cs)}, {"inputs": []}, z3,
    )
    normalized, proof = rt.prove_branch_destinations(
        head, term, current_cs=current_cs, encode_term=_encoder(head, inputs),
        z3=z3, budget=rt.ControlProofBudget(max_queries=4),
    )
    assert proof.verdict is rt.ControlProofVerdict.PROVEN, proof.failure
    assert normalized is not None
    assert proof.stats.queries <= 4


def test_relocation_rewrite_cannot_repair_a_corrupt_control_term(tmp_path: Path) -> None:
    """Native control theorems must encode raw terms, never relocation rewrites."""
    oracle, _candidate, _mapping = _shifted_call_docs(tmp_path)
    caller = _part_by_entry(oracle, 0x1200)
    outputs = caller["outputs"]
    term = _resolved(caller, outputs["control_ip"])
    assert term is not None
    # The added 32-bit one is a real changed control effect. A value rewrite
    # of one to zero must not make its native-target theorem become proved.
    corrupt = {"op": "add", "width": 32, "args": [term, {"op": "const", "width": 32, "value": "0x1"}]}
    caller["_constant_normalization"] = {1: 0}
    ledger = boundary.ControlProofLedger()
    result = boundary.prove_call_bound_output(
        caller, corrupt, output_name="control_ip", bound_values={0x1210}, logical_ip=0x210,
        current_cs=outputs.get("cs"), callbacks=_CALLBACKS, ledger=ledger,
    )
    assert result.value is None
    assert result.failure is rt.ControlDomainFailure.DESTINATION_UNPROVED


def test_native_fetch_domain_schema_rejects_incomplete_marker(tmp_path: Path) -> None:
    """The public artifact schema accepts generated facts and rejects missing fields."""
    import copy

    import jsonschema

    oracle, _candidate, _mapping = _shifted_call_docs(tmp_path)
    root = Path(__file__).resolve().parents[3]
    schema = json.loads((root / "tools/dosunit/schemas/dosunit.ssa.v1.schema.json").read_text())
    validator = jsonschema.Draft202012Validator(schema)
    validator.validate(oracle)
    incomplete = copy.deepcopy(oracle)
    incomplete["functions"][0]["source"]["control_domain"].pop("terminal_linear")
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(incomplete)


def test_preclassification_timeout_is_a_typed_proof_refusal() -> None:
    """A timeout before any solver verdict still blocks equality promotion."""
    ledger = boundary.ControlProofLedger(raw_fact_count=1)
    boundary._refusal(ledger, "test.timeout", {}, rt.ControlDomainFailure.BUDGET_EXHAUSTED)
    assert ledger.classified_fact_count == 0
    assert ledger.counters().closed()
    assert ledger.accounting_failure() is boundary.ControlEvidenceFailure.PROOF_REFUSED
    assert not ledger.document()["closed"]


def test_expired_call_proof_is_public_refusal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Exhausted native-target normalization cannot become a modeled mismatch."""
    oracle, candidate_ssa, mapping = _mapped_call_docs(tmp_path)
    monkeypatch.setattr(boundary, "CONTROL_PROOF_ATTEMPT_SECONDS", 0.0)
    compared = cssa.compare_ssa_documents(
        oracle=oracle, candidate=candidate_ssa, mapping_document=mapping, max_solver_inputs=0,
    )
    caller = next(r for r in compared["results"] if r["function"]["name"] == "caller")
    assert caller["status"] == "refused", caller
    assert caller["reason"] == boundary.ControlEvidenceFailure.PROOF_REFUSED.value
    normalizations = caller["call_compare"]["normalizations"]
    proof_record = next(item for item in normalizations if item.get("kind") == "call_bound_control_outputs")
    reasons = proof_record["control_proofs"]["oracle"]["failure_reasons"]
    assert reasons and all(reason == "budget_exhausted" for reason in reasons)
