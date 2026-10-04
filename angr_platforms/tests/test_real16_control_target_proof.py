"""Native-bound real16 control-target proof and corruption controls.

Layer: dosunit regression tests.
Responsibility: bind symbolic control proofs to recorded native instructions,
retain conditional predicates, and reject foreign domains, stale hashes,
physical-address aliases and selector-dependent wraparound.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from tools.dosunit import real16_control_targets as rt
from tools.dosunit import straightline_ssa as ssa
from tools.dosunit.ssa_constant_terms import constant_bitvector

z3 = pytest.importorskip("z3")


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
    header[0x06:0x08] = (0).to_bytes(2, "little")
    header[0x08:0x0A] = (header_size // 16).to_bytes(2, "little")
    header[0x0A:0x0C] = (0x1000).to_bytes(2, "little")
    header[0x0C:0x0E] = (0xFFFF).to_bytes(2, "little")
    header[0x0E:0x10] = (0x0080).to_bytes(2, "little")
    header[0x10:0x12] = (0xFFFE).to_bytes(2, "little")
    header[0x14:0x16] = (0).to_bytes(2, "little")
    header[0x16:0x18] = (0).to_bytes(2, "little")
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
    """Local hex-or-int parse for the staged boundary."""
    return ssa._optional_int(value)


def _dfield(node: dict[str, Any], key: str) -> dict[str, Any]:
    """Return ``node[key]`` as a dict, or ``{}`` when absent/foreign."""
    value = node.get(key)
    return value if isinstance(value, dict) else {}


def _assignments(part: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Index one part's assignments by id."""
    return {
        str(item["id"]): item
        for item in part.get("assignments", []) or []
        if isinstance(item, dict) and "id" in item
    }


def _resolved(part: dict[str, Any], term: dict[str, Any]) -> dict[str, Any] | None:
    """Resolve a top-level ``ref`` output to its assignment body."""
    if not isinstance(term, dict):
        return None
    ref = term.get("ref")
    if isinstance(ref, str):
        resolved = _assignments(part).get(ref)
        return resolved if isinstance(resolved, dict) else None
    return term


def _inject_domain_facts(document: dict[str, Any], arch: object) -> int:
    """Apply the proposed ``_record_lowered_part`` domain emission in-place.

    This replicates the proposed producer wiring for staged controls: the
    marker is produced by ``producer_domain_fact`` from the genuine lifter
    arch object — never synthesized from output fields.
    """
    count = 0
    for part in document.get("functions", []) or []:
        if not isinstance(part, dict):
            continue
        source = _dfield(part, "source")
        head = _opt_int(_dfield(part, "entry").get("linear"))
        instructions = [i for i in source.get("instructions", []) or [] if isinstance(i, dict)]
        if not source or head is None or not instructions:
            continue
        terminal = _opt_int(_dfield(instructions[-1], "address").get("linear")) or head
        fact = rt.producer_domain_fact(arch, head_linear=head, terminal_linear=terminal)
        if fact is not None:
            source["control_domain"] = fact
            count += 1
    return count


def _leaf_specs(part: dict[str, Any], *terms: Any) -> list[dict[str, Any]]:
    """Collect declared and walked input leaves for a proof boundary."""
    specs: dict[str, dict[str, Any]] = {}
    for item in part.get("inputs", []) or []:
        if isinstance(item, dict) and item.get("name"):
            specs[str(item["name"])] = dict(item)
    assignments = _assignments(part)
    for term in terms:
        if not isinstance(term, dict):
            continue
        walked = rt.term_input_leaves(term, assignments=assignments)
        if walked is not None:
            for leaf in walked[0]:
                specs[str(leaf["name"])] = leaf
    return list(specs.values())


def _encoder(part: dict[str, Any], inputs: dict[str, tuple[Any, int]]) -> Any:
    """Z3 boundary callback matching the proposed integration's encoder.

    Reuses ``_z3_term`` for leaves/ref roots and ``_z3_apply`` for inline
    composite nodes — exactly the staged callback contract.
    """
    assignments = _assignments(part)

    def encode(node: dict[str, Any]) -> Any:
        if "ref" in node:
            return ssa._z3_term(
                node, document=part, inputs=inputs, z3=z3, assignments=assignments, cache={}
            )
        op = node.get("op")
        if op in {"input", "mem_input", "const"}:
            return ssa._z3_term(node, document=part, inputs=inputs, z3=z3)
        args = [encode(arg) for arg in node.get("args", []) or [] if isinstance(arg, dict)]
        return ssa._z3_apply(str(op), int(node.get("width", 16)), args, z3)

    return encode


def _prove_control(part: dict[str, Any], term: dict[str, Any], current_cs: dict[str, Any] | None) -> Any:
    """Shared staged encode+prove for one control term on one part."""
    inputs = ssa._z3_inputs({"inputs": _leaf_specs(part, term, current_cs)}, {"inputs": []}, z3)
    return rt.prove_control_term(
        part, term, current_cs=current_cs, encode_term=_encoder(part, inputs), z3=z3
    )


def _prove_scalar(part: dict[str, Any], term: dict[str, Any], current_cs: dict[str, Any] | None,
                  candidates: set[int], **kwargs: Any) -> Any:
    """Shared staged scalar proof for one part."""
    inputs = ssa._z3_inputs({"inputs": _leaf_specs(part, term, current_cs)}, {"inputs": []}, z3)
    return rt.prove_term_destination(
        part,
        term,
        current_cs=current_cs,
        candidates=candidates,
        encode_term=_encoder(part, inputs),
        z3=z3,
        **kwargs,
    )


def _prove_call_output(part: dict[str, Any], name: str, *, bound_values: set[int],
                       logical_ip: int | None, current_cs: dict[str, Any] | None,
                       **kwargs: Any) -> Any:
    """Prove one call-bound control output on one lowered part."""
    term = _resolved(part, (part.get("outputs") or {}).get(name) or {})
    assert isinstance(term, dict)
    inputs = ssa._z3_inputs({"inputs": _leaf_specs(part, term, current_cs)}, {"inputs": []}, z3)
    return rt.prove_call_control_output(
        part,
        term,
        output_name=name,
        bound_values=bound_values,
        logical_ip=logical_ip,
        current_cs=current_cs,
        encode_term=_encoder(part, inputs),
        z3=z3,
        **kwargs,
    )


def _part_by_entry(document: dict[str, Any], linear: int) -> dict[str, Any]:
    """Locate one lowered part by exact physical entry."""
    for part in document.get("functions", []) or []:
        if isinstance(part, dict) and _opt_int(_dfield(part, "entry").get("linear")) == linear:
            return part
    raise AssertionError(f"no part at {hex(linear)}")


def _shifted_call_docs(tmp_path: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Lower the shifted-call pair used by the region-proven red test."""
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
    oracle = ssa.lower_straightline_ssa_document(
        exe_path=original,
        functions_catalog=original_catalog,
        output_regs=ssa.INTERNAL_STATE_REGS,
        follow_call_fallthrough=False,
    )
    candidate = ssa.lower_straightline_ssa_document(
        exe_path=candidate,
        functions_catalog=candidate_catalog,
        output_regs=ssa.INTERNAL_STATE_REGS,
        follow_call_fallthrough=False,
    )
    return oracle, candidate, mapping


def _countdown_docs(tmp_path: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Lower the bounded-loop countdown pair used by the ABI red test."""
    image = bytearray(0x240)
    image[0x200:0x214] = bytes.fromhex("558bec31c08b4e0485c97e044049ebf88be55dc3")
    original = tmp_path / "original.exe"
    candidate = tmp_path / "candidate.exe"
    original.write_bytes(_mz_exe(bytes(image)))
    candidate.write_bytes(_mz_exe(bytes(image)))
    catalog = _edge_catalog("demo.exe:countdown", "countdown", offset=0x0200, size=0x14)
    output_regs = ("ax", "bp", "sp", "ip", "ss")
    oracle = ssa.lower_straightline_ssa_document(
        exe_path=original, functions_catalog=catalog, output_regs=output_regs,
        max_blocks_per_function=16,
    )
    candidate_ssa = ssa.lower_straightline_ssa_document(
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


def _arch_for(exe: Path) -> object:
    """The genuine lifter architecture object for one lowered image."""
    return ssa._load_lifter_project(exe).arch


def test_flat32_domain_marker_refused() -> None:
    """A non-real16 arch object must never emit a fetch-domain marker."""

    class _Flat32:
        name = "amd64"
        bits = 32
        control_address_domain = "flat32_linear"

    assert rt.producer_domain_fact(_Flat32(), head_linear=0x1200) is None
    assert rt.producer_domain_fact(object(), head_linear=0x1200) is None


def test_shifted_call_control_output_proven(tmp_path: Path) -> None:
    """Positive: the lifted shifted-call control term denotes 0x1210 for all fetch CS."""
    oracle, _candidate, _mapping = _shifted_call_docs(tmp_path)
    exe = tmp_path / "original.exe"
    arch = _arch_for(exe)
    assert _inject_domain_facts(oracle, arch) == 4
    caller = _part_by_entry(oracle, 0x1200)
    outputs = caller["outputs"]
    before = json.dumps({k: v for k, v in outputs.items() if k not in {"ip", "control_ip"}},
                        sort_keys=True)

    outcome = _prove_call_output(
        caller, "control_ip",
        bound_values={0x1210}, logical_ip=0x210, current_cs=outputs.get("cs"),
    )
    assert outcome.proven and outcome.value == 0x1210

    outcome_ip = _prove_call_output(
        caller, "ip",
        bound_values={0x1210}, logical_ip=0x210, current_cs=outputs.get("cs"),
    )
    assert outcome_ip.proven and outcome_ip.value == 0x1210

    after = json.dumps({k: v for k, v in outputs.items() if k not in {"ip", "control_ip"}},
                       sort_keys=True)
    assert before == after  # non-control observables untouched


def test_countdown_scalar_control_proven(tmp_path: Path) -> None:
    """Positive: the loop-back edge term denotes 0x1208 under the whole fetch window."""
    oracle, _candidate, _manifest = _countdown_docs(tmp_path)
    arch = _arch_for(tmp_path / "original.exe")
    assert _inject_domain_facts(oracle, arch) == 4
    loop_block = _part_by_entry(oracle, 0x120C)
    outputs = loop_block["outputs"]
    term = _resolved(loop_block, outputs["control_ip"])
    assert term is not None and constant_bitvector(term) is None  # genuinely symbolic

    outcome = _prove_scalar(
        loop_block, term, outputs.get("cs"), {0x1208},
    )
    assert outcome.proven and outcome.value == 0x1208


def test_countdown_branch_arms_proven(tmp_path: Path) -> None:
    """Positive: the countdown conditional's arms cover the decoded successor set."""
    oracle, _candidate, _manifest = _countdown_docs(tmp_path)
    arch = _arch_for(tmp_path / "original.exe")
    _inject_domain_facts(oracle, arch)
    head = _part_by_entry(oracle, 0x1200)
    outputs = head["outputs"]
    term = _resolved(head, outputs["control_ip"])
    assert term is not None and term.get("op") == "ite"
    inputs = ssa._z3_inputs({"inputs": _leaf_specs(head, term, outputs.get("cs"))}, {"inputs": []}, z3)
    normalized, outcome = rt.prove_branch_destinations(
        head, term, current_cs=outputs.get("cs"), encode_term=_encoder(head, inputs), z3=z3
    )
    assert outcome.verdict is rt.ControlProofVerdict.PROVEN and normalized is not None
    assert normalized["args"][0] == term["args"][0]  # original predicate retained verbatim
    assert constant_bitvector(normalized["args"][1]) == (0x120C, 32)
    assert constant_bitvector(normalized["args"][2]) == (0x1210, 32)


def test_e8cbff_high_selector_counterexample_refuses(tmp_path: Path) -> None:
    """Mandatory negative: E8 CB FF at 0x1032 must never bind to 0x1000.

    Under CS=0x0103/IP=0x0002 the same native bytes fetch, but the physical
    destination is 0x11000, not the decoded linear target 0x1000 — any
    binding claiming 0x1000 is unsound and must refuse.
    """
    image = bytearray(0x40)
    image[0x00:0x04] = b"\x31\xc0\xc3\x90"  # callee head at linear 0x1000
    image[0x32:0x36] = b"\xe8\xcb\xff\xc3"  # call 0x1000; ret — head 0x1032
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
    doc = ssa.lower_straightline_ssa_document(
        exe_path=exe, functions_catalog=catalog, output_regs=ssa.INTERNAL_STATE_REGS,
        follow_call_fallthrough=False,
    )
    _inject_domain_facts(doc, _arch_for(exe))
    caller = _part_by_entry(doc, 0x1032)
    term = _resolved(caller, caller["outputs"]["control_ip"])
    assert term is not None and constant_bitvector(term) is None
    outcome = _prove_call_output(
        caller, "control_ip",
        bound_values={0x1000}, logical_ip=0x0000, current_cs=caller["outputs"].get("cs"),
    )
    assert not outcome.proven
    assert outcome.failure is rt.ControlDomainFailure.DESTINATION_UNPROVED


def test_shifted_call_negative_mutations(tmp_path: Path) -> None:
    """Each independent mutation must refuse without normalizing the term."""
    oracle, _candidate, _mapping = _shifted_call_docs(tmp_path)
    arch = _arch_for(tmp_path / "original.exe")
    _inject_domain_facts(oracle, arch)
    caller = _part_by_entry(oracle, 0x1200)
    base_term = _resolved(caller, caller["outputs"]["control_ip"])
    assert base_term is not None
    cs_term = caller["outputs"].get("cs")

    cases: list[tuple[str, dict[str, Any], dict[str, Any], dict[str, Any] | None, Any]] = []

    missing = copy.deepcopy(caller)
    missing["source"].pop("control_domain")
    cases.append(("missing_fact", missing, base_term, cs_term, rt.ControlDomainFailure.DOMAIN_FACT_MISSING))

    stale = copy.deepcopy(caller)
    stale["source"]["control_domain"]["head_linear"] = "0x1300"
    cases.append(("stale_head", stale, base_term, cs_term, rt.ControlDomainFailure.DOMAIN_HEAD_MISMATCH))

    tampered_window = copy.deepcopy(caller)
    tampered_window["source"]["control_domain"]["selector_max"] = "0xffff"
    cases.append(("tampered_window", tampered_window, base_term, cs_term,
                  rt.ControlDomainFailure.DOMAIN_WINDOW_MISMATCH))

    forged_terminal = copy.deepcopy(caller)
    # Internally consistent forged window: recompute(0x1200, 0x10ff0) is
    # [0x100, 0x120], excluding real low selectors.  The premise must stay
    # bound to the sha-verified last-instruction linear, so this refuses.
    forged_terminal["source"]["control_domain"].update(
        terminal_linear="0x10ff0", selector_min="0x0100"
    )
    cases.append(("forged_terminal", forged_terminal, base_term, cs_term,
                  rt.ControlDomainFailure.DOMAIN_TERMINAL_MISMATCH))

    foreign_arch = copy.deepcopy(caller)
    foreign_arch["source"]["control_domain"]["arch"] = "amd64"
    cases.append(("foreign_arch", foreign_arch, base_term, cs_term,
                  rt.ControlDomainFailure.DOMAIN_ARCH_MISMATCH))

    foreign_kind = copy.deepcopy(caller)
    foreign_kind["source"]["control_domain"]["kind"] = "flat32_selector"
    cases.append(("foreign_kind", foreign_kind, base_term, cs_term,
                  rt.ControlDomainFailure.DOMAIN_FACT_MALFORMED))

    bad_hash = copy.deepcopy(caller)
    bad_hash["source"]["machine_code_sha256"] = "00" * 32
    cases.append(("tampered_sha256", bad_hash, base_term, cs_term,
                  rt.ControlDomainFailure.MACHINE_CODE_MISMATCH))

    bad_size = copy.deepcopy(caller)
    bad_size["source"]["machine_code_size"] = "0x9999"
    cases.append(("tampered_size", bad_size, base_term, cs_term,
                  rt.ControlDomainFailure.MACHINE_CODE_MISMATCH))

    mutated_bytes = copy.deepcopy(caller)
    mutated_bytes["source"]["instructions"][-1]["bytes"] = "909090"  # was c3 ret
    cases.append(("tampered_terminal_bytes", mutated_bytes, base_term, cs_term,
                  rt.ControlDomainFailure.MACHINE_CODE_MISMATCH))

    swapped_entry = copy.deepcopy(caller)
    swapped_entry["entry"]["linear"] = "0x1300"
    cases.append(("foreign_part_entry", swapped_entry, base_term, cs_term,
                  rt.ControlDomainFailure.DOMAIN_HEAD_MISMATCH))

    changed_term = copy.deepcopy(base_term)
    # Perturb one literal inside the add/v6 subterm so term != target somewhere in-window.
    changed_term["args"][1] = {"op": "zext", "width": 32,
                               "args": [{"op": "const", "value": "0x00f1", "width": 16}]}
    cases.append(("changed_term_literal", caller, changed_term, cs_term,
                  rt.ControlDomainFailure.DESTINATION_UNPROVED))

    cases.append(("foreign_cs_input", caller, base_term,
                  {"op": "input", "name": "ds", "width": 16},
                  rt.ControlDomainFailure.CS_BINDING_FOREIGN))
    cases.append(("missing_cs", caller, base_term, None,
                  rt.ControlDomainFailure.CS_BINDING_MISSING))
    cases.append(("cs_outside_window", caller, base_term,
                  {"op": "const", "value": "0x0500", "width": 16},
                  rt.ControlDomainFailure.FETCH_PREMISE_UNSAT))

    for label, part, term, cs, expected in cases:
        outcome = _prove_scalar(part, term, cs, {0x1210})
        assert not outcome.proven, label
        if expected is not None:
            assert outcome.failure is expected, (label, outcome.failure)

    budget = rt.ControlProofBudget(max_queries=0)
    outcome = _prove_scalar(caller, base_term, cs_term, {0x1210}, budget=budget)
    assert not outcome.proven and outcome.failure is rt.ControlDomainFailure.BUDGET_EXHAUSTED

    high_alias = _prove_scalar(caller, base_term, cs_term, {0x11210})
    assert not high_alias.proven  # 0x11210 is a low-word alias, not a reachable destination

    wide_candidate = _prove_scalar(
        caller, {"op": "const", "value": "0x1210", "width": 16}, cs_term, {0x11210}
    )
    assert not wide_candidate.proven  # never bind a 16-bit term to a >16-bit destination


def test_call_decode_binding_refuses_foreign_target(tmp_path: Path) -> None:
    """Decoded E8 destination outside bound_values must refuse (target mismatch)."""
    oracle, _candidate, _mapping = _shifted_call_docs(tmp_path)
    _inject_domain_facts(oracle, _arch_for(tmp_path / "original.exe"))
    caller = _part_by_entry(oracle, 0x1200)
    outcome = _prove_call_output(
        caller, "control_ip",
        bound_values={0x1400}, logical_ip=0x210, current_cs=caller["outputs"].get("cs"),
    )
    assert not outcome.proven and outcome.failure is rt.ControlDomainFailure.TERMINAL_DECODE_MISMATCH


def test_branch_negative_mutations(tmp_path: Path) -> None:
    """Malformed/swapped/changed branch conditionals refuse or stay unchanged."""
    oracle, _candidate, _manifest = _countdown_docs(tmp_path)
    _inject_domain_facts(oracle, _arch_for(tmp_path / "original.exe"))
    head = _part_by_entry(oracle, 0x1200)
    outputs = head["outputs"]
    term = _resolved(head, outputs["control_ip"])
    assert term is not None
    cs_term = outputs.get("cs")
    inputs = ssa._z3_inputs({"inputs": _leaf_specs(head, term, cs_term)}, {"inputs": []}, z3)
    encode = _encoder(head, inputs)

    malformed = {"op": "ite", "width": 32, "args": [term["args"][0], term["args"][1]]}
    normalized, outcome = rt.prove_branch_destinations(
        head, malformed, current_cs=cs_term, encode_term=encode, z3=z3
    )
    assert normalized is None and outcome.failure is rt.ControlDomainFailure.TERM_UNENCODABLE

    changed_arm = {"op": "ite", "width": 32,
                   "args": [term["args"][0],
                            {"op": "const", "value": "0x9999", "width": 32},
                            term["args"][2]]}
    normalized, outcome = rt.prove_branch_destinations(
        head, changed_arm, current_cs=cs_term, encode_term=encode, z3=z3
    )
    assert normalized is None and not outcome.proven

    duplicated = {"op": "ite", "width": 32,
                  "args": [term["args"][0],
                           {"op": "const", "value": "0x120c", "width": 32},
                           {"op": "const", "value": "0x120c", "width": 32}]}
    normalized, outcome = rt.prove_branch_destinations(
        head, duplicated, current_cs=cs_term, encode_term=encode, z3=z3
    )
    assert normalized is None and outcome.failure is rt.ControlDomainFailure.COVERAGE_INCOMPLETE

    swapped = {"op": "ite", "width": 32,
               "args": [term["args"][0],
                        {"op": "const", "value": "0x1210", "width": 32},
                        {"op": "const", "value": "0x120c", "width": 32}]}
    normalized, outcome = rt.prove_branch_destinations(
        head, swapped, current_cs=cs_term, encode_term=encode, z3=z3
    )
    if normalized is not None:
        # Per-position proof keeps the term's own semantics; routing follows the
        # proved values, never the recorded successor order.
        assert normalized["args"][0] == swapped["args"][0]
        assert constant_bitvector(normalized["args"][1]) == (0x1210, 32)
        assert constant_bitvector(normalized["args"][2]) == (0x120C, 32)
    else:
        assert not outcome.proven


