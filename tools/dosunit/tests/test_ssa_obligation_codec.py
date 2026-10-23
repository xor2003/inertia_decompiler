"""Predicate evidence must survive JSON without expansion or lost constraints."""

import copy
import json

import pytest
import z3

from tools.dosunit.compare import straightline_ssa as S
from tools.dosunit.ssa.obligation_codec import ENCODING, decode_obligation, encode_bound_predicates, encode_obligation


def const(value: int, width: int = 32):
    return {"op": "const", "width": width, "value": hex(value)}


def predicate():
    x = {"op": "input", "width": 32, "name": "eax"}
    return {"op": "eq", "width": 1, "args": [x, const(7)]}


def record(term=None):
    return {"kind": "x87_pending_check", "predicate": predicate() if term is None else term,
            "literal_constants": True, "site": {"entry": "0x1000"}}


def test_shared_predicate_json_roundtrip_preserves_formula():
    term = {"op": "input", "name": "eax", "width": 32}
    for _ in range(24):
        term = {"op": "add", "width": 32, "args": [term, term], "annotation": "retained"}
    source = record(term)
    packed = encode_obligation(source)
    raw = json.dumps(packed)
    assert len(raw) < 5000
    unpacked = decode_obligation(json.loads(raw))
    assert unpacked["args"][0] is unpacked["args"][1]
    assert unpacked["annotation"] == "retained"
    assert packed["site"] == source["site"]
    assert source["predicate"] is term
    x = z3.BitVec("eax", 32)
    inputs = {"eax": (x, 32)}
    left = S._z3_obligation_term(term, document={}, inputs=inputs, z3=z3)
    right = S._z3_obligation_term(unpacked, document={}, inputs=inputs, z3=z3)
    solver = z3.Solver()
    solver.add(left != right)
    assert solver.check() == z3.unsat
    assert encode_obligation(packed) == packed


def test_deep_predicate_codec_does_not_recurse():
    term = const(0)
    for _ in range(2000):
        term = {"op": "add", "width": 32, "args": [term, const(1)]}
    packed = encode_obligation(record(term))
    assert len(packed["predicate_assignments"]) == 2000
    restored = decode_obligation(json.loads(json.dumps(packed)))
    count = 0
    while restored["op"] == "add":
        count += 1
        restored = restored["args"][0]
    assert count == 2000


def test_completed_report_preserves_shared_records_and_verdict():
    obligation = record()
    original = {"status": "failed", "domain_obligations": [obligation],
                "x87_assumptions": {"obligations": [obligation]}}
    result = encode_bound_predicates(original)
    first = result["domain_obligations"][0]
    assert first is result["x87_assumptions"]["obligations"][0]
    assert first["predicate_encoding"] == ENCODING
    assert "predicate_encoding" not in obligation
    assert result["status"] == "failed"
    assert encode_bound_predicates(result) == result


def test_many_independent_records_do_not_reuse_temporary_object_ids():
    records = []
    for value in range(128):
        term = predicate()
        term["args"][1] = const(value)
        for _ in range(12):
            term = {"op": "and", "width": 1, "args": [term, term]}
        records.append(record(term))
    packed = encode_bound_predicates({"domain_obligations": records})
    restored = json.loads(json.dumps(packed))
    for value, item in enumerate(restored["domain_obligations"]):
        term = decode_obligation(item)
        for _ in range(12):
            assert term["args"][0] is term["args"][1]
            term = term["args"][0]
        assert term["args"][1] == const(value)


@pytest.mark.parametrize("leaf", [const(1, 1),
    {"op": "input", "name": "eax", "width": 32},
    {"op": "mem_input", "name": "mem", "addr_width": 32, "value_width": 8}])
def test_leaf_fields_survive(leaf):
    assert decode_obligation(encode_obligation(record(leaf))) == leaf


@pytest.mark.parametrize("kind", ["encoding", "missing", "duplicate", "forward", "cycle",
                                  "dangling", "mixed_ref", "bad_arg", "inline_operator"])
def test_invalid_encoded_evidence_is_rejected(kind):
    packed = encode_obligation(record())
    definitions = packed["predicate_assignments"]
    if kind == "encoding":
        packed["predicate_encoding"] = "unknown"
    elif kind == "missing":
        del packed["predicate_assignments"]
    elif kind == "duplicate":
        definitions.append(copy.deepcopy(definitions[0]))
    elif kind in {"forward", "cycle"}:
        definitions[0]["args"][0] = {"ref": "p0" if kind == "cycle" else "p1"}
    elif kind == "dangling":
        packed["predicate"] = {"ref": "missing"}
    elif kind == "mixed_ref":
        packed["predicate"]["op"] = "const"
    elif kind == "bad_arg":
        definitions[0]["args"][0] = 7
    else:
        packed["predicate"] = predicate()
    with pytest.raises(ValueError):
        decode_obligation(packed)


@pytest.mark.parametrize("kind", ["cycle", "borrowed_ref", "bad_arg"])
def test_invalid_inline_evidence_cannot_be_silently_encoded(kind):
    term = predicate()
    term["args"][0] = term if kind == "cycle" else {"ref": "borrowed"} if kind == "borrowed_ref" else 7
    with pytest.raises(ValueError):
        encode_obligation(record(term))


@pytest.mark.parametrize("case", ["valid", "vacuous", "missing_input", "malformed"])
def test_serialized_obligation_is_enforced_by_actual_comparator(case):
    term = predicate()
    if case == "vacuous":
        term = {"op": "and", "width": 1, "args": [term,
            {"op": "eq", "width": 1, "args": [term["args"][0], const(8)]}]}
    packed = encode_obligation(record(term))
    if case == "malformed":
        packed["predicate"] = {"ref": "missing"}
    inputs = [] if case == "missing_input" else [{"name": "eax", "width": 32}]
    left = {"outputs": {"eax": const(0)}, "assignments": [], "inputs": inputs, "obligations": [packed]}
    right = {"outputs": {"eax": const(1)}, "assignments": [], "inputs": []}
    result = S._compare_functions(left, right, timeout_ms=1000)
    expected = {"valid": "observable_mismatch", "vacuous": "domain_obligation_vacuous",
                "missing_input": "domain_obligation_unenforceable", "malformed": "domain_obligation_encoding_invalid"}
    assert result["reason"] == expected[case], result
    assert result["status"] == ("failed" if case == "valid" else "refused")
    if case == "valid":
        assert result["domain_obligations"][0]["predicate_encoding"] == ENCODING
