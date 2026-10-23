"""Root buffer premises retain writes, saved registers and circular addresses."""

import json
import time

import pytest
import z3

from tools.comparator.abi_catalog import load_abi_catalog
from tools.dosunit.compare.flat32_abi_observation import Flat32AbiObservation
from tools.dosunit.compare.straightline_ssa import _enforce_domain_obligations, _z3_obligation_term
from tools.dosunit.contracts.flat32_buffer_domain import Flat32StackDisjointBuffer
from tools.dosunit.ssa.z3_ops import apply_operator
from tools.dosunit.tests.test_flat32_abi_observation import _compare

pytestmark = pytest.mark.ssa_z3


@pytest.mark.parametrize("case,expected", [
    ("zero", "conditional"), ("missing", "refused"),
    ("range", "refused"), ("changed_return", "failed"), ("overwrite", "refused"),
])
def test_initial_singleton_can_close_callback_branch_without_hiding_writes(case, expected):
    from tools.dosunit.contracts.flat32_buffer_domain import Flat32EntryMemoryRange

    code = "a100000200 85c0 7402 ffd0 b807000000 c3"
    candidate = code.replace("b807", "b808") if case == "changed_return" else code
    if case == "overwrite":
        code = "c7050000020001000000 " + code
        candidate = code
    ranges = () if case == "missing" else (Flat32EntryMemoryRange(0x20000, 32, 0, 1 if case == "range" else 0),)
    result = _compare(code, candidate, Flat32AbiObservation(32, entry_memory_ranges=ranges))
    assert result["status"] == expected, result


def _inputs(esp: int, pointer: int):
    memory = z3.K(z3.BitVecSort(32), z3.BitVecVal(0, 8))
    memory = apply_operator("storele", 0, [memory, z3.BitVecVal(esp + 4, 32), z3.BitVecVal(pointer, 32)], z3)
    return {"esp": (z3.BitVecVal(esp, 32), 32), "mem": (memory, 0)}


@pytest.mark.parametrize("esp", [0, 1, 8, 4096, 0xffffffff])
@pytest.mark.parametrize("size", [1, 2, 16])
def test_circular_interval_matches_byte_intersection(esp: int, size: int) -> None:
    predicate = Flat32StackDisjointBuffer(0, size).obligation(12)["predicate"]
    frame = {(esp + delta) & 0xffffffff for delta in range(-12, 0)}
    for delta in range(-30, 20):
        pointer = (esp + delta) & 0xffffffff
        actual = _z3_obligation_term(predicate, document={}, inputs=_inputs(esp, pointer), z3=z3)
        buffer = {(pointer + i) & 0xffffffff for i in range(size)}
        assert bool(z3.simplify(actual).as_long()) == frame.isdisjoint(buffer), (esp, size, delta)


@pytest.mark.parametrize("case", ["good", "missing", "short", "wrong_argument", "changed_memory"])
def test_buffer_contract_preserves_complete_native_effects(case: str) -> None:
    left = "56578b44240c66c70034125f5ec3"
    right = "57568b44240c66c70034125e5fc3"
    if case == "changed_memory":
        right = right.replace("3412", "3512")
    buffers = () if case == "missing" else (Flat32StackDisjointBuffer(
        1 if case == "wrong_argument" else 0, 1 if case == "short" else 2),)
    result = _compare(left, right, Flat32AbiObservation(32, 8, buffers))
    assert result["status"] == ("conditional" if case == "good" else "failed"), result
    assert "x87_assumptions" not in result
    if case == "good":
        assert len(result["domain_obligations"]) == 2
        assert result["abi_observation"]["stack_disjoint_buffers"][0]["argument_index"] == 0


@pytest.mark.parametrize("pointer,expected", [(0xff0, None), (0xfff, "domain_obligation_vacuous")])
def test_literal_domain_not_changed_by_code_normalization(pointer: int, expected) -> None:
    obligation = Flat32StackDisjointBuffer(0, 2).obligation(8)
    document = {"obligations": [obligation], "_constant_normalization": {2: 100, 4: 200, 8: 300}}
    _, refusal = _enforce_domain_obligations(z3.Solver(), document, {}, _inputs(0x1000, pointer), z3,
                                             started=time.monotonic())
    assert (refusal["reason"] if refusal else None) == expected


def test_buffer_catalog_is_explicit_and_validated(tmp_path) -> None:
    path = tmp_path / "abi.json"
    item = {"return_bits": 32, "private_stack_bytes": 8,
            "stack_disjoint_buffers": [{"argument_index": 0, "size_bytes": 2}]}
    document = {"schema": "dosunit.flat32_abi_observation.v1", "functions": {"f": item}}
    path.write_text(json.dumps(document))
    contracts, identity = load_abi_catalog(path, "matched-cfg")
    assert contracts["f"].stack_disjoint_buffers == (Flat32StackDisjointBuffer(0, 2),)
    assert identity["sha256"]
    item["stack_disjoint_buffers"][0]["size_bytes"] = True
    path.write_text(json.dumps(document))
    with pytest.raises(ValueError):
        load_abi_catalog(path, "matched-cfg")


@pytest.mark.parametrize("argument,size", [(-1, 2), (32, 2), (True, 2), (0, 0), (0, 65537), (0, True)])
def test_bad_buffer_contracts_rejected(argument, size) -> None:
    with pytest.raises(ValueError):
        Flat32StackDisjointBuffer(argument, size)


def test_empty_private_frame_rejected() -> None:
    with pytest.raises(ValueError):
        Flat32AbiObservation(32, 0, (Flat32StackDisjointBuffer(0, 2),))


@pytest.mark.parametrize("maximum,expected", [(64, "conditional"), (65, "failed")])
def test_root_memory_range_constrains_values_without_erasing_effects(maximum, expected):
    from tools.dosunit.contracts.flat32_buffer_domain import Flat32EntryMemoryRange
    from tools.dosunit.tests.test_flat32_abi_observation import _compare

    # The original clamps values above 64; the candidate returns the raw value.
    original = "a100000200 83f840 7605 b800000000 c3"
    candidate = "a100000200 c3"
    domain = Flat32EntryMemoryRange(0x20000, 32, 0, maximum)
    contract = Flat32AbiObservation(32, entry_memory_ranges=(domain,))
    result = _compare(original, candidate, contract)
    assert result["status"] == expected, result
    assert result["abi_observation"]["entry_memory_ranges"][0]["max"] == maximum
    changed = _compare(original, "a100000200 40 c3", contract)
    assert changed["status"] == "failed", changed
    # A later store is not constrained by the entry bound.
    overwrite = "c7050000020041000000 "
    overwritten = _compare(overwrite + original, overwrite + candidate, contract)
    assert overwritten["status"] == "failed", overwritten
    public_store = _compare(original, "c7050000030001000000 " + candidate, contract)
    assert public_store["status"] == "failed", public_store


def test_root_memory_range_catalog_is_explicit_and_validated(tmp_path):
    from tools.dosunit.contracts.flat32_buffer_domain import Flat32EntryMemoryRange

    item = {"return_bits": 32, "private_stack_bytes": 0,
            "entry_memory_ranges": [{"address": 0x20000, "width": 32, "min": 0, "max": 64}]}
    path = tmp_path / "memory-domain.json"
    path.write_text(json.dumps({"schema": "dosunit.flat32_abi_observation.v1", "functions": {"f": item}}))
    contracts, identity = load_abi_catalog(path, "matched-cfg")
    assert contracts["f"].entry_memory_ranges == (Flat32EntryMemoryRange(0x20000, 32, 0, 64),)
    assert identity["sha256"]
    with pytest.raises(ValueError):
        Flat32EntryMemoryRange(0x20000, 32, 65, 64)
    with pytest.raises(ValueError):
        Flat32EntryMemoryRange(True, 32, 0, 64)


def test_conflicting_entry_memory_ranges_cannot_prove_identical_functions():
    from tools.dosunit.contracts.flat32_buffer_domain import Flat32EntryMemoryRange

    contract = Flat32AbiObservation(32, entry_memory_ranges=(
        Flat32EntryMemoryRange(0x20000, 32, 0, 0),
        Flat32EntryMemoryRange(0x20000, 32, 1, 1)))
    result = _compare("a100000200 c3", "a100000200 c3", contract)
    assert result["status"] == "refused", result


def test_entry_memory_range_is_not_transported_to_arbitrary_loop_cutpoints():
    from tools.dosunit.compare.flat32_loop_observation import compare_observed_loop
    from tools.dosunit.contracts.flat32_buffer_domain import Flat32EntryMemoryRange

    def forbidden_check(outputs):
        pytest.fail("A root-entry range cannot be assumed at a loop cutpoint")

    contract = Flat32AbiObservation(32, entry_memory_ranges=(Flat32EntryMemoryRange(0x20000, 32, 0, 64),))
    assert compare_observed_loop(forbidden_check, contract)["status"] == "refused"


@pytest.mark.parametrize("bounded,expected", [(True, "true"), (False, None)])
def test_path_solver_preserves_aliases_and_records_stack_domain(bounded, expected):
    from tools.dosunit.compare.flat32_constant_branches import branch_under_path

    def const(value):
        return {"op": "const", "width": 32, "value": hex(value)}

    esp = {"op": "input", "name": "esp", "width": 32}
    eax = {"op": "input", "name": "eax", "width": 32}
    memory = {"op": "mem_input", "name": "mem", "addr_width": 32, "value_width": 8}
    memory = {"op": "storele", "width": 0, "args": [memory, const(0x20000), const(0)]}
    memory = {"op": "storele", "width": 0, "args": [memory, esp, const(9)]}
    load = {"op": "loadle", "width": 32, "args": [memory, const(0x20000)]}
    condition = {"op": "eq", "width": 1, "args": [load, const(0)]}
    path = {"op": "eq", "width": 1, "args": [eax, const(0)]}
    constraints = [{"name": "esp", "kind": "unsigned_range", "min": 0x70000, "max": 0x80000}] if bounded else []
    proof = branch_under_path(condition, path, timeout_ms=1000, input_constraints=constraints)
    assert (proof.value.value if proof else None) == expected
    if proof is not None:
        assert proof.to_document()["input_constraints"] == tuple(constraints)


@pytest.mark.parametrize("kind,expected", [("and", "true"), ("or", None), ("not_or", "true")])
def test_path_literal_projection_never_uses_one_arm_of_a_disjunction(kind, expected):
    from tools.dosunit.compare.flat32_constant_branches import branch_under_path

    zero = {"op": "const", "width": 32, "value": "0x0"}
    x, y = [{"op": "input", "width": 32, "name": name} for name in ("eax", "ebx")]
    facts = [{"op": "eq", "width": 1, "args": [item, zero]} for item in (x, y)]
    if kind == "not_or":
        inner = {"op": "or", "width": 1, "args": [{"op": "not", "width": 1, "args": [fact]} for fact in facts]}
        path = {"op": "not", "width": 1, "args": [inner]}
    else:
        path = {"op": kind, "width": 1, "args": facts}
    squared = {"op": "mul", "width": 32, "args": [x, x]}
    condition = {"op": "eq", "width": 1, "args": [squared, zero]}
    proof = branch_under_path(condition, path, timeout_ms=1000)
    assert (proof.value.value if proof else None) == expected


def test_singleton_binding_relocation_rejects_ambiguous_inverse():
    from tools.dosunit.compare.flat32_call_composition import _entry_memory_bindings
    from tools.dosunit.compare.flat32_call_contracts import CallCompositionRefusal
    from tools.dosunit.contracts.flat32_buffer_domain import Flat32EntryMemoryRange

    ranges = (Flat32EntryMemoryRange(0x20000, 32, 0, 0),)
    binding, = _entry_memory_bindings(ranges, {0x30000: 0x20000})
    assert binding.local_address == 0x30000
    assert binding.domain.address == 0x20000
    with pytest.raises(CallCompositionRefusal, match="ambiguous_entry_memory_binding"):
        _entry_memory_bindings(ranges, {0x30000: 0x20000, 0x40000: 0x20000})
