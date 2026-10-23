"""External-call contracts must retain arguments, memory and ordered effects."""

from dataclasses import replace
from typing import Any

import pytest
import z3

from tools.dosunit.compare.flat32_call_contracts import _initial_state, _register_widths
from tools.dosunit.compare.flat32_external_call import (
    ExternalStackCleanup,
    Flat32ExternalCall,
    external_call_state,
    preserve_import_memory,
)
from tools.dosunit.ssa.materialization import input_items, materialize_term
from tools.dosunit.ssa.translation import TranslationContext
from tools.dosunit.ssa.z3_ops import apply_operator

pytestmark = [pytest.mark.ssa_z3, pytest.mark.runtime]

CONTRACT = Flat32ExternalCall("KERNEL32.dll", "Example", 3, ExternalStackCleanup.CALLEE)


def translate(terms: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Exercise the production materialization and translation of effect DAGs."""
    assignments: list[dict[str, Any]] = []
    memo: dict[str, str] = {}
    outputs = {name: materialize_term(term, assignments=assignments, memo=memo) for name, term in terms.items()}
    inputs = {}
    for item in input_items(list(outputs.values()), assignments):
        name = item["name"]
        if item.get("kind") == "memory":
            inputs[name] = (z3.Array(name, z3.BitVecSort(32), z3.BitVecSort(8)), 0)
        else:
            inputs[name] = (z3.BitVec(name, item["width"]), item["width"])
    context = TranslationContext(
        {}, inputs, {a["id"]: a for a in assignments}, {}, z3,
        lambda value, **_kwargs: value,
    )
    return {name: context.term(term) for name, term in outputs.items()}


def state() -> dict[str, dict[str, Any]]:
    """Construct the same complete flat32 input state as call composition."""
    return _initial_state(_register_widths())


def different(left: Any, right: Any) -> bool:
    """Find whether an allowed opaque implementation can distinguish terms."""
    solver = z3.Solver()
    solver.add(left != right)
    return solver.check() == z3.sat


def test_external_call_roundtrip_and_stack_contract() -> None:
    before = state()
    after = external_call_state(CONTRACT, before)
    values = translate({"esp": after["esp"], "old_esp": before["esp"], "eip": after["eip"],
                        "return_slot": {"op": "loadle", "width": 32, "args": [after["memory"], before["esp"]]}})
    assert not different(values["esp"], values["old_esp"] + 16)
    assert not different(values["return_slot"], values["eip"])
    for register in ("ebx", "ebp", "esi", "edi", "d"):
        assert after[register] == before[register]
    assert state() == before  # transition does not mutate its caller


def test_caller_cleanup_pops_only_return_address() -> None:
    before = state()
    after = external_call_state(replace(CONTRACT, cleanup=ExternalStackCleanup.CALLER), before)
    values = translate({"esp": after["esp"], "old_esp": before["esp"]})
    assert not different(values["esp"], values["old_esp"] + 4)


@pytest.mark.parametrize("output", ["eax", "memory", "io"])
def test_changed_argument_changes_effects(output: str) -> None:
    before = state()
    changed = dict(before)
    changed["esp"] = {"op": "add", "width": 32, "args": [before["esp"], {"op": "const", "width": 32, "value": "0x4"}]}
    left = external_call_state(CONTRACT, before)
    right = external_call_state(CONTRACT, changed)
    values = translate({"left": left[output], "right": right[output]})
    assert different(values["left"], values["right"])


@pytest.mark.parametrize("changed_input", ["memory", "io"])
def test_full_memory_and_history_affect_result(changed_input: str) -> None:
    before = state()
    changed = dict(before)
    changed[changed_input] = {"op": "mem_input", "name": "other", "addr_width": 32, "value_width": 8}
    left = external_call_state(CONTRACT, before)
    right = external_call_state(CONTRACT, changed)
    values = translate({"left": left["eax"], "right": right["eax"]})
    assert different(values["left"], values["right"])


def test_repeat_call_does_not_force_identical_result() -> None:
    before = state()
    first = external_call_state(CONTRACT, before)
    # Repeat exactly the same argument/memory state, changing only history.
    second_entry = {**before, "io": first["io"]}
    second = external_call_state(CONTRACT, second_entry)
    values = translate({"first": first["eax"], "second": second["eax"]})
    assert different(values["first"], values["second"])


def test_external_effect_survives_unused_return_value() -> None:
    before = state()
    after = external_call_state(CONTRACT, before)
    values = translate({"before": before["io"], "after": after["io"]})
    assert different(values["before"], values["after"])


def test_external_call_order_remains_observable() -> None:
    first = CONTRACT
    second = replace(CONTRACT, name="Other")
    left = external_call_state(second, external_call_state(first, state()))
    right = external_call_state(first, external_call_state(second, state()))
    values = translate({"left": left["io"], "right": right["io"]})
    assert different(values["left"], values["right"])


def test_identical_transitions_are_congruent() -> None:
    left = external_call_state(CONTRACT, state())
    right = external_call_state(CONTRACT, state())
    for output in ("eax", "memory", "io", "cc_dep1"):
        values = translate({"left": left[output], "right": right[output]})
        assert not different(values["left"], values["right"])


def test_identity_encoding_cannot_merge_punctuation() -> None:
    left = external_call_state(replace(CONTRACT, name="a-b"), state())
    right = external_call_state(replace(CONTRACT, name="a_b"), state())
    values = translate({"left": left["io"], "right": right["io"]})
    assert different(values["left"], values["right"])
    assert CONTRACT.operator_prefix() == replace(CONTRACT, dll="kernel32.dll").operator_prefix()


@pytest.mark.parametrize("count", [-1, 33, True, 1.0])
def test_invalid_argument_count_refused(count: Any) -> None:
    with pytest.raises(ValueError, match="DWORD arguments"):
        replace(CONTRACT, argument_count=count)


def test_premises_state_the_abstract_boundary() -> None:
    fields = CONTRACT.declared_fields()
    assert fields["outcome"] == "normal_return_assumed"
    assert fields["memory"] == "arbitrary_except_four_return_address_bytes"
    assert fields["dependencies"] == ["all_memory", "external_history", "ordered_arguments"]


@pytest.mark.parametrize("address,original", [(0xFFF, False), (0x1000, True), (0x1003, True),
                                           (0x1004, False), (0xFFFFFFFC, False)])
def test_memory_frame_preserves_exact_byte_boundaries(address: int, original: bool) -> None:
    old = z3.Array("old", z3.BitVecSort(32), z3.BitVecSort(8))
    new = z3.Array("new", z3.BitVecSort(32), z3.BitVecSort(8))
    framed = apply_operator("memory_preserve", 0, [new, old, z3.BitVecVal(0x1000, 32), z3.BitVecVal(0x1003, 32)], z3)
    assert not different(z3.Select(framed, address), z3.Select(old if original else new, address))


def test_iat_frame_keeps_gaps_writable_and_handles_last_address() -> None:
    old = {"op": "mem_input", "name": "old", "addr_width": 32, "value_width": 8}
    new = {"op": "mem_input", "name": "new", "addr_width": 32, "value_width": 8}
    framed = preserve_import_memory(new, old, (0x1000, 0x1004, 0x1010, 0xFFFFFFFC))
    values = translate({"framed": framed, "old": old, "new": new})
    for address in (0x1000, 0x1007, 0x1013, 0xFFFFFFFF):
        assert not different(z3.Select(values["framed"], address), z3.Select(values["old"], address))
    for address in (0, 0x1008, 0x100F, 0x1014):
        assert not different(z3.Select(values["framed"], address), z3.Select(values["new"], address))


def test_iat_preservation_requires_explicit_slots_and_boolean() -> None:
    with pytest.raises(ValueError, match="boolean"):
        replace(CONTRACT, preserve_import_bindings=1)
    with pytest.raises(ValueError, match="actual import slots"):
        external_call_state(replace(CONTRACT, preserve_import_bindings=True), state())


def test_scalar_external_contract_ignores_memory_but_preserves_it() -> None:
    from tools.dosunit.compare.flat32_external_call import ExternalMemoryAccess

    contract = replace(CONTRACT, argument_count=0, memory_access=ExternalMemoryAccess.NONE)
    before = state()
    changed = {**before, "memory": {"op": "mem_input", "name": "other", "addr_width": 32, "value_width": 8}}
    left, right = external_call_state(contract, before), external_call_state(contract, changed)
    values = translate({"left": left["eax"], "right": right["eax"]})
    assert not different(values["left"], values["right"])
    assert left["memory"] == before["memory"] and right["memory"] == changed["memory"]
    fields = contract.declared_fields()
    assert fields["memory_access"] == "none"
    assert fields["dependencies"] == ["external_history", "ordered_arguments"]
    assert contract.operator_prefix() != replace(contract, memory_access=ExternalMemoryAccess.ARBITRARY).operator_prefix()


@pytest.mark.parametrize("changed_input", ["memory", "io"])
def test_scalar_external_arguments_and_history_remain_observable(changed_input: str) -> None:
    from tools.dosunit.compare.flat32_external_call import ExternalMemoryAccess

    contract = replace(CONTRACT, memory_access=ExternalMemoryAccess.NONE)
    before = state()
    changed = {**before, changed_input: {"op": "mem_input", "name": "other", "addr_width": 32, "value_width": 8}}
    left, right = external_call_state(contract, before), external_call_state(contract, changed)
    values = translate({"left": left["io"], "right": right["io"]})
    assert different(values["left"], values["right"])


def test_scalar_external_memory_contract_requires_enum() -> None:
    with pytest.raises(ValueError, match="typed memory"):
        replace(CONTRACT, memory_access="none")


@pytest.mark.parametrize("corrupt", [False, True])
def test_native_scalar_call_with_different_return_addresses(tmp_path: Any, corrupt: bool) -> None:
    """Native calls keep events/results but need a separate final stack premise."""
    import struct

    from tools.dosunit.architectures.flat32_loader import load_flat32_project
    from tools.dosunit.compare.flat32_abi_observation import Flat32AbiObservation
    from tools.dosunit.compare.flat32_call_composition import compare_functions_with_calls
    from tools.dosunit.compare.flat32_external_call import ExternalMemoryAccess
    from tools.dosunit.contracts.flat32_proof_domain import Flat32ProofDomain
    from tools.dosunit.tests.test_pe32_import_service import ENTRY, IAT_SLOT, pe32_import_bytes

    call = b"\xff\x15" + struct.pack("<I", IAT_SLOT)
    left = call + b"\xc3"
    right = b"\x90" + call + (b"\x40" if corrupt else b"") + b"\xc3"
    op, cp = tmp_path / "o.exe", tmp_path / "c.exe"
    op.write_bytes(pe32_import_bytes(left))
    cp.write_bytes(pe32_import_bytes(right))
    contract = Flat32ExternalCall("kernel32.dll", "GetTickCount", 0, ExternalStackCleanup.CALLEE,
                                 memory_access=ExternalMemoryAccess.NONE)
    result = compare_functions_with_calls(
        load_flat32_project(op), load_flat32_project(cp), oracle_entry=ENTRY, candidate_entry=ENTRY,
        oracle_functions={ENTRY: len(left)}, candidate_functions={ENTRY: len(right)},
        outputs=("eax",), timeout_ms=10000, external_contracts=(contract,),
        entry_domain=Flat32ProofDomain(0x7F000, 0x80000),
        abi_observation=Flat32AbiObservation(32, 4),
    )
    assert (result["status"] == "conditional") is not corrupt, result
    assert result["external_call_assumptions"]["contracts"][0]["memory_access"] == "none"


@pytest.mark.parametrize("pointer,size,probe,inside", [
    (0x1000, 4, 0x1000, True), (0x1000, 4, 0x1003, True),
    (0x1000, 4, 0x1004, False), (0x1000, 4, 0xFFF, False),
    (0xFFFFFFFE, 4, 0xFFFFFFFF, True), (0xFFFFFFFE, 4, 0, True),
    (0xFFFFFFFE, 4, 2, False), (0, 4, 0, False), (0x1000, 0, 0x1000, False),
])
def test_return_region_exact_byte_footprint(pointer: int, size: int, probe: int, inside: bool) -> None:
    """Observe both endpoints, outside bytes, wrapping, failure and empty writes."""
    from tools.dosunit.compare.flat32_external_call import _constant, _returned_region_memory

    original = state()["memory"]
    content = {"op": "mem_input", "name": "fresh", "addr_width": 32, "value_width": 8}
    result = _returned_region_memory(original, content, _constant(pointer), _constant(size))
    values = translate({"result": result, "old": original, "new": content})
    address = z3.BitVecVal(probe, 32)
    expected = values["new" if inside else "old"][address]
    assert not different(values["result"][address], expected)
    assert different(values["result"][address], values["old" if inside else "new"][address])


def test_return_region_keeps_unrelated_memory_and_ordered_effects() -> None:
    """Different irrelevant stack bytes cannot affect EAX but must remain in memory."""
    from tools.dosunit.compare.flat32_external_call import ExternalMemoryAccess, _constant

    contract = replace(CONTRACT, memory_access=ExternalMemoryAccess.RETURNED_REGION, write_size_argument=2)
    before = state()
    before["esp"] = _constant(0x80000)
    # Equal explicit arguments isolate the relation from arbitrary stack inputs.
    for offset, value in ((4, 7), (8, 0), (12, 4)):
        before["memory"] = {"op": "storele", "width": 0, "args": [before["memory"], _constant(0x80000+offset), _constant(value)]}
    changed = {**before, "memory": {"op": "storele", "width": 0, "args": [
        before["memory"], _constant(0x90000), {"op": "const", "width": 8, "value": "0x57"}]}}
    left, right = external_call_state(contract, before), external_call_state(contract, changed)
    values = translate({"eax1": left["eax"], "eax2": right["eax"], "mem1": left["memory"],
                        "mem2": right["memory"], "io1": left["io"], "io2": right["io"], "old_io": before["io"]})
    assert not different(values["eax1"], values["eax2"])
    assert not different(values["io1"], values["io2"])
    assert different(values["io1"], values["old_io"])
    solver = z3.Solver()
    solver.add(values["eax1"] == 0)
    solver.add(z3.simplify(values["mem1"][z3.BitVecVal(0x90000, 32)] !=
                           values["mem2"][z3.BitVecVal(0x90000, 32)]))
    result = solver.check()
    assert result == z3.sat, (result, solver.reason_unknown())
    assert contract.declared_fields()["freshness_assumed"] is False


@pytest.mark.parametrize("index", [None, True, -1, 3, "2"])
def test_return_region_requires_in_range_typed_size_argument(index: object) -> None:
    """Malformed footprints never silently turn into unrestricted or empty effects."""
    from tools.dosunit.compare.flat32_external_call import ExternalMemoryAccess

    with pytest.raises(ValueError, match="size argument"):
        replace(CONTRACT, memory_access=ExternalMemoryAccess.RETURNED_REGION, write_size_argument=index)


def test_size_argument_cannot_change_other_external_contract_modes() -> None:
    with pytest.raises(ValueError, match="size argument"):
        replace(CONTRACT, write_size_argument=2)


@pytest.mark.parametrize("corrupt", [False, True])
def test_native_region_call_with_different_return_addresses(tmp_path: Any, corrupt: bool) -> None:
    """Native region calls preserve effects across different code return addresses."""
    import struct

    from tools.dosunit.architectures.flat32_loader import load_flat32_project
    from tools.dosunit.compare.flat32_abi_observation import Flat32AbiObservation
    from tools.dosunit.compare.flat32_call_composition import compare_functions_with_calls
    from tools.dosunit.compare.flat32_external_call import ExternalMemoryAccess
    from tools.dosunit.contracts.flat32_proof_domain import Flat32ProofDomain
    from tools.dosunit.tests.test_pe32_import_service import ENTRY, IAT_SLOT, pe32_import_bytes

    call = b"\xff\x15" + struct.pack("<I", IAT_SLOT)
    left = b"\x6a\x04" + call + b"\xc3"
    right = b"\x90\x6a\x04" + call + (b"\x40" if corrupt else b"") + b"\xc3"
    op, cp = tmp_path / "o.exe", tmp_path / "c.exe"
    op.write_bytes(pe32_import_bytes(left).replace(b"GetTickCount", b"ExampleAlloc"))
    cp.write_bytes(pe32_import_bytes(right).replace(b"GetTickCount", b"ExampleAlloc"))
    contract = Flat32ExternalCall("kernel32.dll", "ExampleAlloc", 1, ExternalStackCleanup.CALLEE,
                                 memory_access=ExternalMemoryAccess.RETURNED_REGION, write_size_argument=0)
    result = compare_functions_with_calls(
        load_flat32_project(op), load_flat32_project(cp), oracle_entry=ENTRY, candidate_entry=ENTRY,
        oracle_functions={ENTRY: len(left)}, candidate_functions={ENTRY: len(right)},
        outputs=("eax",), timeout_ms=10000, external_contracts=(contract,),
        entry_domain=Flat32ProofDomain(0x7F000, 0x80000),
        abi_observation=Flat32AbiObservation(32, 8),
    )
    assert (result["status"] == "conditional") is not corrupt, result
    assert result["external_call_assumptions"]["contracts"][0]["memory_access"] == "returned_region"



def test_output_buffer_ignores_old_contents_but_preserves_other_memory() -> None:
    """An output-only contract couples results without discarding unrelated stores."""
    from tools.dosunit.compare.flat32_external_call import ExternalMemoryAccess, _constant

    contract = replace(CONTRACT, argument_count=1, memory_access=ExternalMemoryAccess.ARGUMENT_REGION,
                       write_address_argument=0, write_size_bytes=16)
    before = state()
    before["esp"] = _constant(0x80000)
    before["memory"] = {"op": "storele", "width": 0, "args": [
        before["memory"], _constant(0x80004), _constant(0x90000)]}
    changed = {**before, "memory": {"op": "storele", "width": 0, "args": [
        before["memory"], _constant(0x90000), _constant(123)]}}
    left, right = external_call_state(contract, before), external_call_state(contract, changed)
    values = translate({"a": left["memory"], "b": right["memory"], "before": before["memory"],
                        "io_a": left["io"], "io_b": right["io"], "old_io": before["io"]})
    assert not different(values["io_a"], values["io_b"])
    assert different(values["io_a"], values["old_io"])
    assert not different(values["a"], values["b"])
    for address in (0x8ffff, 0x90010, 0x80000, 0x80003):
        assert not different(values["a"][address], values["before"][address])
    assert different(values["a"][0x90000], values["before"][0x90000])
    assert contract.operator_prefix() != replace(contract, write_size_bytes=8).operator_prefix()
    assert contract.declared_fields()["write_size_bytes"] == 16


@pytest.mark.parametrize("address,size", [(None, 16), (True, 16), (1, 16), (0, None), (0, True), (0, 0), (0, 65537)])
def test_output_buffer_rejects_malformed_footprint(address: object, size: object) -> None:
    """Malformed declarations cannot become no-memory or unbounded contracts."""
    from tools.dosunit.compare.flat32_external_call import ExternalMemoryAccess

    with pytest.raises(ValueError):
        replace(CONTRACT, argument_count=1, memory_access=ExternalMemoryAccess.ARGUMENT_REGION,
                write_address_argument=address, write_size_bytes=size)


@pytest.mark.parametrize("pointer", [0, 0x1000, 0xfffffffe])
@pytest.mark.parametrize("size", [1, 3, 16, 64, 65])
def test_fixed_output_footprint_boundaries(pointer: int, size: int) -> None:
    """Finite stores and range fallback agree at wraparound and both boundaries."""
    from tools.dosunit.compare.flat32_external_call import _constant, _fixed_output_memory

    original = state()["memory"]
    content = {"op": "mem_input", "name": "fresh", "addr_width": 32, "value_width": 8}
    result = _fixed_output_memory(original, content, _constant(pointer), size)
    values = translate({"result": result, "old": original, "new": content})
    for offset, inside in [(-1, False), (0, True), (size - 1, True), (size, False)]:
        address = z3.BitVecVal((pointer + offset) & 0xffffffff, 32)
        assert not different(values["result"][address], values["new" if inside else "old"][address])


def test_declared_memory_frame_preserves_only_external_effects() -> None:
    contract = replace(CONTRACT, preserved_memory_ranges=((0x70000, 0x80003),))
    before = state()
    after = external_call_state(contract, before)

    def load(memory, address):
        return {"op": "loadle", "width": 8, "args": [memory, {"op": "const", "width": 32, "value": hex(address)}]}

    values = translate({"old": load(before["memory"], 0x7ffff),
                        "new": load(after["memory"], 0x7ffff),
                        "public_old": load(before["memory"], 0x60000),
                        "public_new": load(after["memory"], 0x60000)})
    assert not different(values["old"], values["new"])
    assert different(values["public_old"], values["public_new"])
    written = {"op": "storele", "width": 0, "args": [after["memory"],
               {"op": "const", "width": 32, "value": "0x7ffff"},
               {"op": "const", "width": 8, "value": "0x42"}]}
    values = translate({"old": load(before["memory"], 0x7ffff), "new": load(written, 0x7ffff)})
    assert different(values["old"], values["new"])
    assert contract.declared_fields()["preserved_memory_ranges"] == [[0x70000, 0x80003]]


@pytest.mark.parametrize("ranges", [((True, 9),), ((10, 9),), ((0, 2**32),), ((4, 8), (7, 9))])
def test_invalid_declared_memory_frame_rejected(ranges) -> None:
    with pytest.raises(ValueError):
        replace(CONTRACT, preserved_memory_ranges=ranges)


@pytest.mark.parametrize("missing,expected", [(False, "passed"), (True, "failed")])
def test_relocated_iat_slots_keep_bytes_when_import_order_changes(missing, expected):
    from tools.dosunit.compare import straightline_ssa as scalar
    from tools.dosunit.ssa.ssa_output_lemmas import ScalarPreprocessing
    from tools.dosunit.tests.test_flat32_comparator_lane import _driver_lane

    old = {"op": "mem_input", "name": "old", "addr_width": 32, "value_width": 8}
    new = {"op": "mem_input", "name": "new", "addr_width": 32, "value_width": 8}

    def document(slots):
        assignments = []
        term = materialize_term(preserve_import_memory(new, old, slots), assignments=assignments, memo={})
        return {"outputs": {"memory": term}, "assignments": assignments, "inputs": input_items([term], assignments)}

    original = document((0x1000, 0x1010))
    candidate = document((0x2000,) if missing else (0x2000, 0x2004))
    candidate["_constant_normalization"] = {0x2000: 0x1010, 0x2004: 0x1000}
    # Observe all memory plus a concrete byte at the potentially omitted slot.
    # This also supplies a concrete public-byte counterexample when corrupted.
    for document in (original, candidate):
        document["assignments"].append({"id": "observed_byte", "op": "loadle", "width": 8,
            "args": [document["outputs"]["memory"], {"op": "const", "width": 32, "value": "0x1003"}]})
        document["outputs"]["byte"] = {"ref": "observed_byte"}
        if missing:
            # Require a concrete differing public byte, not an opaque array model.
            document["outputs"].pop("memory")
    with _driver_lane("msc8") as lane, lane.adapter.installed(region=True):
        result = scalar._compare_functions(original, candidate, timeout_ms=2000,
            scalar_preprocessing=ScalarPreprocessing.READ_OVER_WRITE)
    assert result["status"] == expected, result


def test_memory_frame_catalog_intake_keeps_explicit_ranges() -> None:
    from tools.comparator.external_catalog import _contracts

    item = {"dll": "kernel32.dll", "name": "Example", "argument_count": 3,
            "cleanup": "callee", "preserved_memory_ranges": [[0x70000, 0x80003]]}
    contract, = _contracts([item])
    assert contract.preserved_memory_ranges == ((0x70000, 0x80003),)
    for malformed in ("0x70000:0x80003", [[0, True]], [[9, 8]], [[0, 4], [4, 8]]):
        with pytest.raises(ValueError):
            _contracts([{**item, "preserved_memory_ranges": malformed}])
