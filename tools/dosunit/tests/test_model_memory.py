"""Exact memory-model evidence, including overwrite and truncation controls."""
import z3

from tools.dosunit.ssa.model_memory import MemoryModelStatus, serialize_byte_memory


def test_serialized_memory_preserves_latest_store_and_default() -> None:
    memory = z3.K(z3.BitVecSort(32), z3.BitVecVal(19, 8))
    for address, value in ((4, 7), (9, 11), (4, 13)):
        memory = z3.Store(memory, z3.BitVecVal(address, 32), z3.BitVecVal(value, 8))
    result = serialize_byte_memory(memory)
    assert result["status"] is MemoryModelStatus.COMPLETE
    rows = {int(row["address"], 0): row["value"] for row in result["stores"]}
    for address in (0, 4, 9, 0xFFFFFFFF):
        assert rows.get(address, result["default_byte"]) == z3.simplify(
            z3.Select(memory, z3.BitVecVal(address, 32))).as_long()


def test_memory_limit_never_publishes_partial_bytes() -> None:
    memory = z3.Store(z3.K(z3.BitVecSort(32), z3.BitVecVal(19, 8)), 4, 7)
    assert serialize_byte_memory(memory, max_stores=0) == {"status": MemoryModelStatus.LIMIT}


def test_unsupported_memory_never_supplies_a_default() -> None:
    unresolved = z3.Array("unresolved", z3.BitVecSort(32), z3.BitVecSort(8))
    assert serialize_byte_memory(unresolved) == {"status": MemoryModelStatus.UNSUPPORTED}
    wrong_sort = z3.K(z3.BitVecSort(16), z3.BitVecVal(0, 8))
    assert serialize_byte_memory(wrong_sort) == {"status": MemoryModelStatus.UNSUPPORTED}


def test_ordinary_comparison_does_not_serialize_memory(monkeypatch) -> None:
    from tools.comparator.return_counterexample import _observation_document
    from tools.dosunit.compare import straightline_ssa as owner
    from tools.dosunit.ssa import model_memory

    def unexpected_capture(*args, **kwargs):
        raise AssertionError("ordinary comparison must not serialize memory")

    monkeypatch.setattr(model_memory, "serialize_byte_memory", unexpected_capture)
    term = {"op": "loadle", "width": 8, "args": [
        {"op": "mem_input", "name": "mem", "addr_width": 32, "value_width": 8},
        {"op": "const", "width": 32, "value": "0x60000000"}]}
    result = owner._compare_functions(
        _observation_document({"eax": term}),
        _observation_document({"eax": {"op": "const", "width": 8, "value": "0x1"}}),
        timeout_ms=1000,
    )
    assert result["status"] == "failed"
    assert "counterexample_memory" not in result
