"""SSA call/block composition keeps program and I/O arrays independently live."""
import tools.dosunit.compare.straightline_ssa as S


def _array(name: str) -> dict[str, object]:
    """Create a complete raw native byte-array input term."""
    return {"op": "mem_input", "name": name, "addr_width": 32, "value_width": 8}


def test_block_identity_keeps_separate_live_memory_and_io_arrays() -> None:
    """A fresh block cannot replace the caller's I/O state with program bytes."""
    program, ports = _array("caller_program"), _array("caller_ports")
    state = {"memory": program, "io": ports}
    outputs = {"memory": _array("mem"), "io": _array("io")}
    composed = S._compose_block_outputs({"assignments": []}, outputs, state)
    assert composed["memory"] is program
    assert composed["io"] is ports


def test_nested_io_read_substitutes_only_its_named_array() -> None:
    """A port-array load retains I/O identity through expression composition."""
    program, ports = _array("caller_program"), _array("caller_ports")
    term = {"op": "loadle", "width": 8, "args": [_array("io"),
            {"op": "const", "width": 32, "value": "0x1234"}]}
    result = S._substitute_abi_inputs(term, {"memory": program, "io": ports})
    assert result["args"][0] is ports
    assert result["args"][1] == term["args"][1]


def test_unbound_named_array_preserves_its_explicit_unknown_input() -> None:
    """An absent array binding cannot silently alias a known program array."""
    named = _array("device_state")
    result = S._substitute_abi_inputs(named, {"memory": _array("program")})
    assert result is named


def test_primary_memory_default_and_explicit_key_keep_compatibility() -> None:
    """Canonical mem and legacy unnamed roots still bind program memory."""
    program = _array("caller_program")
    for term in (_array("mem"), _array("memory"), {"op": "mem_input"}):
        assert S._substitute_abi_inputs(term, {"memory": program}) is program
