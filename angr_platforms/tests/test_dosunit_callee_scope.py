"""Entry-block equality must not certify the whole callee's effects."""

from pathlib import Path

from test_dosunit_tool import _edge_function, _mz_exe

from tools.dosunit.straightline_ssa import compare_ssa_documents, lower_straightline_ssa_document


def test_equal_callee_entry_does_not_hide_changed_later_block(tmp_path: Path) -> None:
    documents = []
    for name, increment in [('original', 1), ('candidate', 2)]:
        image = bytearray(0x300)
        image[0x200:0x204] = bytes.fromhex('e82d00c3')
        image[0x230:0x238] = bytes.fromhex('89d8eb0083c0') + bytes([increment, 0xc3])
        executable = tmp_path / f'{name}.exe'
        executable.write_bytes(_mz_exe(bytes(image)))
        catalog = {'schema': 'dosunit.functions.v1', 'module': 'demo.exe', 'functions': [
            _edge_function('demo.exe:caller', 'caller', offset=0x200, size=4),
            _edge_function('demo.exe:callee', 'callee', offset=0x230, size=8),
        ]}
        documents.append(lower_straightline_ssa_document(
            exe_path=executable, functions_catalog=catalog, output_regs=('ax', 'bx'),
            max_blocks_per_function=32, follow_call_fallthrough=True,
        ))
    compared = compare_ssa_documents(oracle=documents[0], candidate=documents[1], skip_binary_equal=False,
                                      timeout_ms=1000, semantic_proof_passes=1)
    callers = [row for row in compared['results'] if row['function']['name'] == 'caller' and row.get('call_compare')]
    assert callers, compared
    assert all(row['status'] != 'passed' for row in callers), compared


def test_call_arguments_in_unselected_registers_remain_live(tmp_path: Path) -> None:
    """A callee consuming DX makes its pre-call value part of the proof state."""
    documents = []
    for name, argument in [('original', 1), ('candidate', 2)]:
        image = bytearray(0x300)
        image[0x200:0x207] = b'\xba' + argument.to_bytes(2, 'little') + bytes.fromhex('e82a00c3')
        image[0x230:0x233] = bytes.fromhex('89d0c3')
        executable = tmp_path / f'{name}.exe'
        executable.write_bytes(_mz_exe(bytes(image)))
        catalog = {'schema': 'dosunit.functions.v1', 'module': 'demo.exe', 'functions': [
            _edge_function('demo.exe:caller', 'caller', offset=0x200, size=7),
            _edge_function('demo.exe:callee', 'callee', offset=0x230, size=3),
        ]}
        documents.append(lower_straightline_ssa_document(
            exe_path=executable, functions_catalog=catalog, output_regs=('ax',),
            max_blocks_per_function=32, follow_call_fallthrough=True,
        ))
    compared = compare_ssa_documents(oracle=documents[0], candidate=documents[1], skip_binary_equal=False,
                                      timeout_ms=1000, semantic_proof_passes=1)
    callers = [row for row in compared['results'] if row['function']['name'] == 'caller' and row.get('call_compare')]
    assert callers, compared
    assert all(row['status'] != 'passed' for row in callers), compared
