"""Selection controls over real MZ code and catalogued call closures."""
from pathlib import Path

from tools.dosunit.tests.test_dosunit_tool import _edge_function, _mz_exe
from tools.dosunit.tests.test_real16_public_accounting import _catalog

from tools.dosunit.compare.real16_binary_compare import compare_binary16


def test_selected_leaf_ignores_unreachable_io(tmp_path: Path) -> None:
    """An unrelated port instruction must not taint the selected leaf."""
    exe = tmp_path / "selected.exe"
    exe.write_bytes(_mz_exe(bytes.fromhex("89 d8 c3 ec c3")))
    catalog = _catalog(
        _edge_function("demo.exe:f", "f", offset=0, size=3),
        _edge_function("demo.exe:io", "io", offset=3, size=2),
    )
    report = compare_binary16(exe, exe, catalog, catalog, selected=("f",))
    assert report["status"] == "proved", report["proof"]
    assert report["lowering"]["oracle"]["functions_attempted"] == 1


def test_selected_call_keeps_reachable_io(tmp_path: Path) -> None:
    """A reachable port callee remains inside the environment refusal scope."""
    exe = tmp_path / "called.exe"
    exe.write_bytes(_mz_exe(bytes.fromhex("e8 01 00 c3 ec c3")))
    catalog = _catalog(
        _edge_function("demo.exe:f", "f", offset=0, size=4),
        _edge_function("demo.exe:io", "io", offset=4, size=2),
    )
    report = compare_binary16(exe, exe, catalog, catalog, selected=("f",))
    assert report["status"] == "unknown"
    assert report["lowering"]["oracle"]["functions_attempted"] == 2


def test_candidate_only_call_keeps_io(tmp_path: Path) -> None:
    """Candidate call closure is independent of oracle edges."""
    oracle = tmp_path / "oracle.exe"
    candidate = tmp_path / "candidate.exe"
    oracle.write_bytes(_mz_exe(bytes.fromhex("90 90 90 c3 ec c3")))
    candidate.write_bytes(_mz_exe(bytes.fromhex("e8 01 00 c3 ec c3")))
    catalog = _catalog(
        _edge_function("demo.exe:f", "f", offset=0, size=4),
        _edge_function("demo.exe:io", "io", offset=4, size=2),
    )
    report = compare_binary16(oracle, candidate, catalog, catalog, selected=("f",))
    assert report["status"] == "unknown"
    assert report["lowering"]["oracle"]["functions_attempted"] == 1
    assert report["lowering"]["candidate"]["functions_attempted"] == 2


def test_selection_queue_retains_aliases_and_full_addresses() -> None:
    """Repeated aliases survive and low16 collisions cannot add wrong callees."""
    from tools.dosunit.ssa.ssa_selection import LoweringSelection

    functions = [
        {"id": str(i), "names": [], "linear": linear}
        for i, linear in enumerate((0x10000, 0x20000, 0x20000, 0x30000))
    ]
    selection = LoweringSelection(functions, frozenset({"0"}), lambda item: item["linear"])
    visited = []
    for function in selection:
        visited.append(function["id"])
        if function["id"] == "0":
            selection.observe([{"source": {"transfer": {
                "kind": "direct_call", "target": {"raw": "0x20000"},
            }}}])
    assert visited == ["0", "1", "2"]
    assert list(LoweringSelection(functions, None, lambda item: item["linear"])) == functions
    assert list(LoweringSelection(functions, frozenset({"missing"}), lambda item: item["linear"])) == functions


def test_default_selection_keeps_all_environment_effects(tmp_path: Path) -> None:
    """The legacy all-functions request still refuses catalogued I/O."""
    exe = tmp_path / "all.exe"
    exe.write_bytes(_mz_exe(bytes.fromhex("89 d8 c3 ec c3")))
    catalog = _catalog(
        _edge_function("demo.exe:f", "f", offset=0, size=3),
        _edge_function("demo.exe:io", "io", offset=3, size=2),
    )
    report = compare_binary16(exe, exe, catalog, catalog)
    assert report["status"] == "unknown"
    assert report["lowering"]["oracle"]["functions_attempted"] == 2
    assert len(report["requested_functions"]) == 2


def test_same_image_mapping_does_not_reuse_other_root(tmp_path: Path) -> None:
    """Same image and catalog do not imply identical mapped entry scopes."""
    from tools.dosunit.tests.test_real16_public_accounting import _mapping, _mapping_row

    exe = tmp_path / "mapped.exe"
    exe.write_bytes(_mz_exe(bytes.fromhex("89 d8 c3 ec c3")))
    catalog = _catalog(
        _edge_function("demo.exe:f", "f", offset=0, size=3),
        _edge_function("demo.exe:io", "io", offset=3, size=2),
    )
    report = compare_binary16(
        exe, exe, catalog, catalog, selected=("f",),
        mapping=_mapping(_mapping_row("f", "io", 3)),
    )
    assert report["status"] == "unknown"
    assert report["lowering_reuse"]["candidate"] is False
    assert report["lowering"]["candidate"]["functions_attempted"] == 1


def test_selected_ambiguous_mapping_retains_existing_accounting(tmp_path, monkeypatch):
    """Run all existing ambiguous-counterpart assertions with explicit selection."""
    import tools.dosunit.tests.test_real16_public_accounting as accounting

    def selected_compare(*args, **kwargs):
        return compare_binary16(*args, **kwargs, selected=("f",))

    monkeypatch.setattr(accounting, "compare_binary16", selected_compare)
    accounting.test_candidate_only_reachable_stays_in_denominator(tmp_path)


def test_uncertain_selection_retains_full_catalog() -> None:
    """Indirect successors and unresolved nonempty roots cannot discard entries."""
    from tools.dosunit.ssa.ssa_selection import LoweringSelection, selected_catalog_indices

    functions = [{"id": str(i), "names": [], "linear": i} for i in range(3)]
    selection = LoweringSelection(functions, frozenset({"0"}), lambda item: item["linear"])
    selection.observe([{"source": {"transfer": {"kind": "indirect_successor"}}}])
    assert list(selection) == functions
    assert selected_catalog_indices(functions, frozenset({"missing"})) == frozenset({0, 1, 2})
    assert selected_catalog_indices(functions, frozenset()) == frozenset()


def test_transitive_recursive_calls_visit_each_alias_once() -> None:
    """Root to A to B to A closes finitely despite repeated calls and aliases."""
    from tools.dosunit.ssa.ssa_selection import LoweringSelection

    functions = [
        {"id": key, "names": [], "linear": linear}
        for key, linear in (("root", 0), ("a", 16), ("alias_a", 16), ("b", 32), ("dead", 48))
    ]
    selection = LoweringSelection(functions, frozenset({"root"}), lambda item: item["linear"])
    targets = {"root": 16, "a": 32, "alias_a": 32, "b": 16}
    visited = []
    for function in selection:
        visited.append(function["id"])
        transfer = {"source": {"transfer": {
            "kind": "direct_call", "target": {"raw": targets[function["id"]]},
        }}}
        selection.observe([transfer, transfer])
    assert visited == ["root", "a", "alias_a", "b"]
