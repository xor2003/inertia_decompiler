"""Native PE import routing, target preservation and conditional proof controls."""

import json
import struct
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from tools.dosunit.architectures.flat32_loader import load_flat32_project
from tools.dosunit.compare.flat32_call_composition import CallCompositionLimits, compare_functions_with_calls
from tools.dosunit.compare.flat32_external_binding import bind_project_imports
from tools.dosunit.compare.flat32_external_call import ExternalStackCleanup, Flat32ExternalCall
from tools.dosunit.contracts.flat32_proof_domain import Flat32ProofDomain
from tools.dosunit.tests.test_pe32_import_service import ENTRY, IAT_SLOT, pe32_import_bytes

pytestmark = [pytest.mark.ssa_z3, pytest.mark.runtime]
CONTRACT = Flat32ExternalCall("kernel32.dll", "GetTickCount", 0, ExternalStackCleanup.CALLEE)
JUMP = b"\xff\x25" + struct.pack("<I", IAT_SLOT)


def compare(tmp_path: Path, code: bytes, *, declared: bool = True, candidate_code: bytes | None = None,
            preserve_iat: bool = False) -> dict:
    """Run both native PE lanes through the public call-composition comparator."""
    left_path, right_path = tmp_path / "left.exe", tmp_path / "right.exe"
    left_path.write_bytes(pe32_import_bytes(code))
    candidate_code = code if candidate_code is None else candidate_code
    right_path.write_bytes(pe32_import_bytes(candidate_code))
    return compare_functions_with_calls(
        load_flat32_project(left_path), load_flat32_project(right_path),
        oracle_entry=ENTRY, candidate_entry=ENTRY,
        oracle_functions={ENTRY: len(code)}, candidate_functions={ENTRY: len(candidate_code)},
        outputs=("eax",), timeout_ms=10000,
        external_contracts=(replace(CONTRACT, preserve_import_bindings=True) if preserve_iat else CONTRACT,) if declared else (),
        entry_domain=Flat32ProofDomain(0x7F000, 0x80000),
    )


def test_import_tail_is_conditional_with_live_target_evidence(tmp_path: Path) -> None:
    baseline = compare(tmp_path, JUMP, declared=False)
    assert baseline["status"] == "refused"
    assert baseline["reason"] == "indirect_jump"
    result = compare(tmp_path, JUMP)
    assert result["status"] == "conditional", result
    sites = result["external_call_assumptions"]["oracle_sites"]
    assert len(sites) == 1 and sites[0]["target_preserved"]
    assert sites[0]["entry_iat_binding_assumed"]


def test_overwritten_iat_refuses_even_for_identical_binaries(tmp_path: Path) -> None:
    code = b"\xc7\x05" + struct.pack("<II", IAT_SLOT, 0x12345678) + JUMP
    result = compare(tmp_path, code)
    assert result["status"] == "refused"
    assert result["reason"] == "external_import_target_not_preserved"


def test_possible_alias_to_iat_refuses(tmp_path: Path) -> None:
    result = compare(tmp_path, b"\xc7\x00\x78\x56\x34\x12" + JUMP)  # mov [eax],imm
    assert result["status"] == "refused"
    assert result["reason"] == "external_import_target_not_preserved"


def test_direct_iat_call_continues_to_native_return(tmp_path: Path) -> None:
    code = b"\xff\x15" + struct.pack("<I", IAT_SLOT) + b"\xc3"
    result = compare(tmp_path, code)
    assert result["status"] == "conditional", result
    assert result["return_targets_proved"] == 2


def test_two_imports_require_explicit_iat_frame(tmp_path: Path) -> None:
    code = (b"\xff\x15" + struct.pack("<I", IAT_SLOT)) * 2 + b"\xc3"
    assert compare(tmp_path, code)["reason"] == "external_import_target_not_preserved"
    result = compare(tmp_path, code, preserve_iat=True)
    assert result["status"] == "conditional", result
    sites = result["external_call_assumptions"]["oracle_sites"]
    assert len(sites) == 2
    assert sites[0]["preserved_import_slots"] == [hex(IAT_SLOT)]


def test_iat_frame_does_not_hide_program_overwrite(tmp_path: Path) -> None:
    call = b"\xff\x15" + struct.pack("<I", IAT_SLOT)
    overwrite = b"\xc7\x05" + struct.pack("<II", IAT_SLOT, 0x12345678)
    result = compare(tmp_path, call + overwrite + call + b"\xc3", preserve_iat=True)
    assert result["status"] == "refused"
    assert result["reason"] == "external_import_target_not_preserved"


def test_changed_memory_is_not_proved_equal(tmp_path: Path) -> None:
    result = compare(tmp_path, JUMP, candidate_code=b"\xc7\x05\x00\x00\x60\x00\x01\x00\x00\x00" + JUMP)
    assert result["status"] != "conditional", result
    assert result["reason"] == "opaque_external_call_countermodel"


def test_import_binding_uses_loaded_bytes_after_file_changes(tmp_path: Path) -> None:
    path = tmp_path / "loaded.exe"
    raw = pe32_import_bytes(JUMP)
    path.write_bytes(raw)
    project = load_flat32_project(path)
    path.write_bytes(b"not the loaded executable")
    bindings = bind_project_imports(project, (CONTRACT,))
    assert bindings[IAT_SLOT].contract == CONTRACT
    assert project.loader.main_object.source_pe_bytes == raw


@pytest.mark.parametrize("overwrite", [False, True])
def test_nested_import_uses_root_memory(tmp_path: Path, overwrite: bool) -> None:
    prefix = b"\xc7\x05" + struct.pack("<II", IAT_SLOT, 0x12345678) if overwrite else b""
    caller = prefix + b"\xe8\x01\x00\x00\x00\xc3"
    path = tmp_path / "nested.exe"
    path.write_bytes(pe32_import_bytes(caller + JUMP))
    project = load_flat32_project(path)
    functions = {ENTRY: len(caller), ENTRY + len(caller): len(JUMP)}
    result = compare_functions_with_calls(
        project, project, oracle_entry=ENTRY, candidate_entry=ENTRY,
        oracle_functions=functions, candidate_functions=functions,
        outputs=("eax",), timeout_ms=10000, external_contracts=(CONTRACT,),
        limits=CallCompositionLimits(max_inline_depth=0),
        entry_domain=Flat32ProofDomain(0x7F000, 0x80000),
    )
    assert result["status"] == ("refused" if overwrite else "conditional"), result
    if overwrite:
        assert result["reason"] == "external_import_target_not_preserved"


def test_msc8_cli_publishes_external_premise(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from tools.comparator.msc8_cli import main

    for side in ("oracle", "candidate"):
        (tmp_path / (side + ".exe")).write_bytes(pe32_import_bytes(JUMP))
        end = ENTRY if side == "oracle" else ENTRY + len(JUMP) - 1
        (tmp_path / (side + ".lst")).write_text(
            f".text:00401000 sub_401000 proc near\n.text:{end:08X} sub_401000 endp\n")
    catalog = tmp_path / "external.json"
    catalog.write_text(json.dumps({"schema": "dosunit.flat32_external_calls.v1", "functions": {
        "sub_401000": [{"dll": "kernel32.dll", "name": "GetTickCount", "argument_count": 0, "cleanup": "callee"}]}}))
    monkeypatch.setattr(sys, "argv", ["z3cmp32", "--oracle-exe", str(tmp_path / "oracle.exe"),
        "--oracle-lst", str(tmp_path / "oracle.lst"), "--candidate-exe", str(tmp_path / "candidate.exe"),
        "--candidate-lst", str(tmp_path / "candidate.lst"), "--functions", "sub_401000",
        "--candidate-lst-end-kind", "last-byte",
        "--mode", "matched-cfg", "--external-call-catalog", str(catalog), "--out-dir", str(tmp_path / "out")])
    main()
    report = json.loads((tmp_path / "out/compare.json").read_text())
    row = report["results"][0]
    assert row["status"] == "conditional", row
    assert row["external_call_assumptions"]["oracle_sites"][0]["target_preserved"]
    assert row["strict_cfg_result"]["status"] == "refused"
    assert report["auxiliary_inputs"]["external_call_catalog"]["path"] == str(catalog)


@pytest.mark.parametrize("prefix,declared,expected", [
    (b"", True, "conditional"),
    (b"", False, "refused"),
    (b"\x90", True, "refused"),
    (b"\xc7\x00\x78\x56\x34\x12", True, "refused"),
])
def test_terminal_import_thunk_does_not_consume_inline_depth(
    tmp_path: Path, prefix: bytes, declared: bool, expected: str,
) -> None:
    """Only a declared native JMP-IAT leaf may cross the depth boundary."""
    caller = b"\xe8\x01\x00\x00\x00\xc3"
    thunk = prefix + JUMP
    path = tmp_path / "depth.exe"
    path.write_bytes(pe32_import_bytes(caller + thunk))
    project = load_flat32_project(path)
    functions = {ENTRY: len(caller), ENTRY + len(caller): len(thunk)}
    result = compare_functions_with_calls(
        project, project, oracle_entry=ENTRY, candidate_entry=ENTRY,
        oracle_functions=functions, candidate_functions=functions,
        outputs=("eax",), timeout_ms=10000,
        limits=CallCompositionLimits(max_inline_depth=0),
        external_contracts=(CONTRACT,) if declared else (),
        entry_domain=Flat32ProofDomain(0x7F000, 0x80000),
    )
    assert result["status"] == expected, result
    if expected == "refused":
        assert result["reason"] == "call_inline_depth_limit", result
    else:
        assert result["external_call_assumptions"]["oracle_sites"][0]["target_preserved"]
        assert result["return_targets_proved"] == 2


@pytest.mark.parametrize("declared_size,call_budget,reason", [
    (5, 32, "call_inline_depth_limit"),
    (6, 0, "call_inline_budget"),
])
def test_import_depth_exemption_keeps_extent_and_work_budgets(
    tmp_path: Path, declared_size: int, call_budget: int, reason: str,
) -> None:
    """No byte-range widening or unbounded inlining accompanies a leaf exemption."""
    path = tmp_path / "bounded.exe"
    path.write_bytes(pe32_import_bytes(b"\xe8\x01\x00\x00\x00\xc3" + JUMP))
    project = load_flat32_project(path)
    functions = {ENTRY: 6, ENTRY + 6: declared_size}
    result = compare_functions_with_calls(
        project, project, oracle_entry=ENTRY, candidate_entry=ENTRY,
        oracle_functions=functions, candidate_functions=functions,
        outputs=("eax",), timeout_ms=10000,
        limits=CallCompositionLimits(max_inline_depth=0, max_inlined_calls=call_budget),
        external_contracts=(CONTRACT,),
        entry_domain=Flat32ProofDomain(0x7F000, 0x80000),
    )
    assert result["status"] == "refused", result
    assert result["reason"] == reason, result


def test_disjoint_iat_writes_need_no_value_solver(monkeypatch: pytest.MonkeyPatch) -> None:
    """Preservation depends on write addresses, not expensive stored expressions."""
    from tools.dosunit.compare import flat32_external_binding as binding

    def unexpected_solver(*args: object, **kwargs: object) -> dict:
        pytest.fail("disjoint writes must discharge before the value solver")

    monkeypatch.setattr(binding.S, "_compare_functions", unexpected_solver)
    memory = {"op": "mem_input", "name": "mem", "addr_width": 32, "value_width": 8}
    address = {"op": "input", "name": "esp", "width": 32}
    for index in range(28):
        address = {"op": "sub", "width": 32, "args": [address, {"op": "const", "width": 32, "value": "0x4"}]}
        memory = {"op": "storele", "width": 0, "args": [memory, address,
                  {"op": "input", "name": f"data{index}", "width": 32}]}
    target = {"op": "loadle", "width": 32, "args": [memory, {"op": "const", "width": 32, "value": hex(IAT_SLOT)}]}
    binding.prove_import_target(target, binding.ExternalImportBinding(IAT_SLOT, CONTRACT),
                                timeout_ms=1000, input_constraints=Flat32ProofDomain(0x7F000, 0x80000).constraints())


@pytest.mark.parametrize("address,width,accepted", [
    (IAT_SLOT - 4, 32, True), (IAT_SLOT - 3, 32, False),
    (IAT_SLOT + 3, 8, False), (IAT_SLOT + 4, 8, True),
    (0xFFFFFFFF, 32, False),
])
def test_region_preservation_checks_all_store_bytes(address: int, width: int, accepted: bool) -> None:
    from tools.dosunit.compare.flat32_memory_preservation import prove_region_preserved

    initial = {"op": "mem_input", "name": "mem", "addr_width": 32, "value_width": 8}
    memory = {"op": "storele", "width": 0, "args": [initial,
              {"op": "const", "width": 32, "value": hex(address)},
              {"op": "const", "width": width, "value": "0"}]}
    assert (prove_region_preserved(memory, IAT_SLOT, 4) is not None) == accepted
    branch = {"op": "ite", "width": 0, "args": [
        {"op": "input", "width": 1, "name": "condition"}, initial, memory]}
    assert (prove_region_preserved(branch, IAT_SLOT, 4) is not None) == accepted


def test_region_preservation_defers_unknown_alias_wrap_and_memory() -> None:
    from tools.dosunit.compare.flat32_memory_preservation import prove_region_preserved

    initial = {"op": "mem_input", "name": "mem", "addr_width": 32, "value_width": 8}
    pointer = {"op": "input", "name": "esp", "width": 32}
    address = {"op": "sub", "width": 32, "args": [pointer, {"op": "const", "width": 32, "value": "4"}]}
    value = {"op": "const", "width": 32, "value": "0"}
    memory = {"op": "storele", "width": 0, "args": [initial, address, value]}
    assert prove_region_preserved(memory, IAT_SLOT, 4) is None
    assert prove_region_preserved(memory, IAT_SLOT, 4,
                                  [{"name": "esp", "kind": "unsigned_range", "min": 0, "max": 8}]) is None
    assert prove_region_preserved({**initial, "name": "other"}, IAT_SLOT, 4) is None
    assert prove_region_preserved({"op": "external_memory", "width": 0}, IAT_SLOT, 4) is None
    for _ in range(300):
        memory = {"op": "storele", "width": 0, "args": [memory,
                  {"op": "const", "width": 32, "value": "0"}, value]}
    assert prove_region_preserved(memory, IAT_SLOT, 4) is None


@pytest.mark.parametrize("case,checked", [("failure", True), ("success", False),
    ("arbitrary", False), ("overwrite", False), ("no_stack_domain", False)])
def test_guarded_allocation_failure_preserves_callback_only_on_proved_path(case: str, checked: bool) -> None:
    """Failure writes no region; prefix aliases and later writes remain observable."""
    from tools.dosunit.compare.flat32_call_contracts import _initial_state, _register_widths
    from tools.dosunit.compare.flat32_external_call import ExternalMemoryAccess, _constant, external_call_state
    from tools.dosunit.compare.flat32_guarded_memory import check_guarded_region_preservation

    before = _initial_state(_register_widths())
    incoming = {**before, "memory": {"op": "storele", "width": 0,
                "args": [before["memory"], before["esp"], _constant(0x401005)]}}
    contract = Flat32ExternalCall("kernel32.dll", "ExampleAlloc", 3, ExternalStackCleanup.CALLEE,
        memory_access=ExternalMemoryAccess.RETURNED_REGION, write_size_argument=2)
    if case == "arbitrary":
        contract = replace(contract, memory_access=ExternalMemoryAccess.ARBITRARY, write_size_argument=None)
    post = external_call_state(contract, incoming)
    guard = {"op": "ne" if case == "success" else "eq", "width": 1, "args": [post["eax"], _constant(0)]}
    if case == "overwrite":
        post["memory"] = {"op": "storele", "width": 0, "args": [post["memory"], _constant(IAT_SLOT), _constant(99)]}
    domain = None if case == "no_stack_domain" else Flat32ProofDomain(0x7F000, 0x80000).constraints()
    result = check_guarded_region_preservation(before["memory"], post["memory"], guard, IAT_SLOT, 4,
                                                timeout_ms=1000, input_constraints=domain)
    assert (result["status"] == "checked") is checked, result
    assert not result["function_equivalence_proved"]
    assert not result["guard_feasibility_proved"]


@pytest.mark.parametrize("path_valid", [True, False])
def test_factored_memory_check_proves_intermediate_guard_instead_of_assuming_it(path_valid: bool) -> None:
    """A valid failure frame cannot justify preservation on every path."""
    from tools.dosunit.compare.flat32_call_contracts import _initial_state, _register_widths
    from tools.dosunit.compare.flat32_external_call import ExternalMemoryAccess, _constant, external_call_state
    from tools.dosunit.compare.flat32_guarded_memory import check_region_preservation_via_guard

    before = _initial_state(_register_widths())
    contract = Flat32ExternalCall("kernel32.dll", "ExampleAlloc", 3, ExternalStackCleanup.CALLEE,
        memory_access=ExternalMemoryAccess.RETURNED_REGION, write_size_argument=2)
    post = external_call_state(contract, before)
    failure = {"op": "eq", "width": 1, "args": [post["eax"], _constant(0)]}
    path = failure if path_valid else {"op": "const", "width": 1, "value": "0x1"}
    result = check_region_preservation_via_guard(before["memory"], post["memory"], path, failure, IAT_SLOT, 4,
                                                input_constraints=Flat32ProofDomain(0x7F000, 0x80000).constraints())
    assert (result["status"] == "checked") is path_valid, result
    assert result["region_lemma"]["status"] == "checked"
    assert not result["function_equivalence_proved"]


def test_guard_substitution_cannot_narrow_a_dword_store_to_one_byte() -> None:
    """An 8-bit comparison literal does not authorize changing a 32-bit store width."""
    from tools.dosunit.compare.flat32_external_call import _constant
    from tools.dosunit.compare.flat32_guarded_memory import check_guarded_region_preservation

    memory = {"op": "mem_input", "name": "mem", "addr_width": 32, "value_width": 8}
    eax = {"op": "input", "name": "eax", "width": 32}
    before = {"op": "storele", "width": 0, "args": [memory, _constant(IAT_SLOT), _constant(0x123456FF)]}
    after = {"op": "storele", "width": 0, "args": [before, _constant(IAT_SLOT), eax]}
    guard = {"op": "eq", "width": 1, "args": [eax, {"op": "const", "width": 8, "value": "0xff"}]}
    proof = check_guarded_region_preservation(before, after, guard, IAT_SLOT, 4)
    assert proof["preprocessing"] == "none"
    assert proof["status"] == "mismatch", proof


@pytest.mark.parametrize("other,accepted", [(0x7FFE0, True), (IAT_SLOT, False), (None, False)])
def test_conditional_stack_address_preserves_iat_only_for_both_arms(other: int | None, accepted: bool) -> None:
    """A joined address is safe only when every possible destination is disjoint."""
    from tools.dosunit.compare.flat32_memory_preservation import prove_region_preserved

    initial = {"op": "mem_input", "name": "mem", "addr_width": 32, "value_width": 8}
    alternate = ({"op": "input", "name": "unknown", "width": 32} if other is None
                 else {"op": "const", "width": 32, "value": hex(other)})
    address = {"op": "ite", "width": 32, "args": [
        {"op": "input", "name": "condition", "width": 1},
        {"op": "input", "name": "esp", "width": 32}, alternate]}
    memory = {"op": "storele", "width": 0, "args": [initial, address,
              {"op": "input", "name": "data", "width": 32}]}
    proof = prove_region_preserved(memory, IAT_SLOT, 4,
        [{"name": "esp", "kind": "unsigned_range", "min": 0x7F000, "max": 0x80000}])
    assert (proof is not None) == accepted


@pytest.mark.parametrize("case,expected", [("disjoint", True), ("no_domain", False),
    ("overlap", False), ("relocation_collision", False), ("other_memory", False)])
def test_root_read_pruning_keeps_aliases_and_relocation_collisions(case: str, expected: bool) -> None:
    """Read simplification needs both native and relocated byte-preservation proofs."""
    from tools.dosunit.compare import straightline_ssa as scalar
    from tools.dosunit.compare.flat32_memory_preservation import simplify_preserved_root_reads

    memory = {"op": "mem_input", "name": "other" if case == "other_memory" else "mem",
              "addr_width": 32, "value_width": 8}
    def literal(value: int) -> dict[str, object]:
        return {"op": "const", "width": 32, "value": hex(value)}
    esp = {"op": "input", "name": "esp", "width": 32}
    assignments = [
        {"id": "stack", "op": "sub", "width": 32, "args": [esp, literal(4)]},
        {"id": "save", "op": "storele", "width": 0,
         "args": [memory, {"ref": "stack"}, literal(12)]},
        {"id": "global", "op": "storele", "width": 0,
         "args": [{"ref": "save"}, literal(0x1FF if case == "overlap" else 0x100), literal(7)]},
        {"id": "read", "op": "loadle", "width": 8,
         "args": [{"ref": "global"}, literal(0x200)]},
    ]
    constraints = [] if case == "no_domain" else [
        {"name": "esp", "kind": "unsigned_range", "min": 0x70000, "max": 0x80000}]
    function = {"assignments": assignments, "outputs": {"eax": {"ref": "read"}},
                "inputs": [{"name": "esp", "width": 32}, {"kind": "memory", "name": memory["name"],
                "addr_width": 32, "value_width": 8}], "input_constraints": constraints}
    def normalized(value: int, width: int) -> int:
        return 0x200 if case == "relocation_collision" and value == 0x100 else value
    result = simplify_preserved_root_reads(function, normalize=normalized, check_budget=lambda: None)
    assert bool(result["root_read_preservation"]) == expected
    assert result["assignments"][1] is assignments[1]
    assert result["assignments"][2] is assignments[2]
    if expected:
        proof = scalar._compare_functions(function, result, timeout_ms=1000, input_constraints=constraints)
        assert proof["status"] == "passed", proof
        assert result["assignments"][-1]["args"][0] == memory


@pytest.mark.parametrize("value,shift,expected", [(3, 1, (6, 6)),
    (0x80000000, 1, None), (1, 32, None)])
def test_read_address_shift_requires_nonwrapping_bounds(value: int, shift: int, expected) -> None:
    from tools.dosunit.compare.flat32_memory_preservation import _RegionCheck

    term = {"op": "shl", "width": 32, "args": [
        {"op": "const", "width": 32, "value": hex(value)},
        {"op": "const", "width": 8, "value": hex(shift)}]}
    assert _RegionCheck(0, 1, [], []).interval(term) == expected


def test_read_address_zero_idiom_requires_the_same_input() -> None:
    from tools.dosunit.compare.flat32_memory_preservation import _RegionCheck

    a = {"op": "input", "width": 32, "name": "ecx"}
    term = {"op": "sub", "width": 32, "args": [a, dict(a)]}
    assert _RegionCheck(0, 1, [], []).interval(term) == (0, 0)
    term["args"][1] = {**a, "name": "edx"}
    assert _RegionCheck(0, 1, [], []).interval(term) is None


@pytest.mark.parametrize("changed", [False, True])
def test_unused_external_catalog_does_not_change_native_verdict(tmp_path: Path, changed: bool) -> None:
    """A declared but never executed import cannot make a concrete mismatch opaque."""
    code = b"\xb8\x01\x00\x00\x00\xc3"
    candidate = b"\xb8\x02\x00\x00\x00\xc3" if changed else code
    result = compare(tmp_path, code, candidate_code=candidate)
    assert result["status"] == ("failed" if changed else "conditional"), result
    assert "external_call_assumptions" not in result


@pytest.mark.parametrize("boundary,accepted", [(IAT_SLOT + 4, True), (IAT_SLOT + 3, False)])
def test_import_preservation_uses_executed_path_guard(tmp_path: Path, boundary: int, accepted: bool) -> None:
    """A branch can exclude all IAT bytes; excluding only three is insufficient."""
    # cmp eax,boundary; jb return; mov byte [eax],0x78; jmp [IAT]; return: ret
    code = b"\x3d" + struct.pack("<I", boundary) + b"\x72\x09\xc6\x00\x78" + JUMP + b"\xc3"
    result = compare(tmp_path, code)
    assert result["status"] == ("conditional" if accepted else "refused"), result
    if accepted:
        sites = result["external_call_assumptions"]["oracle_sites"]
        assert sites[0]["target_preservation_proof"]["method"] == "smt_path_guarded_target_equality"
    else:
        assert result["reason"] == "external_import_target_not_preserved"


@pytest.mark.parametrize("boundary,accepted", [(IAT_SLOT + 4, True), (IAT_SLOT + 3, False)])
def test_import_thunk_inherits_root_path_guard(tmp_path: Path, boundary: int, accepted: bool) -> None:
    """A real direct CALL keeps the caller guard in root-bound thunk execution."""
    body = b"\x3d" + struct.pack("<I", boundary) + b"\x72\x08\xc6\x00\x78\xe8\x01\x00\x00\x00\xc3"
    path = tmp_path / "guarded-call.exe"
    path.write_bytes(pe32_import_bytes(body + JUMP))
    project = load_flat32_project(path)
    functions = {ENTRY: len(body), ENTRY + len(body): len(JUMP)}
    result = compare_functions_with_calls(project, project,
        oracle_entry=ENTRY, candidate_entry=ENTRY,
        oracle_functions=functions, candidate_functions=functions,
        outputs=("eax",), timeout_ms=10000, external_contracts=(CONTRACT,),
        entry_domain=Flat32ProofDomain(0x7F000, 0x80000))
    assert result["status"] == ("conditional" if accepted else "refused"), result
    if not accepted:
        assert result["reason"] == "external_import_target_not_preserved"


@pytest.mark.parametrize("tampered", [False, True])
@pytest.mark.parametrize("status", ["conditional", "failed"])
def test_composition_admission_rederives_import_map(monkeypatch, tampered, status):
    from tools.dosunit.compare import flat32_external_binding as binding
    from tools.dosunit.compare.flat32_proof_retry import _admit_import_composition

    monkeypatch.setattr(binding, "import_slot_correspondence", lambda *args: {0x3000: 0x2000})
    mapping = {"0x5000": "0x4000", "0x3000": "0x2000"}
    if tampered:
        mapping["0x6000"] = "0x7000"
    document = {"status": status, "oracle_inlined_calls": 1,
                "assumptions": {"entry": "explicit"},
                "normalization_assumptions": {"proved": False, "constant_map": mapping}}
    result = _admit_import_composition(document, {0x5000: 0x4000}, None, None, (object(),))
    if tampered:
        assert result is None
    else:
        assert result["status"] == status
