"""Prove caller boundaries from block bytes, not aggregate function sizes."""

from dataclasses import replace
from types import SimpleNamespace

import pytest
from angr_platforms.X86_16.frontend_boundary_transport import (
    capture_function_boundary_8616,
    restore_function_boundary_8616,
)

from inertia_decompiler.project_loading import _build_project_from_bytes


def _fixture(code=b"\xeb\x03\x90\x90\x90\xc3", base=0x1000):
    project = _build_project_from_bytes(code, base_addr=base, entry_point=base)
    blocks = (project.factory.block(base, opt_level=0), project.factory.block(base + 5, opt_level=0))
    function = SimpleNamespace(addr=base, size=3, blocks=blocks)
    return project, function


def test_discontiguous_function_round_trip_uses_extents_not_summed_size():
    source, function = _fixture()
    proof = capture_function_boundary_8616(source, function)
    assert proof is not None
    assert proof.entry == 0x1000
    assert proof.end == 0x1006
    destination, _ = _fixture()
    restored = restore_function_boundary_8616(destination, proof)
    assert restored is not None
    assert restored.project is destination
    assert restored.reachable_instruction_addrs == {0x1000, 0x1005}
    assert restore_function_boundary_8616(destination, proof) is restored


def test_missing_block_does_not_turn_into_closed_boundary():
    project, function = _fixture()
    function.blocks = function.blocks[:1]
    assert capture_function_boundary_8616(project, function) is None


def test_reachable_bytes_in_unclaimed_gap_refuse():
    project, function = _fixture(bytes.fromhex("90 90 90 90 90 c3"))
    function.blocks = (SimpleNamespace(addr=0x1000, size=2), function.blocks[1])
    assert capture_function_boundary_8616(project, function) is None


def test_changed_binary_refuses_before_using_cached_reachability():
    source, function = _fixture()
    proof = capture_function_boundary_8616(source, function)
    assert proof is not None
    destination, _ = _fixture(bytes.fromhex("eb 03 90 90 90 cb"))
    with pytest.raises(ValueError, match="bytes disagree"):
        restore_function_boundary_8616(destination, proof)


def test_wrong_project_mapping_cannot_rebase_proof_implicitly():
    source, function = _fixture()
    proof = capture_function_boundary_8616(source, function)
    assert proof is not None
    destination, _ = _fixture(base=0x2000)
    with pytest.raises(ValueError, match="unmapped"):
        restore_function_boundary_8616(destination, proof)


@pytest.mark.parametrize("field,value", [("entry", True), ("entry", -1), ("entry", 0x1002), ("blocks", ())])
def test_invalid_boundary_proof_is_rejected(field, value):
    project, function = _fixture()
    proof = capture_function_boundary_8616(project, function)
    assert proof is not None
    with pytest.raises(ValueError):
        restore_function_boundary_8616(project, replace(proof, **{field: value}))


def test_missing_third_party_inventory_is_unknown_not_guessed():
    project, _ = _fixture()
    assert capture_function_boundary_8616(project, SimpleNamespace(addr=0x1000, size=6)) is None


def test_caller_catalog_ranges_use_proven_extents_not_summed_block_size():
    from angr_platforms.X86_16.lowering.project_callee_callsite_collection import _function_ranges_8616

    project, function = _fixture()
    assert function.size == 3
    assert _function_ranges_8616(project, (function,)) == ((0x1000, 0x1006),)


def test_caller_catalog_without_blocks_does_not_guess_range_from_size():
    from angr_platforms.X86_16.lowering.project_callee_callsite_collection import _function_ranges_8616

    project, _ = _fixture()
    assert _function_ranges_8616(project, (SimpleNamespace(addr=0x1000, size=6),)) == ()


def test_explicit_caller_ranges_remain_authoritative():
    from angr_platforms.X86_16.lowering.project_callee_callsite_collection import _function_ranges_8616

    project, function = _fixture()
    project._inertia_caller_function_ranges_8616 = ((0x1000, 0x1006),)
    assert _function_ranges_8616(project, (function,)) == ((0x1000, 0x1006),)


def test_unreachable_catalog_callsite_cannot_receive_boundary_witness():
    from angr_platforms.X86_16.frontend_boundary_transport import function_boundary_record_8616

    project, function = _fixture()
    assert function_boundary_record_8616(project, function, required_instruction=0x1003) is None
    assert function_boundary_record_8616(project, function, required_entry=0x1001) is None


@pytest.mark.parametrize("original_owner", [False, True])
@pytest.mark.parametrize("corruption", [None, "caller", "callsite", "digest", "fields"])
def test_callsite_codec_retains_boundary_on_fresh_project(original_owner, corruption):
    import json

    from angr_platforms.X86_16.lowering.callee_callsite_codec import (
        callee_callsite_census_map_from_record_8616,
        callee_callsite_census_map_record_8616,
    )
    from angr_platforms.X86_16.lowering.callee_callsite_contracts import (
        CalleeCallsiteCensus8616,
        CalleeCallsiteFact8616,
        attach_callee_callsite_censuses_8616,
    )

    source, function = _fixture()
    fact = CalleeCallsiteFact8616(source, function, 0x2000, 0x1000, 0x1000, None)
    active = SimpleNamespace(_inertia_original_project=source) if original_owner else source
    attach_callee_callsite_censuses_8616(active, {0x2000: CalleeCallsiteCensus8616(0x2000, (fact,), 1, 0, 1)})
    record = json.loads(json.dumps(callee_callsite_census_map_record_8616(active)))
    destination, _ = _fixture()
    target = SimpleNamespace(_inertia_original_project=destination) if original_owner else destination
    encoded_fact = record[0]["facts"][0]
    if corruption == "caller":
        encoded_fact["caller_addr"] += 1
    elif corruption == "callsite":
        encoded_fact["callsite_addr"] += 3
    elif corruption == "digest":
        encoded_fact["caller_boundary"]["blocks"][0]["digest"] = "0" * 64
    elif corruption == "fields":
        del encoded_fact["caller_boundary"]["blocks"][0]["size"]
    if corruption is not None:
        with pytest.raises(ValueError, match="caller boundary"):
            callee_callsite_census_map_from_record_8616(target, record)
        return
    restored = callee_callsite_census_map_from_record_8616(target, record)[0x2000].facts[0]
    assert restored.caller_function is not None
    assert restored.caller_function.project is destination
    assert restored.caller_function.reachable_instruction_addrs == {0x1000, 0x1005}
    from angr_platforms.X86_16.ir.function_ssa_registry import FunctionSSAArtifactVerdict8616
    from angr_platforms.X86_16.semantics.call_stack_effect_pipeline import (
        semantic_function_ssa_artifact_at_address_8616,
    )

    ssa = semantic_function_ssa_artifact_at_address_8616(
        destination, restored.caller_addr, function=restored.caller_function,
    )
    assert ssa.verdict is FunctionSSAArtifactVerdict8616.PROVEN
    assert ssa.artifact is not None


def test_boundary_owner_participates_in_persistent_cache_identity():
    from pathlib import Path

    from inertia_decompiler.cache import DECOMPILATION_CACHE_SOURCE_FILES, PROGRAM_CALLSITE_CACHE_SOURCE_FILES

    owner = Path(__file__).resolve().parents[1] / "angr_platforms/X86_16/frontend_boundary_transport.py"
    assert owner in DECOMPILATION_CACHE_SOURCE_FILES
    assert owner in PROGRAM_CALLSITE_CACHE_SOURCE_FILES


@pytest.mark.parametrize("suffix,accepted", [("c3", True), ("40 c3", False)])
def test_return_semantics_consume_reconstructed_frontend_edges(suffix, accepted):
    from angr_platforms.X86_16.semantics.terminal_return_passthrough import (
        collect_terminal_return_passthrough_evidence_8616,
    )

    code = bytes.fromhex("e8 00 00 " + suffix)
    source = _build_project_from_bytes(code, base_addr=0x1000, entry_point=0x1000)
    function = SimpleNamespace(addr=0x1000, blocks=(
        source.factory.block(0x1000, opt_level=0), source.factory.block(0x1003, opt_level=0),
    ))
    witness = capture_function_boundary_8616(source, function)
    assert witness is not None
    destination = _build_project_from_bytes(code, base_addr=0x1000, entry_point=0x1000)
    boundary = restore_function_boundary_8616(destination, witness)
    assert boundary is not None
    evidence = collect_terminal_return_passthrough_evidence_8616(destination, boundary, (0x1000,))
    assert evidence.complete is accepted
