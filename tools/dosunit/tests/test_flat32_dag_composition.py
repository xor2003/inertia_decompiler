"""Reconverging native branch chains retain full semantics under fixed budgets."""
import pytest

from tools.dosunit.tests.test_flat32_comparator_lane import BASE, _compare_calls, _driver_lane

pytestmark = pytest.mark.ssa_z3


def _diamonds(changed=False):
    raw = bytearray.fromhex("8b54240431c0")
    for bit in range(8):
        raw += bytes.fromhex("f7c2") + (1 << bit).to_bytes(4, "little")
        raw += bytes.fromhex("7405b9") + (1 << bit).to_bytes(4, "little")
        # Both arms reconverge before the next test; ECX is deliberately live.
        raw += bytes.fromhex("09c8")
    raw += bytes.fromhex("83c001" if changed else "83c000")
    return bytes(raw + b"\xc3")


@pytest.mark.parametrize("changed,expected", [(False, "passed"), (True, "failed")])
def test_diamond_chain_compares_without_expanding_all_paths(changed, expected):
    left, right = _diamonds(), _diamonds(changed)
    with _driver_lane("msc8") as lane:
        result = _compare_calls(lane, left.hex(), right.hex(),
                                oracle_functions={BASE: len(left)},
                                candidate_functions={BASE: len(right)}, outputs=("eax",))
    assert result["status"] == expected, result


def test_dag_does_not_hide_output_memory_difference():
    prefix = _diamonds()[:-1]
    left = prefix + bytes.fromhex("c70607000000c3")
    right = prefix + bytes.fromhex("c70608000000c3")
    with _driver_lane("msc8") as lane:
        result = _compare_calls(lane, left.hex(), right.hex(),
                                oracle_functions={BASE: len(left)},
                                candidate_functions={BASE: len(right)}, outputs=("eax",))
    assert result["status"] == "failed", result
    assert any(item.get("kind") == "memory_expr_changed" for item in result["mismatches"])


def test_dag_keeps_cycles_with_the_induction_owner():
    prefix = _diamonds()[:-1]
    code = prefix + b"\xe9" + (-len(prefix) - 5).to_bytes(4, "little", signed=True)
    with _driver_lane("msc8") as lane:
        result = _compare_calls(lane, code.hex(), code.hex(),
                                oracle_functions={BASE: len(code)},
                                candidate_functions={BASE: len(code)}, outputs=("eax",))
    assert result["status"] == "refused", result
    assert result["reason"] == "loop_requires_inductive_proof"


@pytest.mark.parametrize("changed,expected", [(False, "passed"), (True, "failed")])
def test_dag_preserves_both_return_arms(changed, expected):
    prefix = _diamonds()[:-1]
    # Two separately returning suffixes; changing just the taken arm must fail.
    left = prefix + bytes.fromhex("85d2740683c002c3909083c003c3")
    right = prefix + bytes.fromhex("85d2740683c002c3909083c004c3" if changed
                                   else "85d2740683c002c3909083c003c3")
    with _driver_lane("msc8") as lane:
        result = _compare_calls(lane, left.hex(), right.hex(),
                                oracle_functions={BASE: len(left)},
                                candidate_functions={BASE: len(right)}, outputs=("eax",))
    assert result["status"] == expected, result


@pytest.mark.parametrize("changed,expected", [(False,"passed"),(True,"failed")])
@pytest.mark.parametrize("memory", [False,True])
def test_dag_composes_shared_call_tail_once(changed,expected,memory):
    prefix=_diamonds()[:-1]
    root=prefix+bytes.fromhex("e801000000c3")
    original=("c744240807000000c3" if memory else "83c001c3")
    altered=("c744240808000000c3" if memory else "83c002c3") if changed else original
    left=root+bytes.fromhex(original)
    right=root+bytes.fromhex(altered)
    functions={BASE:len(root),BASE+len(root):len(bytes.fromhex(original))}
    with _driver_lane("msc8") as lane:
        result=_compare_calls(lane,left.hex(),right.hex(),oracle_functions=functions,
                              candidate_functions=functions,outputs=("eax",))
    assert result["status"] == expected,result
    assert result["oracle_inlined_calls"] == 1
    assert result["return_targets_proved"] == 2


def test_dag_shared_call_keeps_return_address_proof():
    root=_diamonds()[:-1]+bytes.fromhex("e801000000c3")
    leaf=bytes.fromhex("c7042407000000c3")
    code=root+leaf
    functions={BASE:len(root),BASE+len(root):len(leaf)}
    with _driver_lane("msc8") as lane:
        result=_compare_calls(lane,code.hex(),code.hex(),oracle_functions=functions,
                              candidate_functions=functions,outputs=("eax",))
    assert result["status"] == "refused",result
    assert result["reason"] == "call_return_target_mismatch",result


def test_dag_shared_external_tail_retains_exact_event_count(tmp_path):
    import struct

    from tools.dosunit.tests.test_flat32_external_binding import compare
    from tools.dosunit.tests.test_pe32_import_service import IAT_SLOT

    prefix=_diamonds()[:-1]
    call=b"\xff\x15"+struct.pack("<I",IAT_SLOT)
    result=compare(tmp_path,prefix+call+call+b"\xc3",preserve_iat=True)
    assert result["status"] == "conditional",result
    assumptions=result["external_call_assumptions"]
    assert len(assumptions["oracle_sites"]) == len(assumptions["candidate_sites"]) == 2
    changed=compare(tmp_path,prefix+call+call+b"\xc3",candidate_code=prefix+call+b"\xc3",preserve_iat=True)
    assert changed["status"] == "refused",changed


def test_dag_shared_external_tail_keeps_iat_overwrite_check(tmp_path):
    import struct

    from tools.dosunit.tests.test_flat32_external_binding import compare
    from tools.dosunit.tests.test_pe32_import_service import IAT_SLOT

    prefix=_diamonds()[:-1]
    overwrite=b"\xc7\x05"+struct.pack("<II",IAT_SLOT,0x12345678)
    call=b"\xff\x15"+struct.pack("<I",IAT_SLOT)
    result=compare(tmp_path,prefix+overwrite+call+b"\xc3",preserve_iat=True)
    assert result["status"] == "refused",result
    assert result["reason"] == "external_import_target_not_preserved",result


def test_dag_partition_keeps_original_graph_for_other_proof_owners():
    from tools.dosunit.compare.flat32_call_composition import CallCompositionLimits
    from tools.dosunit.compare.flat32_call_contracts import _ComposeSession, _register_widths
    from tools.dosunit.compare.flat32_call_execution import _compose_root
    from tools.dosunit.compare.flat32_call_lowering import _lift_function
    from tools.dosunit.tests.test_flat32_comparator_lane import _project

    root=_diamonds()[:-1]+bytes.fromhex("e801000000c3")
    leaf=bytes.fromhex("83c001c3")
    with _driver_lane("msc8") as lane, lane.adapter.installed(region=True):
        session=_ComposeSession(project=_project((root+leaf).hex(),BASE),
             functions={BASE:len(root),BASE+len(root):len(leaf)},labels={},
             limits=CallCompositionLimits(),reg_widths=_register_widths())
        blocks=_lift_function(session,BASE)
        original=dict(blocks)
        assert len([b for b in blocks.values() if b.jumpkind=="Ijk_Call"]) == 2
        _compose_root(session,BASE)
        assert session.inlined_calls == 1
        assert all(session.blocks[BASE][key] is value for key,value in original.items())
