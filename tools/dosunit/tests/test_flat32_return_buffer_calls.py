"""Native call integration checks for explicit root-buffer premises."""
import angr
import pytest

from tools.dosunit.compare.flat32_abi_observation import Flat32AbiObservation
from tools.dosunit.compare.flat32_call_composition import compare_functions_with_calls, summarize_with_calls
from tools.dosunit.contracts.flat32_buffer_domain import Flat32StackDisjointBuffer

BASE=0x401000


def compare(left,right,domain,functions=None):
    a,b=bytes.fromhex(left),bytes.fromhex(right)
    return compare_functions_with_calls(
        angr.load_shellcode(a,arch="x86",load_address=BASE),
        angr.load_shellcode(b,arch="x86",load_address=BASE),
        oracle_entry=BASE,candidate_entry=BASE,
        oracle_functions=functions or {BASE:10,BASE+10:7},candidate_functions=functions or {BASE:10,BASE+10:7},
        outputs=("eax",),timeout_ms=10000,abi_observation=domain)


CODE="8b442404 e801000000 c3 c70001000000 c3"


def test_native_same_callee_conditional_with_proven_return():
    domain=Flat32AbiObservation(32,4,(Flat32StackDisjointBuffer(0,4),))
    result=compare(CODE,CODE,domain)
    assert result["status"] == "conditional",result
    assert result["return_targets_proved"] == 2
    for side in ("oracle","candidate"):
        assert result["return_buffer_proofs"][side][0]["skipped_stores"] == 1
    assert result["abi_observation"]["stack_disjoint_buffers"]


def test_public_memory_changes_remain_observable():
    domain=Flat32AbiObservation(32,4,(Flat32StackDisjointBuffer(0,4),))
    result=compare(CODE,CODE.replace("c70001000000","c70002000000"),domain)
    assert result["status"] == "failed",result


@pytest.mark.parametrize("domain",[None,
    Flat32AbiObservation(32,4,(Flat32StackDisjointBuffer(1,4),)),
    Flat32AbiObservation(32,4,(Flat32StackDisjointBuffer(0,2),))])
def test_missing_or_wrong_domain_cannot_pass(domain):
    result=compare(CODE,CODE,domain)
    assert result["status"] == "refused",result


def test_standalone_summary_retains_bound_domain():
    code=bytes.fromhex(CODE)
    summary=summarize_with_calls(angr.load_shellcode(code,arch="x86",load_address=BASE),
        entry=BASE,functions={BASE:10,BASE+10:7},outputs=("eax",),
        root_buffer_domains=((Flat32StackDisjointBuffer(0,4),4),))
    assert summary["root_buffer_domains"][0] in summary["obligations"]
    assert summary["root_bound_retry"] is False
    assert summary["return_buffer_proofs"][0]["status"] == "conditional"


@pytest.mark.parametrize("code,functions",[
    ("8b442404 e806000000 e801000000 c3 c70001000000 c3",{BASE:15,BASE+15:7}),
    ("8b442404 e801000000 c3 e801000000 c3 c70001000000 c3",{BASE:10,BASE+10:6,BASE+16:7}),
])
def test_repeated_and_nested_calls_keep_root_domain(code,functions):
    result=compare(code,code,Flat32AbiObservation(32,8,(Flat32StackDisjointBuffer(0,4),)),functions)
    assert result["status"] == "conditional",result
    assert result["return_targets_proved"] == 4
    for side in ("oracle","candidate"):
        assert len(result["return_buffer_proofs"][side]) == 2
        for proof in result["return_buffer_proofs"][side]:
            assert proof["obligations"][0]["argument_index"] == 0
            assert proof["obligations"][0]["private_stack_bytes"] == 8
