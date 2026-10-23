"""Positive/negative controls for private conditional return-read reduction."""
import copy

import pytest
import z3

from tools.dosunit.compare.flat32_return_footprint import reduce_return_read
from tools.dosunit.contracts.flat32_buffer_domain import Flat32StackDisjointBuffer


def c(n):
    return {"op": "const", "width": 32, "value": hex(n & 0xffffffff)}


def add(a, n):
    return {"op": "add", "width": 32, "args": [a, c(n)]}


def fixture(write_offset=0, write_width=80, read_offset=0):
    domain = Flat32StackDisjointBuffer(1, 12)
    obligation = domain.obligation(20)
    pointer, frame = obligation["predicate"]["args"][0]["args"][0]["args"]
    memory = {"op": "mem_input", "name": "mem", "addr_width": 32, "value_width": 8}
    stored = {"op": "storele", "width": 0, "args": [memory, add(pointer, write_offset),
                  {"op": "input", "width": write_width, "name": "opaque_fpu_result"}]}
    read = {"op": "loadle", "width": 32, "args": [stored, add(frame, read_offset)]}
    return domain, read


@pytest.mark.parametrize("write_offset,width,read_offset,expected", [
    (0,80,0,1), (2,80,16,1), (10,16,0,1),
    (-1,80,0,0), (3,80,0,0), (0,104,0,0),
    (0,80,-1,0), (0,80,17,0), (0,0,0,0), (0,79,0,0),
])
def test_containment_and_no_mutation(write_offset,width,read_offset,expected):
    domain, term = fixture(write_offset,width,read_offset)
    original = copy.deepcopy(term)
    result = reduce_return_read(term, domain, 20)
    assert result.skipped_stores == expected
    assert len(result.obligations) == expected
    assert term == original


@pytest.mark.parametrize("index,depth", [(0,20),(1,16),(2,20)])
def test_wrong_root_domain(index,depth):
    _, term = fixture()
    assert reduce_return_read(term, Flat32StackDisjointBuffer(index,12), depth).skipped_stores == 0


@pytest.mark.parametrize("depth,size,ro,wo,width", [
    (20,12,0,0,10), (20,12,16,2,10), (20,12,0,10,2),
    (8192,65536,8188,65526,10), (4,1,0,0,1),
])
def test_universal_circular_disjointness(depth,size,ro,wo,width):
    # Translation by frame start is bijective on 32-bit addresses. This
    # includes every wrapping frame/buffer configuration, not just samples.
    delta = z3.BitVec("buffer_minus_frame",32)
    guard = z3.And(z3.UGE(delta,depth),z3.UGE(-delta,size))
    solver = z3.Solver()
    solver.set(timeout=1000)
    solver.add(guard)
    assert solver.check() == z3.sat
    overlap = z3.Or(*[delta == ((ro+i-wo-j)&0xffffffff)
                     for i in range(4) for j in range(width)])
    solver.add(overlap)
    assert solver.check() == z3.unsat


def test_unknown_store_blocks_reduction():
    domain, term = fixture()
    term["args"][0]["args"][1] = {"op": "input","width": 32,"name": "unknown_address"}
    assert reduce_return_read(term,domain,20).skipped_stores == 0


@pytest.mark.parametrize("stack_offset,expected", [(-4,1),(-16,1),(8,0),(9,0),(5,0)])
def test_argument_load_after_stack_writes(stack_offset,expected):
    domain, term=fixture()
    store=term["args"][0]
    pointer=store["args"][1]["args"][0]
    esp={"op": "input","name": "esp","width": 32}
    memory=pointer["args"][0]
    pushed={"op": "storele","width": 0,"args": [memory,add(esp,stack_offset),c(123)]}
    # EBP=entryESP-4, [EBP+12] is the original argument1 slot.
    pointer["args"]=[pushed,add(add(esp,-4),12)]
    assert reduce_return_read(term,domain,20).skipped_stores == expected


@pytest.mark.parametrize("unknown_other_branch", [False,True])
def test_conditional_memory_keeps_unknown_effects(unknown_other_branch):
    domain,term=fixture()
    stored,address=term["args"]
    other=stored["args"][0]
    if unknown_other_branch:
        other={"op": "storele","width": 0,"args": [other,address,c(0xdeadbeef)]}
    condition={"op": "input","width": 1,"name": "masked_exception"}
    term["args"]=[{"op": "ite","width": 0,"args": [condition,stored,other]},address]
    result=reduce_return_read(term,domain,20)
    assert result.skipped_stores == 1
    if unknown_other_branch:
        assert result.term["op"] == "ite"
        assert result.term["args"][2] == c(0xdeadbeef)
    else:
        assert result.term == {"op": "loadle","width": 32,"args": [other,address]}


@pytest.mark.parametrize("offset,width,expected",[(0,32,True),(1,32,False),(0,16,False),(0,64,False)])
def test_return_forwarding_requires_exact_address_and_width(offset,width,expected):
    domain,term=fixture()
    store,address=term["args"]
    value={"op": "input","name": "return_value","width": width}
    pushed={"op": "storele","width": 0,"args": [store["args"][0],add(address,offset),value]}
    store["args"][0]=pushed
    result=reduce_return_read(term,domain,20)
    assert result.skipped_stores == 1
    assert (result.term == value) is expected


@pytest.mark.parametrize("offset,width,endian", [(8,32,"le"),(-4,32,"le"),(3,8,"le"),(0,32,"be"),(0,16,"le")])
def test_literal_read_reduction_preserves_alias_and_endian(offset,width,endian):
    import time

    from tools.dosunit.compare import straightline_ssa as S
    from tools.dosunit.ssa.literal_read_reduction import reduce_literal_reads
    from tools.dosunit.ssa.materialization import input_items, materialize_term

    pointer={"op":"input","name":"esp","width":32}
    memory={"op":"mem_input","name":"mem","addr_width":32,"value_width":8}
    first={"op":"storele","width":0,"args":[memory,pointer,c(0x12345678)]}
    changed={"op":"store"+endian,"width":0,"args":[first,add(pointer,offset),
             {"op":"const","width":width,"value":"0xab"}]}
    read={"op":"loadle","width":32,"args":[changed,pointer]}
    assignments=[]
    root=materialize_term(read,assignments=assignments,memo={})
    original={"outputs":{"eip":root},"assignments":assignments,"inputs":input_items([root],assignments)}
    reduced=reduce_literal_reads(original,[],deadline=time.monotonic()+1)
    assert S._compare_functions(original,reduced,timeout_ms=1000)["status"]=="passed"
    expected={"outputs":{"eip":c(0x12345678)},"assignments":[],"inputs":[]}
    status=S._compare_functions(reduced,expected,timeout_ms=1000)["status"]
    assert status == ("passed" if offset in (8,-4) else "failed")


@pytest.mark.parametrize("declared", [False,True])
def test_literal_read_reduction_global_stack_separation(declared):
    import time

    from tools.dosunit.compare import straightline_ssa as S
    from tools.dosunit.ssa.literal_read_reduction import reduce_literal_reads
    from tools.dosunit.ssa.materialization import input_items, materialize_term

    pointer={"op":"input","name":"esp","width":32}
    memory={"op":"mem_input","name":"mem","addr_width":32,"value_width":8}
    address=add(pointer,-16)
    saved={"op":"storele","width":0,"args":[memory,address,c(0x12345678)]}
    changed={"op":"storele","width":0,"args":[saved,c(0x27b80),c(23)]}
    assignments=[]
    root=materialize_term({"op":"loadle","width":32,"args":[changed,address]},assignments=assignments,memo={})
    original={"outputs":{"eip":root},"assignments":assignments,"inputs":input_items([root],assignments)}
    constraints=[{"name":"esp","kind":"unsigned_range","min":0x7f000,"max":0x80000}] if declared else []
    reduced=reduce_literal_reads(original,constraints,deadline=time.monotonic()+1)
    assert S._compare_functions(original,reduced,timeout_ms=1000,input_constraints=constraints)["status"]=="passed"
    expected={"outputs":{"eip":c(0x12345678)},"assignments":[],"inputs":[]}
    assert S._compare_functions(reduced,expected,timeout_ms=1000,input_constraints=constraints)["status"] == ("passed" if declared else "failed")
    assert bool(reduced["literal_read_reduction"]["forwarded"]) == declared
    assert reduce_literal_reads(original,constraints,deadline=0) is original
