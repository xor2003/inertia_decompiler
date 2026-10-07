"""Pure contract and solver-owner compatibility controls."""

import pickle
import subprocess
import sys
from pathlib import Path

import pytest

from tools.dosunit.contracts import LowerFailure, SsaExpr
from tools.dosunit.contracts.scanning import FunctionLoweringPolicy


def test_explicit_cfg_finisher_owns_targets_without_global_installation(monkeypatch):
    from functools import partial

    import archinfo
    import pyvex

    from tools.dosunit.architectures.flat32 import flat32_register_architecture
    from tools.dosunit.architectures.flat32_control import finish_flat32_control
    from tools.dosunit.compare import straightline_ssa as engine

    def forbidden(*args, **kwargs):
        pytest.fail("explicit CFG entered the legacy finisher")

    monkeypatch.setattr(engine, "_finish_irsb_lowering", forbidden)
    registers = engine.REG_BY_OFFSET
    block = pyvex.IRSB(bytes.fromhex("eb00"), 0x500000, archinfo.ArchX86(), opt_level=0)
    for targets, admitted in (({}, False), ({0x500002: 1}, True), ({}, False)):
        result = engine._lower_irsb(
            block, output_regs=("eax", "esp", "eip", "ip", "control_ip"), max_assignments_per_function=4096,
            architecture=flat32_register_architecture(),
            block_finisher=partial(finish_flat32_control, control_targets=targets),
        )
        assert isinstance(result, LowerFailure) is not admitted
        if not admitted:
            assert result.reason == "flat32_indirect_control"
        else:
            for name in ("eip", "ip", "control_ip"):
                assert result["outputs"][name] == {"op": "const", "width": 32, "value": "0x1"}
        assert engine.REG_BY_OFFSET is registers


def test_flat32_leaf_function_owner_preserves_metadata_and_refusal(tmp_path):
    import runpy

    import angr

    from tools.dosunit.architectures.flat32_leaf import lower_flat32_leaf_function
    from tools.dosunit.contracts.model import stable_id

    root = Path(__file__).resolve().parents[3]
    for target in ("bc5", "msc8"):
        adapter = runpy.run_path(str(root / "artifacts" / f"{target}-z3cmp32" / "flat32_adapter.py"))
        assert adapter["lower_function"] is lower_flat32_leaf_function
    binary = tmp_path / "leaf.bin"
    binary.write_bytes(bytes.fromhex("b807000000 c3 e800000000"))
    base = 0x500000
    project = angr.Project(str(binary), auto_load_libs=False, main_opts={
        "backend": "blob", "arch": "x86", "base_addr": base, "entry_point": base,
    })
    for offset, size, success in ((0, 6, True), (6, 5, False)):
        function = {"id": "test:leaf", "names": ["leaf"], "size": size,
                    "entry": {"kind": "module_relative", "offset": hex(offset)}}
        parts, refusals, lifted = lower_flat32_leaf_function(
            project=project, linked_base=base, function=function, output_regs=("eax", "esp"),
            scan_limit=16, max_assignments_per_function=4096,
        )
        assert lifted == 1
        if success:
            assert not refusals
            assert len(parts) == 1
            body = dict(parts[0])
            identifier = body.pop("id")
            assert identifier == stable_id("ssa-function", body)
            assert body["entry"] == {"linear": hex(base)}
            assert body["function"] == {"id": "test:leaf", "name": "leaf"}
        else:
            assert not parts
            assert len(refusals) == 1
            assert refusals[0]["reason"] == "flat32_control_flow"


def test_flat32_leaf_owner_refuses_prefixes_without_installation(monkeypatch):
    import archinfo
    import pyvex

    from tools.dosunit.architectures.flat32_leaf import lower_flat32_leaf_block
    from tools.dosunit.compare import straightline_ssa as engine

    def forbidden(*args, **kwargs):
        pytest.fail("explicit leaf lowering entered the legacy finisher")

    monkeypatch.setattr(engine, "_finish_irsb_lowering", forbidden)
    registers = engine.REG_BY_OFFSET
    for code, reason in (("b807000000 c3", None), ("e800000000", "flat32_control_flow"),
                         ("85c0 7401 c3 c3", "flat32_control_flow")):
        block = pyvex.IRSB(bytes.fromhex(code), 0x500000, archinfo.ArchX86(), opt_level=0)
        result = lower_flat32_leaf_block(block, output_regs=("eax", "esp", "eip"),
                                        max_assignments_per_function=4096)
        if reason is None:
            assert not isinstance(result, LowerFailure), result
            assert set(result["outputs"]) == {"eax", "esp", "eip"}
        else:
            assert isinstance(result, LowerFailure)
            assert result.reason == reason
        assert engine.REG_BY_OFFSET is registers


def test_function_scan_uses_explicit_successor_admission_without_global_patch(tmp_path):
    import angr

    from tools.dosunit.architectures.flat32 import flat32_register_architecture
    from tools.dosunit.compare import straightline_ssa as engine

    binary = tmp_path / "tail.bin"
    binary.write_bytes(bytes.fromhex("e901000000 90 c3"))
    base = 0x500000
    project = angr.Project(str(binary), auto_load_libs=False, main_opts={
        "backend": "blob", "arch": "x86", "base_addr": base, "entry_point": base,
    })
    catalog = {"schema": "dosunit.functions.v1", "module": "test", "functions": [{
        "id": "test:tail", "names": ["tail"], "size": 5,
        "entry": {"kind": "module_relative", "offset": "0x0"},
    }]}
    admission = engine._can_add_dynamic_successor_range
    for admitted, expected_parts in ((False, 1), (True, 2), (False, 1)):
        observed = []

        def admit(*, project, function_base, successor, observed=observed,
                  admitted=admitted, original_project=project):
            assert project is original_project
            observed.append(successor)
            return admitted

        document = engine.lower_straightline_ssa_document(
            exe_path=binary, functions_catalog=catalog, lifter_project=project,
            architecture=flat32_register_architecture(), output_regs=("eax", "esp"),
            scan_limit=16, successor_range_admission=admit,
        )
        assert not document["refusals"], document["refusals"]
        assert len(document["functions"]) == expected_parts
        assert base + 6 in observed
        assert engine._can_add_dynamic_successor_range is admission


@pytest.mark.parametrize("policy", list(FunctionLoweringPolicy))
def test_explicit_architecture_bypasses_legacy_function_and_finisher_patches(tmp_path, monkeypatch, policy):
    import angr

    from tools.dosunit.architectures.flat32 import flat32_register_architecture
    from tools.dosunit.compare import straightline_ssa as engine

    binary = tmp_path / "explicit.bin"
    binary.write_bytes(bytes.fromhex("b807000000 c3"))
    project = angr.Project(str(binary), auto_load_libs=False, main_opts={
        "backend": "blob", "arch": "x86", "base_addr": 0x500000, "entry_point": 0x500000,
    })
    catalog = {"schema": "dosunit.functions.v1", "module": "test", "functions": [{
        "id": "test:f", "names": ["f"], "size": 6,
        "entry": {"kind": "module_relative", "offset": "0x0"},
    }]}

    def legacy_patch(*args, **kwargs):
        pytest.fail("explicit architecture entered a patched legacy lowering callback")

    monkeypatch.setattr(engine, "_lower_function", legacy_patch)
    monkeypatch.setattr(engine, "_finish_irsb_lowering", legacy_patch)
    document = engine.lower_straightline_ssa_document(
        exe_path=binary, functions_catalog=catalog, lifter_project=project,
        architecture=flat32_register_architecture(), output_regs=("eax", "esp"),
        function_lowering_policy=policy,
    )
    assert not document["refusals"]
    assert len(document["functions"]) == 1
    from copy import deepcopy

    for value, status in ((7, "passed"), (8, "failed")):
        expected = deepcopy(document["functions"][0])
        expected["outputs"]["eax"] = {"op": "const", "width": 32, "value": value}
        result = engine._compare_functions(document["functions"][0], expected, timeout_ms=1000)
        assert result["status"] == status


def test_contract_and_operator_imports_do_not_load_the_engine():
    script = """
import sys
sys.path.insert(0, sys.argv[1])
from tools.dosunit.contracts import SsaExpr, LowerFailure
from tools.dosunit.ssa.z3_ops import apply_operator
from tools.dosunit.ssa.translation import TranslationContext
from tools.dosunit.ssa.composition import compose_block_outputs
from tools.dosunit.ssa.materialization import materialize_term
from tools.dosunit.contracts.comparison import EXPLICIT_COMPARISON_POLICY
from tools.dosunit.ssa.identity import quick_compare
from tools.dosunit.contracts.scanning import SuccessorRangeAdmission
assert 'tools.dosunit.compare.straightline_ssa' not in sys.modules
assert not {'angr', 'pyvex', 'z3'}.intersection(sys.modules)
assert SsaExpr('const', 16, value=7).key() == ('const', 16, 7, None, ())
"""
    subprocess.run([sys.executable, "-I", "-c", script, str(Path(__file__).resolve().parents[3])],
                   check=True, capture_output=True, text=True, timeout=20)


def test_legacy_contracts_share_identity_and_pickle_lookup():
    from tools.dosunit.compare import straightline_ssa as legacy
    from tools.dosunit.ssa import z3_ops

    assert legacy.SsaExpr is SsaExpr
    assert legacy.LowerFailure is LowerFailure
    assert legacy._z3_apply is z3_ops.apply_operator
    assert legacy._z3_load is z3_ops._z3_load
    assert pickle.loads(b"ctools.dosunit.straightline_ssa\nSsaExpr\n.") is SsaExpr
    assert pickle.loads(b"ctools.dosunit.straightline_ssa\nLowerFailure\n.") is LowerFailure
    term = SsaExpr("add", 32, (SsaExpr("input", 32, name="eax"), SsaExpr("const", 32, value=1)))
    assert pickle.loads(pickle.dumps(term)) == term
    assert term.key() == ("add", 32, None, None, (("input", 32, None, "eax", ()), ("const", 32, 1, None, ())))


def test_legacy_flat32_architecture_is_the_canonical_module():
    import tools.dosunit.architectures.flat32 as legacy
    from tools.dosunit.architectures import flat32

    assert legacy is flat32
    assert legacy._flat32_read_register is flat32._flat32_read_register
    assert legacy.flat32_register_architecture is flat32.flat32_register_architecture
    assert pickle.loads(b"ctools.dosunit.flat32_lifting\nflat32_register_architecture\n.") is flat32.flat32_register_architecture
    architecture = flat32.flat32_register_architecture()
    restored = pickle.loads(pickle.dumps(architecture))
    assert restored == architecture
    assert restored.reader is architecture.reader


def test_composition_and_materialization_legacy_identity():
    from tools.dosunit.compare import straightline_ssa as engine
    from tools.dosunit.ssa import composition, materialization

    assert engine._compose_block_outputs is composition.compose_block_outputs
    assert engine._materialize_json_term is materialization.materialize_term
    assert engine._TermInputScan is materialization._TermInputScan
    assert pickle.loads(b"ctools.dosunit.straightline_ssa\n_TermInputScan\n.") is materialization._TermInputScan


def test_composition_retains_exact_named_arrays_and_deadline_refusal():
    from tools.dosunit.ssa.composition import compose_block_outputs

    memory = {"op": "mem_input", "name": "original_memory"}
    io = {"op": "mem_input", "name": "original_io"}
    outputs = {"memory": {"op": "mem_input", "name": "mem"},
               "io": {"op": "mem_input", "name": "io"},
               "other": {"op": "mem_input", "name": "unbound"}}
    composed = compose_block_outputs({}, outputs, {"memory": memory, "io": io})
    assert composed["memory"] is memory
    assert composed["io"] is io
    assert composed["other"] == outputs["other"]
    with pytest.raises(LowerFailure) as failed:
        compose_block_outputs({}, outputs, {}, compose_stats={"deadline": -1.0})
    assert failed.value.reason == "compose_budget_exceeded"
    with pytest.raises(LowerFailure) as missing:
        compose_block_outputs({}, {"eax": {"ref": "missing"}}, {})
    assert missing.value.reason == "unsupported_ir"


@pytest.mark.parametrize("width", [16, 32])
def test_composed_shared_assignment_roundtrip_keeps_scalar_effect(width):
    import z3

    from tools.dosunit.ssa.composition import compose_block_outputs
    from tools.dosunit.ssa.materialization import input_items, materialize_term
    from tools.dosunit.ssa.translation import TranslationContext

    scalar = {"op": "input", "name": "value", "width": width}
    block = {"assignments": [{"id": "sum", "op": "add", "width": width,
                              "args": [scalar, {"op": "const", "value": 1, "width": width}]}]}
    state = compose_block_outputs(block, {"left": {"ref": "sum"}, "right": {"ref": "sum"}},
                                  {"value": {"op": "input", "name": "incoming", "width": width}})
    assert state["left"] is state["right"]
    assignments = []
    output = materialize_term(state["left"], assignments=assignments, memo={})
    assert input_items([output], assignments) == [{"name": "incoming", "width": width}]
    incoming = z3.BitVec("incoming", width)
    context = TranslationContext({}, {"incoming": (incoming, width)},
                                 {item["id"]: item for item in assignments}, {}, z3,
                                 lambda value, **kwargs: value)
    result = context.term(output)
    solver = z3.Solver()
    solver.add(result != incoming + 1)
    assert solver.check() == z3.unsat
    solver = z3.Solver()
    solver.add(result != incoming + 2)
    assert solver.check() == z3.sat


@pytest.mark.parametrize("width", [16, 32])
@pytest.mark.parametrize("little_endian", [True, False])
def test_byte_memory_effects_and_corrupted_store(width, little_endian):
    import z3

    from tools.dosunit.ssa.z3_ops import apply_operator

    memory = z3.Array("contract_memory", z3.BitVecSort(32), z3.BitVecSort(8))
    address = z3.BitVecVal(0x1234, width)
    value = z3.BitVec("contract_value", width)
    store = "storele" if little_endian else "storebe"
    load = "loadle" if little_endian else "loadbe"
    written = apply_operator(store, 0, [memory, address, value], z3)
    read = apply_operator(load, width, [written, address], z3)
    solver = z3.Solver()
    solver.add(read != value)
    assert solver.check() == z3.unsat
    corrupted = apply_operator(store, 0, [memory, address, value ^ z3.BitVecVal(1, width)], z3)
    bad_read = apply_operator(load, width, [corrupted, address], z3)
    solver = z3.Solver()
    solver.add(bad_read != value)
    assert solver.check() == z3.sat


def test_translation_contexts_keep_output_normalization_and_caches_separate():
    import z3

    from tools.dosunit.ssa.translation import TranslationContext

    def normalize(value, *, width, document, output_name=None):
        return document["relocation"] if output_name == "ip" else value

    assignments = {"target": {"op": "add", "width": 32, "args": [
        {"op": "const", "width": 32, "value": "0x1000"},
        {"op": "const", "width": 32, "value": "0x0"},
    ]}}
    control = TranslationContext({"relocation": 7}, {}, assignments, {}, z3, normalize, "ip")
    data = TranslationContext({"relocation": 99}, {}, assignments, {}, z3, normalize, "eax")
    assert z3.simplify(control.assignment("target")).as_long() == 14
    assert z3.simplify(data.assignment("target")).as_long() == 0x1000
    assert control.assignment("target") is control.cache["target"]
    assert data.assignment("target") is data.cache["target"]
    assert control.cache is not data.cache


def test_flat32_nested_expression_reads_do_not_install_global_register_state():
    import archinfo
    import pyvex

    from tools.dosunit.architectures.flat32 import _flat32_lower_expr
    from tools.dosunit.compare import straightline_ssa as engine

    original_map = engine.REG_BY_OFFSET
    original_reader = engine._read_register
    expr = pyvex.expr.Binop("Iop_Add32", [
        pyvex.expr.Get(8, "Ity_I32"),
        pyvex.expr.Unop("Iop_16Uto32", [pyvex.expr.Get(12, "Ity_I16")]),
    ])
    lowered = _flat32_lower_expr(expr, temp_defs={}, temp_failures={},
                                reg_versions={}, tyenv=pyvex.IRTypeEnv(archinfo.ArchX86()),
                                memory=SsaExpr("mem_input", 0, name="mem"))
    assert isinstance(lowered, SsaExpr)
    assert lowered.args[0] == SsaExpr("input", 32, name="eax")
    assert lowered.args[1].args[0].args[0] == SsaExpr("input", 32, name="ecx")
    assert engine.REG_BY_OFFSET is original_map
    assert engine._read_register is original_reader


def test_explicit_flat32_block_preserves_partial_write_and_return_state():
    import archinfo
    import pyvex

    from tools.dosunit.architectures.flat32 import flat32_register_architecture
    from tools.dosunit.compare import straightline_ssa as engine

    original_map = engine.REG_BY_OFFSET
    block = pyvex.IRSB(bytes.fromhex("b001c3"), 0x1000, archinfo.ArchX86(), opt_level=0)
    lowered = engine._lower_irsb(block, output_regs=("eax", "esp", "eip"),
                               max_assignments_per_function=100,
                               architecture=flat32_register_architecture())
    assert isinstance(lowered, dict)
    assert {"eax", "esp", "eip"} <= lowered["outputs"].keys()
    inputs = {item["name"]: item for item in lowered["inputs"]}
    assert inputs["eax"]["width"] == 32
    assert inputs["esp"]["width"] == 32
    assert engine.REG_BY_OFFSET is original_map
    import z3

    symbolic_inputs = engine._z3_inputs(lowered, lowered, z3)
    eax = engine._z3_term(lowered["outputs"]["eax"], document=lowered, inputs=symbolic_inputs, z3=z3)
    esp = engine._z3_term(lowered["outputs"]["esp"], document=lowered, inputs=symbolic_inputs, z3=z3)
    expected_eax = (symbolic_inputs["eax"][0] & 0xffffff00) | 1
    solver = z3.Solver()
    solver.add(z3.Or(eax != expected_eax, esp != symbolic_inputs["esp"][0] + 4))
    assert solver.check() == z3.unsat
    solver = z3.Solver()
    solver.add(eax != 1)
    assert solver.check() == z3.sat


def test_explicit_flat32_conditional_control_projections_agree():
    import archinfo
    import pyvex

    from tools.dosunit.architectures.flat32 import flat32_register_architecture
    from tools.dosunit.compare import straightline_ssa as engine

    block = pyvex.IRSB(bytes.fromhex("7502b001c3"), 0x1000, archinfo.ArchX86(), opt_level=0)
    lowered = engine._lower_irsb(block, output_regs=("eip", "ip", "control_ip"),
                               max_assignments_per_function=100,
                               architecture=flat32_register_architecture())
    assert isinstance(lowered, dict)
    assert lowered["outputs"]["eip"] == lowered["outputs"]["ip"] == lowered["outputs"]["control_ip"]
    assert any(item["op"] == "ite" and item["width"] == 32 for item in lowered["assignments"])


def test_explicit_flat32_function_scan_retains_complete_branch_state(tmp_path):
    import angr

    from tools.dosunit.architectures.flat32 import flat32_register_architecture
    from tools.dosunit.compare import straightline_ssa as engine
    from tools.dosunit.contracts.ssa_lowering_scope import SuccessorRangePolicy

    code = bytes.fromhex("85c07406b801000000c3b802000000c3")
    project = angr.load_shellcode(code, arch="x86", load_address=0x400000)
    original_map = engine.REG_BY_OFFSET
    parts, refusals, lifted = engine._lower_function(
        project=project, linked_base=0x400000, exe_path=tmp_path / "scan.bin",
        exe_digest="test", cache_document=None, cache_stats={},
        function={"id": "scan", "names": ["scan"], "size": len(code),
                  "entry": {"kind": "module_relative", "offset": "0x0"}},
        segment_paragraphs={}, output_regs=("eax", "esp", "eip"), source_ir="vex",
        max_blocks_per_function=8, max_insns_per_function=32, max_assignments_per_function=256,
        scan_limit=256, follow_call_fallthrough=False, max_lift_block_ms=0,
        successor_range_policy=SuccessorRangePolicy.DECLARED_ONLY,
        architecture=flat32_register_architecture(),
    )
    assert not refusals
    assert lifted == len(parts) == 3
    branch = parts[0]
    assert {"eax", "ecx", "esp", "eip", "cc_op", "cc_dep1"} <= branch["outputs"].keys()
    assert all(int(part["entry"]["linear"], 16) >= 0x400000 for part in parts)
    assert engine.REG_BY_OFFSET is original_map
