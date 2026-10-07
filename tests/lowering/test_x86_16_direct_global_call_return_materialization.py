from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CExpressionStatement,
    CFunctionCall,
    CStatements,
    CVariable,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.lowering.segmented_global_loads import (
    DirectGlobalCallReturnStoreEvidence8616,
    DirectGlobalSymbolRef8616,
    SegmentedGlobalLoadStats8616,
    materialize_direct_global_symbol_stores_from_evidence_8616,
)
from inertia.lowering.wide_call_return_recombine import (
    DIRECT_CALL_RETURN_STORE_EVIDENCE_TAG_8616,
    _normalized_call_name_8616,
)


class _DummyCodegen:
    def __init__(self) -> None:
        self._idx = 0
        self.cfunc = None
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cstyle_null_cmp = False
        self.max_str_len = None

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def _register(codegen: _DummyCodegen, name: str) -> CVariable:
    offset, size = codegen.project.arch.registers[name]
    return CVariable(SimRegisterVariable(offset, size, name=name), codegen=codegen)


def test_call_return_name_refuses_missing_callee_metadata() -> None:
    codegen = _DummyCodegen()
    call = CFunctionCall(0x5100, None, [], codegen=codegen)

    assert _normalized_call_name_8616(call) is None


def _memory_word(codegen: _DummyCodegen, offset: int, name: str) -> CVariable:
    return CVariable(
        SimMemoryVariable(offset, 2, name=name),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )


def test_dword_call_return_store_consumes_exact_same_group_standalone_call() -> None:
    codegen = _DummyCodegen()
    call = CFunctionCall(
        "worker_tick",
        None,
        [],
        codegen=codegen,
        tags={"ins_addr": 0x5100},
    )
    standalone_call = CExpressionStatement(
        call,
        codegen=codegen,
        tags={"ins_addr": 0x5100},
    )
    low_store = CAssignment(
        _memory_word(codegen, 0x2340, "result"),
        _register(codegen, "ax"),
        codegen=codegen,
        tags={"ins_addr": 0x5103},
    )
    high_store = CAssignment(
        _memory_word(codegen, 0x2342, "result"),
        _register(codegen, "dx"),
        codegen=codegen,
        tags={"ins_addr": 0x5106},
    )
    root = CStatements([standalone_call, low_store, high_store], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x5000, statements=root, body=root)
    evidence = DirectGlobalCallReturnStoreEvidence8616(
        offset=0x2340,
        width=4,
        source_call_name="worker_tick",
        source_call_target=0x6200,
        source_call_ins_addr=0x5100,
        low_store_ins_addr=0x5103,
        high_store_ins_addr=0x5106,
    )
    refs = (
        DirectGlobalSymbolRef8616(0x2340, "result", 0, 2, 2),
        DirectGlobalSymbolRef8616(0x2342, "result", 2, 2, 2),
    )
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_direct_global_symbol_stores_from_evidence_8616(
        codegen,
        refs,
        direct_call_return_stores=(evidence,),
        stats=stats,
    )

    assert changed is True
    assert len(root.statements) == 1
    assignment = root.statements[0]
    assert isinstance(assignment, CAssignment)
    assert assignment.rhs is call
    assert isinstance(assignment.lhs, CVariable)
    assert assignment.lhs.variable.name == "result"
    assert assignment.lhs.variable.size == 4
    assert stats.direct_symbol_call_return_materialized_count == 1


def test_dword_call_return_store_reuses_exact_call_from_separate_group() -> None:
    codegen = _DummyCodegen()
    call = CFunctionCall(
        "read_counter",
        None,
        [],
        codegen=codegen,
        tags={"ins_addr": 0x7100},
    )
    call_group = CStatements(
        [CExpressionStatement(call, codegen=codegen, tags={"ins_addr": 0x7100})],
        codegen=codegen,
    )
    low_store = CAssignment(
        _memory_word(codegen, 0x3450, "counter"),
        _register(codegen, "ax"),
        codegen=codegen,
        tags={"ins_addr": 0x7103},
    )
    high_store = CAssignment(
        _memory_word(codegen, 0x3452, "counter"),
        _register(codegen, "dx"),
        codegen=codegen,
        tags={"ins_addr": 0x7106},
    )
    store_group = CStatements([low_store, high_store], codegen=codegen)
    root = CStatements([call_group, store_group], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x7000, statements=root, body=root)
    evidence = DirectGlobalCallReturnStoreEvidence8616(
        offset=0x3450,
        width=4,
        source_call_name="read_counter",
        source_call_target=0x8200,
        source_call_ins_addr=0x7100,
        low_store_ins_addr=0x7103,
        high_store_ins_addr=0x7106,
    )
    refs = (
        DirectGlobalSymbolRef8616(0x3450, "counter", 0, 2, 2),
        DirectGlobalSymbolRef8616(0x3452, "counter", 2, 2, 2),
    )

    changed = materialize_direct_global_symbol_stores_from_evidence_8616(
        codegen,
        refs,
        direct_call_return_stores=(evidence,),
    )

    assert changed is True
    assert call_group.statements == []
    assert len(store_group.statements) == 1
    assignment = store_group.statements[0]
    assert isinstance(assignment, CAssignment)
    assert assignment.rhs is call

    replayed_call = CFunctionCall(
        "read_counter",
        None,
        [],
        codegen=codegen,
        tags={"ins_addr": 0x7100},
    )
    call_group.statements.append(
        CExpressionStatement(replayed_call, codegen=codegen, tags={"ins_addr": 0x7100})
    )
    replay_stats = SegmentedGlobalLoadStats8616()

    replay_changed = materialize_direct_global_symbol_stores_from_evidence_8616(
        codegen,
        refs,
        direct_call_return_stores=(evidence,),
        stats=replay_stats,
    )

    assert replay_changed is True
    assert call_group.statements == []
    assert store_group.statements == [assignment]
    assert replay_stats.direct_symbol_call_return_carrier_removed_count == 1


def test_synthesized_dword_return_call_keeps_exact_callsite_identity() -> None:
    codegen = _DummyCodegen()
    low_store = CAssignment(
        _memory_word(codegen, 0x4560, "sample"),
        _register(codegen, "ax"),
        codegen=codegen,
        tags={"ins_addr": 0x8103},
    )
    high_store = CAssignment(
        _memory_word(codegen, 0x4562, "sample"),
        _register(codegen, "dx"),
        codegen=codegen,
        tags={"ins_addr": 0x8106},
    )
    root = CStatements([low_store, high_store], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x8000, statements=root, body=root)
    evidence = DirectGlobalCallReturnStoreEvidence8616(
        offset=0x4560,
        width=4,
        source_call_name="sample_counter",
        source_call_target=0x9200,
        source_call_ins_addr=0x8100,
        low_store_ins_addr=0x8103,
        high_store_ins_addr=0x8106,
    )
    refs = (
        DirectGlobalSymbolRef8616(0x4560, "sample", 0, 2, 2),
        DirectGlobalSymbolRef8616(0x4562, "sample", 2, 2, 2),
    )

    changed = materialize_direct_global_symbol_stores_from_evidence_8616(
        codegen,
        refs,
        direct_call_return_stores=(evidence,),
    )

    assert changed is True
    assert len(root.statements) == 1
    assignment = root.statements[0]
    assert isinstance(assignment, CAssignment)
    assert isinstance(assignment.rhs, CFunctionCall)
    assert assignment.rhs.tags["ins_addr"] == 0x8100


def test_tagged_materialized_dword_recombine_folds_to_original_call() -> None:
    codegen = _DummyCodegen()
    evidence = DirectGlobalCallReturnStoreEvidence8616(
        offset=0x5670,
        width=4,
        source_call_name="sample_counter",
        source_call_target=0xA200,
        source_call_ins_addr=0x9100,
        low_store_ins_addr=0x9103,
        high_store_ins_addr=0x9106,
    )
    call = CFunctionCall(
        "sample_counter",
        None,
        [],
        codegen=codegen,
        tags={"ins_addr": evidence.source_call_ins_addr},
    )
    dword = CVariable(SimMemoryVariable(0x5670, 4, name="sample"), codegen=codegen)
    recombine = CBinaryOp(
        "Or",
        call,
        CBinaryOp(
            "Shl",
            _register(codegen, "dx"),
            CConstant(16, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    assignment = CAssignment(
        dword,
        recombine,
        codegen=codegen,
        tags={DIRECT_CALL_RETURN_STORE_EVIDENCE_TAG_8616: evidence},
    )
    root = CStatements([assignment], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x9000, statements=root, body=root)
    refs = (DirectGlobalSymbolRef8616(0x5670, "sample", 0, 4, 4),)
    stats = SegmentedGlobalLoadStats8616()

    changed = materialize_direct_global_symbol_stores_from_evidence_8616(
        codegen,
        refs,
        direct_call_return_stores=(evidence,),
        stats=stats,
    )

    assert changed is True
    assert assignment.rhs is call
    assert stats.direct_symbol_call_return_materialized_count == 1
