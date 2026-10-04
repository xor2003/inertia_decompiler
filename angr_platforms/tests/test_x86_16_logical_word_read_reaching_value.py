"""Binary-backed reaching-value proofs for logical word reads."""

from __future__ import annotations

import io
from dataclasses import replace
from types import SimpleNamespace

import angr
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.ir.logical_memory_contracts import (
    IRLogicalMemoryAccess8616,
    IRMemoryAccessKind8616,
)
from angr_platforms.X86_16.ir.logical_memory_write_value import (
    LogicalWordWriteValueFailureKind8616,
    LogicalWordWriteValueRefusal8616,
    trace_logical_word_write_values_8616,
)
from angr_platforms.X86_16.ir.logical_word_read_reaching_value import (
    LogicalWordReadValueFailureKind8616,
    trace_logical_word_read_values_8616,
)
from angr_platforms.X86_16.ir.ssa_function import SSAFunctionArtifact, build_x86_16_function_ssa
from angr_platforms.X86_16.ir.vex_import import build_x86_16_ir_function_artifact
from angr_platforms.X86_16.lift_86_16 import Lifter86_16  # noqa: F401


def _branching_far_callback_ssa() -> SSAFunctionArtifact:
    """Lift two binary callback assignments into one exact four-block CFG."""
    code = bytes.fromhex(
        "55 8b ec 83 ec 04 83 f8 00 74 0c "
        "c7 46 fc 00 00 c7 46 fe 00 10 eb 0c "
        "c7 46 fc 1a 00 c7 46 fe 00 10 eb 00 "
        "ff 76 08 ff 76 fe ff 76 fc "
        "9a 34 00 00 10 83 c4 06 8b e5 5d cb"
    )
    project = angr.Project(
        io.BytesIO(code),
        main_opts={"backend": "blob", "arch": Arch86_16(), "base_addr": 0x1000, "entry_point": 0x1000},
        auto_load_libs=False,
    )
    function = SimpleNamespace(
        addr=0x1000,
        block_addrs_set={0x1000, 0x100B, 0x1017, 0x1023},
        graph=SimpleNamespace(edges=((0x1000, 0x100B), (0x1000, 0x1017),
                                     (0x100B, 0x1023), (0x1017, 0x1023))),
        info={},
    )
    source = build_x86_16_ir_function_artifact(project, function)
    assert not source.refusals
    return build_x86_16_function_ssa(source)


def _local_load(ssa: SSAFunctionArtifact, offset: int) -> IRLogicalMemoryAccess8616:
    """Select the call setup's exact BP-relative word LOAD."""
    assert ssa.logical_memory is not None
    matches = tuple(
        access for access in ssa.logical_memory.accesses
        if access.kind is IRMemoryAccessKind8616.READ
        and access.address.base == ("bp",)
        and access.address.offset == offset
        and access.address.size == 2
        and access.key.block_addr == 0x1023
    )
    assert len(matches) == 1
    return matches[0]


def test_branching_far_callback_words_reach_call_by_same_predecessors() -> None:
    """Both callback words must retain path-correlated immediate writes."""
    ssa = _branching_far_callback_ssa()
    writes = trace_logical_word_write_values_8616(ssa)
    assert writes.closed
    assert len(ssa.memory_phi_nodes) >= 4

    low = trace_logical_word_read_values_8616(ssa, writes, _local_load(ssa, -4))
    high = trace_logical_word_read_values_8616(ssa, writes, _local_load(ssa, -2))

    assert low.closed and high.closed
    assert low.fact is not None and high.fact is not None
    assert tuple((item.source_block_addr, item.constant) for item in low.fact.incoming) == (
        (0x100B, 0), (0x1017, 0x1A),
    )
    assert tuple((item.source_block_addr, item.constant) for item in high.fact.incoming) == (
        (0x100B, 0x1000), (0x1017, 0x1000),
    )
    corrupt = replace(low.fact.incoming[0], constant=0xFFFF)
    assert not replace(low.fact, incoming=(corrupt, *low.fact.incoming[1:])).complete
    assert not replace(low.fact, incoming=low.fact.incoming[:1]).complete


def test_reaching_word_refuses_unclosed_write_proof() -> None:
    """A missing branch writer cannot be interpreted as a proven value."""
    ssa = _branching_far_callback_ssa()
    writes = trace_logical_word_write_values_8616(ssa)
    incomplete = replace(writes, facts=writes.facts[:-1])

    result = trace_logical_word_read_values_8616(ssa, incomplete, _local_load(ssa, -4))

    assert result.closed
    assert result.fact is None
    assert result.refusal is not None
    assert result.refusal.failure is LogicalWordReadValueFailureKind8616.WRITE_FACTS_OPEN
    assert result.stats.raw_fact_count == result.stats.failure_count == 1


def test_reaching_word_refuses_missing_one_branch_write_value() -> None:
    """A closed write census can still lack a constant for one required path."""
    ssa = _branching_far_callback_ssa()
    writes = trace_logical_word_write_values_8616(ssa)
    missing = next(
        fact for fact in writes.facts
        if fact.access.key.block_addr == 0x1017 and fact.access.address.offset == -4
    )
    partial = replace(
        writes,
        facts=tuple(fact for fact in writes.facts if fact != missing),
        refusals=(*writes.refusals, LogicalWordWriteValueRefusal8616(
            missing.access, LogicalWordWriteValueFailureKind8616.DEFINITION_MISSING,
        )),
        stats=replace(writes.stats, materialized_count=writes.stats.materialized_count - 1,
                      failure_count=writes.stats.failure_count + 1),
    )
    assert partial.closed

    result = trace_logical_word_read_values_8616(ssa, partial, _local_load(ssa, -4))

    assert result.closed and result.fact is None
    assert result.refusal is not None
    assert result.refusal.failure is LogicalWordReadValueFailureKind8616.SOURCE_MISSING


def test_reaching_word_refuses_incomplete_phi_predecessor_census() -> None:
    """A phi missing one CFG predecessor must not publish a path value."""
    ssa = _branching_far_callback_ssa()
    writes = trace_logical_word_write_values_8616(ssa)
    target = next(phi for phi in ssa.memory_phi_nodes if phi.target.offset == -4)
    broken = replace(target, incoming=target.incoming[:1])
    changed = replace(ssa, memory_phi_nodes=tuple(
        broken if phi is target else phi for phi in ssa.memory_phi_nodes
    ))

    result = trace_logical_word_read_values_8616(changed, writes, _local_load(changed, -4))

    assert result.closed and result.fact is None
    assert result.refusal is not None
    assert result.refusal.failure is LogicalWordReadValueFailureKind8616.PHI_PREDECESSOR_CONFLICT
