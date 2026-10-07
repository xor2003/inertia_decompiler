"""Keep compound register sources from replaying changed memory."""

import pytest

from inertia.alias.register_reaching_source import (
    RegisterBlockTransfer8616,
    RegisterBlockTransferKind8616,
    RegisterReachingSourceVerdict8616,
    callsite_source_reads_memory_8616,
    resolve_register_reaching_source_8616,
)


@pytest.mark.parametrize("source,reads_memory", [
    (("bp", -2, 2), True),
    (("expr", ("bp", -2, 2), (("add", 1),)), True),
    (("expr", ("imm", 1), (("add_source", ("bp", -2, 2)),)), True),
    (("expr", ("imm", 1), (("adc_source", ("global", 0x200, 2)),)), True),
    (("expr", ("imm", 1), (("sub_source", ("global_index", 0x200, "si", 2)),)), True),
    (("expr", ("imm", 1), (("sbb_source", ("seg_indirect", "ds", "si", 0, 2)),)), True),
    (("expr", ("imm", 1), (("add_source", (
        "expr", ("imm", 2), (("sub_source", ("bp", -4, 2)),),
    )),)), True),
    (("imm", 7), False),
    (("bp_addr", -8), False),
    (("expr", ("bp_addr", -8), (("add", 2),)), False),
    (("expr", ("imm", 1), (("add_source", ("imm", 2)),)), False),
])
@pytest.mark.parametrize("clobbers_memory", [False, True])
def test_reaching_source_tracks_memory_in_compound_operands(source, reads_memory, clobbers_memory):
    assert callsite_source_reads_memory_8616(source) is reads_memory
    result = resolve_register_reaching_source_8616(
        (
            RegisterBlockTransfer8616(0x1000, (), RegisterBlockTransferKind8616.REPLACE, source),
            RegisterBlockTransfer8616(
                0x1010, (0x1000,), RegisterBlockTransferKind8616.PRESERVE,
                clobbers_memory_sources=clobbers_memory,
            ),
        ),
        entry_addr=0x1000,
        sink_addr=0x1010,
    )
    if reads_memory and clobbers_memory:
        assert result.verdict is RegisterReachingSourceVerdict8616.UNKNOWN_REFUSE
        assert result.source is None
        assert result.materialized_count == 0
        assert result.failure_count == 1
    else:
        assert result.verdict is RegisterReachingSourceVerdict8616.PROVEN
        assert result.source == source
        assert result.classified_fact_count == result.materialized_count == 1
        assert result.failure_count == 0
