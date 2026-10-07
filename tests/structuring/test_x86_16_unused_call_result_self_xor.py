"""Regression tests for unused call-result self-XOR ownership."""

from types import SimpleNamespace

import archinfo
from angr.analyses.decompiler.structured_codegen import c as structured_c
from inertia.semantics.callsite_summary import CallsiteSummary8616

from inertia.structuring.unused_call_result_self_xor import (
    UnusedCallResultSelfXorVerdict8616,
    materialize_unused_call_result_self_xor_8616,
)


class _Codegen:
    """Minimal third-party codegen surface used by structured C nodes."""

    def __init__(self) -> None:
        """Initialize the node-identity and architecture boundary."""
        self.project = SimpleNamespace(arch=archinfo.ArchX86())
        self.cstyle_null_cmp = False
        self._next_idx = 0

    def next_idx(self, _name: str) -> int:
        """Return one unique structured-node index."""
        self._next_idx += 1
        return self._next_idx

    def next_node_idx(self) -> int:
        """Return one unique anonymous structured-node index."""
        return self.next_idx("")

    def next_ident(self, name: str) -> str:
        """Return a stable display identifier for one node class."""
        return name


def _summary() -> CallsiteSummary8616:
    """Build one exact unused-return callsite summary."""
    return CallsiteSummary8616(
        callsite_addr=0x1040,
        target_addr=0x2100,
        return_addr=0x1043,
        kind="near",
        arg_count=0,
        arg_widths=(),
        stack_cleanup=0,
        return_register="ax",
        return_used=False,
    )


def test_retains_one_call_effect_and_replaces_shared_self_xor_projection() -> None:
    """A duplicated value projection must not duplicate an unused machine call."""
    codegen = _Codegen()
    call = structured_c.CFunctionCall(
        "side_effect",
        None,
        [],
        tags={"ins_addr": 0x1040},
        codegen=codegen,
    )
    retained = structured_c.CExpressionStatement(call, codegen=codegen)
    xor = structured_c.CBinaryOp(
        "Xor",
        call,
        call,
        codegen=codegen,
    )
    sink = structured_c.CExpressionStatement(
        structured_c.CFunctionCall("sink", None, [xor], codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        statements=structured_c.CStatements([retained, sink], codegen=codegen)
    )
    summary = _summary()
    codegen._inertia_callsite_summaries = {id(call): summary}
    codegen._inertia_callsite_summary_inventory_8616 = {summary.callsite_addr: summary}

    result = materialize_unused_call_result_self_xor_8616(codegen)

    assert result.verdict is UnusedCallResultSelfXorVerdict8616.MATERIALIZED
    assert result.stats.raw_fact_count == 1
    assert result.stats.normalized_fact_count == 1
    assert result.stats.classified_fact_count == 1
    assert result.stats.materialized_count == 1
    assert result.stats.failure_count == 0
    assert codegen.cfunc.statements.statements[0] is retained
    assert isinstance(sink.expr.args[0], structured_c.CConstant)
    assert sink.expr.args[0].value == 0


def test_refuses_self_xor_without_unique_retained_call_effect() -> None:
    """A nested call projection alone must remain when its effect has no owner."""
    codegen = _Codegen()
    call = structured_c.CFunctionCall(
        "side_effect",
        None,
        [],
        tags={"ins_addr": 0x1040},
        codegen=codegen,
    )
    xor = structured_c.CBinaryOp("Xor", call, call, codegen=codegen)
    sink = structured_c.CExpressionStatement(
        structured_c.CFunctionCall("sink", None, [xor], codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        statements=structured_c.CStatements([sink], codegen=codegen)
    )
    summary = _summary()
    codegen._inertia_callsite_summaries = {id(call): summary}
    codegen._inertia_callsite_summary_inventory_8616 = {summary.callsite_addr: summary}

    result = materialize_unused_call_result_self_xor_8616(codegen)

    assert result.verdict is UnusedCallResultSelfXorVerdict8616.UNKNOWN_REFUSE
    assert result.stats.failure_count == 1
    assert sink.expr.args[0] is xor
