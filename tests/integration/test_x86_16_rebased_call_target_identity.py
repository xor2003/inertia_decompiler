from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import CFunctionCall, CStatements
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.semantics.callsite_summary import CallsiteSummary8616
from inertia.lowering.callsite_prototype_declarations import (
    canonicalize_callsite_target_identities_8616,
)


class _Codegen:
    def __init__(self, project: object) -> None:
        self.project = project
        self._next_index = 0
        self.cfunc: object | None = None
        self._inertia_callsite_summaries: dict[int, CallsiteSummary8616] = {}

    def next_idx(self, _kind: str) -> int:
        self._next_index += 1
        return self._next_index

    def next_node_idx(self) -> int:
        return self.next_idx("")

    def next_ident(self, name: str) -> str:
        return name


class _Functions:
    def __init__(self) -> None:
        self.low = SimpleNamespace(addr=0x137E, name="sub_137e")
        self.linear = SimpleNamespace(addr=0x1137E, name="sub_1137e")

    def function(self, *, addr: int, create: bool) -> object | None:
        assert create is False
        return {0x137E: self.low, 0x1137E: self.linear}.get(addr)


def test_rebinds_low_word_call_target_to_exact_linear_summary_target() -> None:
    functions = _Functions()
    project = SimpleNamespace(
        arch=Arch86_16(),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(linked_base=0x10000, max_addr=0xFFFF),
        ),
        kb=SimpleNamespace(functions=functions),
    )
    codegen = _Codegen(project)
    call = CFunctionCall(
        "sub_137e",
        functions.low,
        [],
        tags={"ins_addr": 0x104AF},
        codegen=codegen,
    )
    root = CStatements([call], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root, body=root)
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x104AF,
            target_addr=0x1137E,
            return_addr=0x104B2,
            kind="near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register="dx:ax",
            return_used=True,
        )
    }

    changed = canonicalize_callsite_target_identities_8616(project, codegen)

    assert changed is True
    assert call.callee_func is functions.linear
    assert call.callee_target == "sub_1137e"
    stats = codegen._inertia_call_target_identity_stats_8616
    assert (
        stats.raw_fact_count,
        stats.normalized_fact_count,
        stats.classified_fact_count,
        stats.materialized_count,
        stats.failure_count,
    ) == (1, 1, 1, 1, 0)
