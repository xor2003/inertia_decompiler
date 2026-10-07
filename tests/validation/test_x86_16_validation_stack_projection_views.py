from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CBinaryOp,
    CConstant,
    CFunctionCall,
    CStatements,
    CVariable,
)
from angr.sim_type import SimTypeLong, SimTypeShort
from angr.sim_variable import SimStackVariable
from inertia.semantics.callsite_summary import CallsiteSummary8616
from inertia.lowering.condition_stack_projection_contracts import (
    ConditionStackProjectionFact8616,
    condition_stack_projection_tags_8616,
)
from archinfo import ArchX86

from inertia.validation.validation_calls import validate_call_argument_classes_8616
from inertia.validation.validation_dataflow import (
    DefUseEntryStackRange8616,
    validate_structured_def_use_8616,
)


class _Codegen:
    """Provide the minimal dynamic angr codegen boundary used by C nodes."""

    def __init__(self) -> None:
        self._next_index = 0
        self._inertia_callsite_summaries: dict[int, CallsiteSummary8616] = {}
        self.cstyle_null_cmp = False
        self.project = SimpleNamespace(arch=ArchX86())

    def next_idx(self, _kind: str) -> int:
        """Return a deterministic structured-node index."""
        index = self._next_index
        self._next_index += 1
        return index

    def next_node_idx(self) -> int:
        """Return a deterministic structured-node index."""
        return self.next_idx("")

    def next_ident(self, name: str) -> str:
        """Return stable identifiers for focused validation tests."""
        return name


def _high_word_projection(codegen: _Codegen) -> CBinaryOp:
    """Build the exact typed high-word view emitted by stack lowering."""
    long_type = SimTypeLong(False).with_arch(codegen.project.arch)
    short_type = SimTypeShort(False).with_arch(codegen.project.arch)
    fact = ConditionStackProjectionFact8616(
        base="bp",
        owner_offset=10,
        owner_size=4,
        view_offset=12,
        view_size=2,
    )
    tags = condition_stack_projection_tags_8616({}, fact)
    owner = CVariable(
        SimStackVariable(10, 4, base="bp", name="cmdline"),
        variable_type=long_type,
        codegen=codegen,
        tags=tags,
    )
    shifted = CBinaryOp(
        "Shr",
        owner,
        CConstant(16, long_type, codegen=codegen),
        codegen=codegen,
        tags=tags,
    )
    return CBinaryOp(
        "And",
        shifted,
        CConstant(0xFFFF, short_type, codegen=codegen),
        codegen=codegen,
        tags=tags,
    )


def test_def_use_validates_only_the_typed_high_word_view() -> None:
    """Do not widen one projected word read back to its four-byte owner."""
    codegen = _Codegen()
    report = validate_structured_def_use_8616(
        CStatements([_high_word_projection(codegen)], codegen=codegen),
        entry_defined_stack_ranges=(DefUseEntryStackRange8616(base_offset=12, width=2),),
    )

    assert report.passed
    assert report.materialized_count == 1


def test_call_source_validation_uses_typed_high_word_view_offset() -> None:
    """Compare a projected high word with its physical BP+12 push source."""
    codegen = _Codegen()
    call = CFunctionCall(
        "consume",
        None,
        [_high_word_projection(codegen)],
        tags={"ins_addr": 0x1070},
        codegen=codegen,
    )
    codegen._inertia_callsite_summaries[id(call)] = CallsiteSummary8616(
        callsite_addr=0x1070,
        target_addr=0x1111,
        return_addr=0x1073,
        kind="direct_near",
        arg_count=1,
        arg_widths=(2,),
        stack_cleanup=2,
        return_register=None,
        return_used=False,
        push_arg_sources=(("bp", 12, 2),),
    )

    report = validate_call_argument_classes_8616(
        codegen,
        CStatements([call], codegen=codegen),
    )

    assert report.passed
    assert report.materialized_count == 1
