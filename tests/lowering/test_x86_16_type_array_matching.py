from __future__ import annotations

from angr.analyses.decompiler.structured_codegen.c import CVariable
from angr.sim_variable import SimRegisterVariable

from inertia.cli.cli_access_profiles import InductionSummary
from inertia.lowering.type_array_matching import (
    _has_induction_evidence_for_key_8616,
    _profile_induction_match_8616,
)


class _DummyCodegen:
    def __init__(self, summary: InductionSummary) -> None:
        self._idx = 0
        self._inertia_induction_summaries = (object(), summary)

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def test_type_array_matching_uses_typed_induction_summary_fields() -> None:
    summary = InductionSummary(
        base_key=("stack", "bp", -4, None),
        index_key=("reg", 0x200),
        stride=2,
        direction="increment",
        bound_candidate=10,
        width=16,
        offset=4,
        count=3,
    )
    codegen = _DummyCodegen(summary)
    loop_var = CVariable(SimRegisterVariable(0x200, 2, name="i"), codegen=codegen)

    assert _has_induction_evidence_for_key_8616(codegen, ("reg", 0x200)) is True

    match = _profile_induction_match_8616(codegen, loop_var)

    assert match is not None
    assert match.var_name == "i"
    assert match.stride == 2
    assert match.base_value == 4
    assert match.loop_bound == 10
    assert match.element_width == 16
