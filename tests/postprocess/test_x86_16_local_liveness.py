from __future__ import annotations

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimRegisterVariable, SimStackVariable

from inertia.postprocess.optimization.local_liveness import local_liveness_key_8616


class _Codegen:
    def __init__(self) -> None:
        self._idx = 0

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


_CODEGEN = _Codegen()


def _cvar(variable: SimRegisterVariable | SimStackVariable) -> structured_c.CVariable:
    return structured_c.CVariable(variable, codegen=_CODEGEN)


def test_local_liveness_matches_distinct_nodes_for_same_ssa_register() -> None:
    assigned = _cvar(SimRegisterVariable(6, 2, ident="ir_6", name="v9", region=0x10678))
    read = _cvar(SimRegisterVariable(6, 2, ident="ir_6", name="v9", region=0x10678))

    assert assigned.variable is not read.variable
    assert local_liveness_key_8616(assigned) == local_liveness_key_8616(read)


def test_local_liveness_keeps_distinct_ssa_register_versions_separate() -> None:
    prior = _cvar(SimRegisterVariable(6, 2, ident="ir_5", name="v8", region=0x10678))
    current = _cvar(SimRegisterVariable(6, 2, ident="ir_6", name="v9", region=0x10678))

    assert local_liveness_key_8616(prior) != local_liveness_key_8616(current)


def test_local_liveness_matches_distinct_nodes_for_same_stack_slot() -> None:
    assigned = _cvar(SimStackVariable(-2, 2, base="bp", name="local_2", region=0x10678))
    read = _cvar(SimStackVariable(-2, 2, base="bp", name="local_2", region=0x10678))

    assert local_liveness_key_8616(assigned) == local_liveness_key_8616(read)
