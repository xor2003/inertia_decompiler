"""Declaration snapshots preserve native objects without recovering storage."""

from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen import c
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from angr_platforms.X86_16 import codegen_metadata


def test_stack_candidate_snapshot_excludes_arguments_and_preserves_objects() -> None:
    local = SimStackVariable(-4, 2, base="bp")
    argument = SimStackVariable(4, 2, base="bp")
    register = SimRegisterVariable(8, 2)
    marker = object()
    function = object.__new__(c.CFunction)
    arg = object.__new__(c.CVariable)
    arg.variable = argument
    function.arg_list = [arg]
    function.variables_in_use = {local: marker, argument: object(), register: object()}
    original = dict(function.variables_in_use)
    snapshot = codegen_metadata.snapshot_stack_local_candidates_8616(SimpleNamespace(cfunc=function))
    assert snapshot == {id(local): (local, marker)}
    assert snapshot[id(local)][0] is local
    assert snapshot[id(local)][1] is marker
    assert function.variables_in_use == original
    snapshot.clear()
    assert function.variables_in_use == original


@pytest.mark.parametrize("codegen", [object(), SimpleNamespace(cfunc=None), SimpleNamespace(cfunc=object())])
def test_stack_candidate_snapshot_requires_native_c_function(codegen: object) -> None:
    with pytest.raises(TypeError, match="requires a native CFunction"):
        codegen_metadata.snapshot_stack_local_candidates_8616(codegen)
