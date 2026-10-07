from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.knowledge_plugins.functions.function import PrototypeSource
from angr.sim_type import SimTypeFunction, SimTypeShort
from angr.sim_variable import SimStackVariable
from inertia.lowering.authoritative_function_prototypes import (
    capture_authoritative_function_prototype_8616,
)
from inertia.lowering.near_return_address_arguments import (
    NearReturnAddressArgumentVerdict8616,
    prune_near_return_address_argument_8616,
)


def _argument(offset: int, codegen: SimpleNamespace) -> structured_c.CVariable:
    variable = SimStackVariable(offset, 2, base="bp", region=0x1000)
    return structured_c.CVariable(
        variable,
        codegen=codegen,
    )


def _codegen_with_arguments(*offsets: int) -> SimpleNamespace:
    codegen = SimpleNamespace(
        next_ident=lambda name: name,
        next_node_idx=lambda: 1,
    )
    codegen.cfunc = SimpleNamespace(
        arg_list=[_argument(offset, codegen) for offset in offsets]
    )
    return codegen


def test_prunes_exact_near_return_word_when_authoritative_census_closes() -> None:
    prototype = SimTypeFunction(
        [SimTypeShort(False), SimTypeShort(False)],
        SimTypeShort(False),
    )
    function = SimpleNamespace(
        addr=0x1000,
        prototype=prototype,
        prototype_source=PrototypeSource.USER,
        info={},
    )
    project = SimpleNamespace()
    capture_authoritative_function_prototype_8616(project, function)
    codegen = _codegen_with_arguments(2, 4, 6)

    result = prune_near_return_address_argument_8616(project, codegen, function)

    assert result.verdict is NearReturnAddressArgumentVerdict8616.MATERIALIZED
    assert result.stats.materialized_count == 1
    assert [arg.variable.offset for arg in codegen.cfunc.arg_list] == [4, 6]


def test_retains_near_return_word_without_authoritative_census() -> None:
    function = SimpleNamespace(
        addr=0x1000,
        prototype=SimTypeFunction([SimTypeShort(False)], SimTypeShort(False)),
        prototype_source=PrototypeSource.GUESSED,
        info={},
    )
    project = SimpleNamespace()
    codegen = _codegen_with_arguments(2, 4)

    result = prune_near_return_address_argument_8616(project, codegen, function)

    assert result.verdict is NearReturnAddressArgumentVerdict8616.CENSUS_UNAVAILABLE_REFUSE
    assert result.stats.failure_count == 1
    assert [arg.variable.offset for arg in codegen.cfunc.arg_list] == [2, 4]
