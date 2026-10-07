from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import CConstant, CReturn, CStatements
from angr.sim_type import SimTypeShort
from inertia.frontend.x86_16.arch_86_16 import Arch86_16

from inertia.structuring.scalar_return_evidence import (
    materialize_complete_scalar_return_leaves_8616,
)


class _Codegen:
    def __init__(self) -> None:
        self._idx = 0
        self.project = SimpleNamespace(arch=Arch86_16())

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def _body(codegen: _Codegen, value: int) -> CStatements:
    return CStatements(
        [CReturn(CConstant(value, SimTypeShort(False), codegen=codegen), codegen=codegen)],
        codegen=codegen,
    )


def test_scalar_return_leaves_reconnect_signed_cfg_values_atomically() -> None:
    codegen = _Codegen()
    bodies = tuple(_body(codegen, value) for value in (0xFFFF, 1, 0, 2))
    recovered = {
        address: CConstant(value, SimTypeShort(True), codegen=codegen)
        for address, value in zip(range(4), (-1, 1, 0, 2), strict=True)
    }

    result = materialize_complete_scalar_return_leaves_8616(
        bodies,
        recovered,
        recovered.get,
    )

    assert result.complete
    assert result.changed
    assert result.stats.materialized_count == 4
    assert all(expression.type.signed is True for expression in result.expressions)
    assert [body.statements[0].retval.value for body in bodies] == [-1, 1, 0, 2]


def test_scalar_return_leaves_refuse_partial_cfg_coverage_without_mutation() -> None:
    codegen = _Codegen()
    bodies = tuple(_body(codegen, value) for value in (0xFFFF, 1, 0, 2))
    recovered = {
        address: CConstant(value, SimTypeShort(True), codegen=codegen)
        for address, value in zip(range(3), (-1, 1, 0), strict=True)
    }

    result = materialize_complete_scalar_return_leaves_8616(
        bodies,
        recovered,
        recovered.get,
    )

    assert not result.complete
    assert not result.changed
    assert result.stats.failure_count == 1
    assert [body.statements[0].retval.value for body in bodies] == [0xFFFF, 1, 0, 2]
