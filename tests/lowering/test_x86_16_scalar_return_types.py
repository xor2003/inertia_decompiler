from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import CConstant, CReturn, CStatements
from angr.sim_type import SimTypeFunction, SimTypeInt, SimTypeShort
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.lowering.scalar_return_types import (
    ScalarReturnTypeEvidenceStatus8616,
    materialize_scalar_return_type_8616,
    record_scalar_return_type_evidence_8616,
)


class _DummyCodegen:
    def __init__(self, arch: Arch86_16) -> None:
        self._idx = 0
        self.project = SimpleNamespace(arch=arch)

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


class _FunctionManager:
    def __init__(self, function: SimpleNamespace) -> None:
        self._function = function

    def function(self, *, addr: int, create: bool) -> SimpleNamespace | None:
        assert create is False
        return self._function if addr == self._function.addr else None


class _SlottedCFunction:
    __slots__ = ("addr", "body", "functy", "statements")

    def __init__(self, statements: CStatements, prototype: SimTypeFunction) -> None:
        self.addr = 0x1000
        self.body = statements
        self.statements = statements
        self.functy = prototype


def _fixture(return_signedness: tuple[bool, ...]) -> tuple[SimpleNamespace, _DummyCodegen]:
    arch = Arch86_16()
    codegen = _DummyCodegen(arch)
    statements = CStatements(
        [
            CReturn(
                CConstant(value, SimTypeShort(signed), codegen=codegen),
                codegen=codegen,
            )
            for value, signed in zip((-1, 1), return_signedness, strict=True)
        ],
        addr=0x1000,
        codegen=codegen,
    )
    prototype = SimTypeFunction([], SimTypeShort(False)).with_arch(arch)
    codegen.cfunc = _SlottedCFunction(statements, prototype)
    function = SimpleNamespace(addr=0x1000, info={}, prototype=prototype)
    project = SimpleNamespace(arch=arch, kb=SimpleNamespace(functions=_FunctionManager(function)))
    return project, codegen


def test_complete_signed_word_returns_materialize_int_prototype() -> None:
    project, codegen = _fixture((True, True))

    result = materialize_scalar_return_type_8616(project, codegen)

    assert result.changed is True
    assert result.stats.materialized_count == 2
    assert isinstance(codegen.cfunc.functy.returnty, SimTypeInt)
    assert codegen.cfunc.functy.returnty.signed is True


def test_mixed_return_signedness_refuses_prototype_change() -> None:
    project, codegen = _fixture((True, False))

    result = materialize_scalar_return_type_8616(project, codegen)

    assert result.changed is False
    assert result.stats.failure_count == 1
    assert isinstance(codegen.cfunc.functy.returnty, SimTypeShort)
    assert codegen.cfunc.functy.returnty.signed is False


def test_recorded_signed_returns_survive_codegen_type_regeneration() -> None:
    project, codegen = _fixture((True, True))
    expressions = tuple(statement.retval for statement in codegen.cfunc.statements.statements)
    status = record_scalar_return_type_evidence_8616(project, 0x1000, expressions)
    regenerated_project, regenerated_codegen = _fixture((False, False))
    regenerated_codegen.project = project
    project.kb = regenerated_project.kb

    result = materialize_scalar_return_type_8616(project, regenerated_codegen)

    assert status is ScalarReturnTypeEvidenceStatus8616.RECORDED
    assert result.changed is True
    assert result.stats.materialized_count == 2
    assert isinstance(regenerated_codegen.cfunc.functy.returnty, SimTypeInt)
    assert regenerated_codegen.cfunc.functy.returnty.signed is True


def test_recorded_signed_returns_refuse_changed_return_values() -> None:
    project, codegen = _fixture((True, True))
    expressions = tuple(statement.retval for statement in codegen.cfunc.statements.statements)
    assert (
        record_scalar_return_type_evidence_8616(project, 0x1000, expressions)
        is ScalarReturnTypeEvidenceStatus8616.RECORDED
    )
    regenerated_project, regenerated_codegen = _fixture((False, False))
    regenerated_codegen.cfunc.statements.statements[1].retval.value = 2
    regenerated_codegen.project = project
    project.kb = regenerated_project.kb

    result = materialize_scalar_return_type_8616(project, regenerated_codegen)

    assert result.changed is False
    assert result.stats.failure_count == 1
    assert isinstance(regenerated_codegen.cfunc.functy.returnty, SimTypeShort)
    assert regenerated_codegen.cfunc.functy.returnty.signed is False
