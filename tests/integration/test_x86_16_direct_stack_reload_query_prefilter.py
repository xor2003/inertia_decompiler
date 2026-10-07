"""Tests for direct-stack reload query prefilter ownership."""

from __future__ import annotations

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CConstant,
    CStatements,
    CTypeCast,
    CVariable,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.lowering.register_variable_identity import (
    capstone_register_name_8616,
    register_cvar_name_8616,
    register_cvar_names_8616,
)
from inertia.pipeline.structured_ast_query_index import (
    StructuredAstQueryIndex8616,
    TaggedAssignmentAddressIndex8616,
)
from capstone.x86_const import X86_REG_AX, X86_REG_INVALID


class _Codegen:
    """Minimal structured-C codegen fixture."""

    def __init__(self) -> None:
        self._index = 0
        self.project = type("Project", (), {"arch": Arch86_16()})()

    def next_idx(self, _name: str) -> int:
        """Return one deterministic test node index."""
        self._index += 1
        return self._index

    def next_node_idx(self) -> int:
        """Return one deterministic statement index."""
        return self.next_idx("")

    def next_ident(self, name: str) -> str:
        """Keep requested test identifiers stable."""
        return name


def _register_variable(codegen: _Codegen, offset: int, name: str) -> CVariable:
    """Build one typed register variable fixture."""
    return CVariable(
        SimRegisterVariable(offset, 2, name=name, region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )


def test_register_identity_preserves_capstone_offset_and_cast_forms() -> None:
    """Every supported third-party coordinate must retain one canonical name."""
    codegen = _Codegen()
    register = _register_variable(codegen, 0, "renamed_ax")
    cast = CTypeCast(
        SimTypeShort(False),
        SimTypeShort(False),
        register,
        codegen=codegen,
    )

    assert capstone_register_name_8616(X86_REG_AX) == "ax"
    assert capstone_register_name_8616(X86_REG_INVALID) is None
    assert register_cvar_name_8616(register) == "ax"
    assert register_cvar_name_8616(cast) == "ax"


def test_query_index_proves_only_exact_register_absence() -> None:
    """The reload prefilter must keep possible hits and reject only true misses."""
    codegen = _Codegen()
    register = _register_variable(codegen, 0, "ax")
    stack = CVariable(
        SimStackVariable(-2, 2, base="bp", name="local_2", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    assignment = CAssignment(
        stack,
        register,
        codegen=codegen,
        tags={"ins_addr": 0x4018},
    )
    query_index = StructuredAstQueryIndex8616.build(
        CStatements([assignment], codegen=codegen)
    )

    assert register_cvar_names_8616(query_index.variables) == frozenset({"ax"})
    assert "dx" not in register_cvar_names_8616(query_index.variables)
    tagged = TaggedAssignmentAddressIndex8616.from_query_index(query_index)
    assert tagged.intersects(frozenset({0x4018})) is True


def test_query_index_does_not_promote_constants_to_register_uses() -> None:
    """Opaque and scalar AST values must not create false register hits."""
    codegen = _Codegen()
    root = CStatements(
        [CConstant(1, SimTypeShort(False), codegen=codegen)],
        codegen=codegen,
    )

    query_index = StructuredAstQueryIndex8616.build(root)

    assert register_cvar_names_8616(query_index.variables) == frozenset()
