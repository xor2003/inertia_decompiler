from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import CStatements, CVariable
from angr.sim_type import SimTypeChar
from angr.sim_variable import SimMemoryVariable
from inertia.lowering.cod_global_identity import (
    CodGlobalStorageSurface8616,
    record_cod_global_storage_identities_8616,
)
from archinfo import ArchX86

from inertia.frontend.x86_16.cod_extract import CODGlobalRef, CODProcMetadata
from inertia.lowering.codegen_metadata import GlobalDeclarationArrayExtent8616


class _Codegen:
    def __init__(self) -> None:
        self.project = SimpleNamespace(arch=ArchX86())
        self.cstyle_null_cmp = False
        self._next_index = 0
        self.cfunc = SimpleNamespace(
            statements=CStatements([], codegen=self),
            variables_in_use={},
        )
        self._inertia_global_declaration_specs_8616 = (
            ("unsigned char", "_S101_g_table", 1),
            ("unsigned char", "g_table", 4),
        )

    def next_idx(self, _kind: str) -> int:
        index = self._next_index
        self._next_index += 1
        return index
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def _metadata(*refs: CODGlobalRef) -> CODProcMetadata:
    return CODProcMetadata(
        stack_aliases={},
        call_names=(),
        call_sources=(),
        global_names=(),
        source_lines=(),
        source_line_set=frozenset(),
        global_refs=refs,
    )


def test_cod_global_identity_survives_display_alias_declaration_reconcile() -> None:
    codegen = _Codegen()
    variable = CVariable(
        SimMemoryVariable(0x44, 1, name="g_table", region=0x1000),
        variable_type=SimTypeChar(False),
        codegen=codegen,
    )
    codegen.cfunc.statements.statements.append(variable)
    metadata = _metadata(
        CODGlobalRef(
            offset=0x44,
            name="_S101_g_table",
            relative_disp=0,
            width=1,
            indexed=True,
            instruction_bytes=b"\x8a",
            source_alias="g_table",
        )
    )

    changed = record_cod_global_storage_identities_8616(
        codegen,
        metadata,
        (CodGlobalStorageSurface8616(0x44, 1, "_S101_g_table"),),
    )

    assert changed is True
    assert variable.name == "g_table"
    assert codegen._inertia_global_declaration_specs_8616 == (
        ("unsigned char", "g_table", 4),
    )
    assert codegen._inertia_cod_global_identity_stats_8616.classified_fact_count == 1
    assert codegen._inertia_cod_global_identity_stats_8616.materialized_count == 1
    assert codegen._inertia_cod_global_identity_stats_8616.failure_count == 0


def test_cod_global_identity_rebinds_persistent_typed_declaration() -> None:
    codegen = _Codegen()
    codegen._inertia_global_declaration_specs_8616 = (
        ("unsigned short", "_S101_g_table", None),
    )
    codegen._inertia_strong_global_declaration_specs_8616 = (
        ("unsigned short", "_S101_g_table", None),
    )
    metadata = _metadata(
        CODGlobalRef(
            offset=0x44,
            name="_S101_g_table",
            relative_disp=0,
            width=1,
            indexed=True,
            instruction_bytes=b"\x8a",
            source_alias="g_table",
        )
    )

    record_cod_global_storage_identities_8616(
        codegen,
        metadata,
        (CodGlobalStorageSurface8616(0x44, 1, "_S101_g_table"),),
    )
    assert codegen._inertia_strong_global_declaration_specs_8616 == (
        ("unsigned short", "g_table", None),
    )
    assert codegen._inertia_global_declaration_specs_8616 == (
        ("unsigned short", "g_table", None),
    )


def test_cod_global_identity_refuses_ambiguous_display_alias() -> None:
    codegen = _Codegen()
    metadata = _metadata(
        CODGlobalRef(0x44, "_S101_g_table", 0, 1, True, b"\x8a", "g_table"),
        CODGlobalRef(0x48, "_S102_g_table", 0, 1, True, b"\x8a", "g_table"),
    )

    changed = record_cod_global_storage_identities_8616(
        codegen,
        metadata,
        (
            CodGlobalStorageSurface8616(0x44, 1, "_S101_g_table"),
            CodGlobalStorageSurface8616(0x48, 1, "_S102_g_table"),
        ),
    )

    assert changed is False
    assert codegen._inertia_cod_global_identity_facts_8616 == ()
    assert codegen._inertia_cod_global_identity_stats_8616.failure_count == 2


def test_cod_global_identity_preserves_unknown_indexed_extent() -> None:
    codegen = _Codegen()
    codegen._inertia_global_declaration_specs_8616 = (
        (
            "unsigned char",
            "_S101_g_table",
            GlobalDeclarationArrayExtent8616.UNKNOWN,
        ),
        (
            "unsigned char",
            "g_table",
            GlobalDeclarationArrayExtent8616.UNKNOWN,
        ),
    )
    metadata = _metadata(
        CODGlobalRef(0x44, "_S101_g_table", 0, 1, True, b"\x8a", "g_table")
    )

    changed = record_cod_global_storage_identities_8616(
        codegen,
        metadata,
        (CodGlobalStorageSurface8616(0x44, 1, "_S101_g_table"),),
    )

    assert changed is True
    assert codegen._inertia_global_declaration_specs_8616 == (
        (
            "unsigned char",
            "g_table",
            GlobalDeclarationArrayExtent8616.UNKNOWN,
        ),
    )
