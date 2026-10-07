from __future__ import annotations

from enum import IntEnum
from types import SimpleNamespace

from inertia.cli.lst_extract import (
    DebugEnumMemberEvidence,
    DebugSymbolEvidence,
    DebugTypeDescriptorEvidence,
    DebugTypeMemberEvidence,
    DebugTypeReferenceEvidence,
    LSTMetadata,
)
import inertia.cli.sidecar_metadata as sidecar_metadata
from inertia.cli.sidecar_cache import _deserialize_lst_metadata, _serialize_lst_metadata


def test_sidecar_metadata_cache_preserves_debug_information_fields():
    metadata = LSTMetadata(
        data_labels={0x2000: "global_counter"},
        code_labels={0x1000: "main"},
        debug_source_files=("DBGPROBE.C",),
        debug_type_names=("Pair", "left", "right"),
        debug_type_descriptors=(
            DebugTypeDescriptorEvidence(
                type_index=0x201,
                kind="STRUCT",
                name="Pair",
                size=4,
                attributes=0x10,
                source="turbo_debug_tdinfo",
            ),
            DebugTypeDescriptorEvidence(
                type_index=0x220,
                kind="FUNCTION",
                name="callback",
                size=0,
                return_type_index=0x201,
                call_kind=2,
                attributes=0x20,
                source="turbo_debug_tdinfo",
            ),
            DebugTypeDescriptorEvidence(
                type_index=0x230,
                kind="ENUM",
                name="Color",
                size=2,
                base_type_index=0x10,
                attributes=0x30,
                lower_bound=0,
                upper_bound=3,
                source="turbo_debug_tdinfo",
            ),
        ),
        debug_type_references=(
            DebugTypeReferenceEvidence(
                name="Pair",
                type_index=0x201,
                symbol_class="TYPEDEF",
                source="turbo_debug_tdinfo",
            ),
        ),
        debug_symbols=(
            DebugSymbolEvidence(
                name="_main",
                symbol_class="0x0105",
                storage="procedure",
                offset=0x20,
                segment=0,
                linear_addr=0x1020,
                length=0x24,
                type_index=0x220,
                attributes=(("debug_start", "1"), ("flags", "0")),
                source="codeview_nb0204",
            ),
            DebugSymbolEvidence(
                name="local_i",
                symbol_class="AUTO",
                storage="auto",
                offset=0xFFFE,
                signed_offset=-2,
                segment=0,
                linear_addr=0xFFFE,
                type_index=0x74,
                attributes=(("record_index", "2"),),
                source="turbo_debug_tdinfo",
            ),
        ),
        debug_type_members=(
            DebugTypeMemberEvidence(
                name="left",
                offset=0,
                owner_type_index=0x201,
                type_index=0x74,
                leaf_index=1,
                source="codeview_nb00",
            ),
            DebugTypeMemberEvidence(
                name="right",
                offset=2,
                owner_type_index=0x201,
                type_index=0x74,
                attributes=0x40,
                source="turbo_debug_tdinfo",
            ),
        ),
        debug_enum_members=(
            DebugEnumMemberEvidence(
                name="RED",
                value=1,
                owner_type_index=0x230,
                attributes=0x80,
                source="turbo_debug_tdinfo",
            ),
        ),
        debug_identifiers=("LOCAL_SUM", "RESULT"),
        debug_line_map={0x1000: (12, 0)},
        absolute_addrs=True,
        source_format="codeview_nb00+turbo_debug_tdinfo",
    )

    restored = _deserialize_lst_metadata(_serialize_lst_metadata(metadata))

    assert restored is not None
    assert restored.debug_source_files == ("DBGPROBE.C",)
    assert restored.debug_type_names == ("Pair", "left", "right")
    assert restored.debug_type_descriptors == (
        DebugTypeDescriptorEvidence(
            type_index=0x201,
            kind="STRUCT",
            name="Pair",
            size=4,
            attributes=0x10,
            source="turbo_debug_tdinfo",
        ),
        DebugTypeDescriptorEvidence(
            type_index=0x220,
            kind="FUNCTION",
            name="callback",
            size=0,
            return_type_index=0x201,
            call_kind=2,
            attributes=0x20,
            source="turbo_debug_tdinfo",
        ),
        DebugTypeDescriptorEvidence(
            type_index=0x230,
            kind="ENUM",
            name="Color",
            size=2,
            base_type_index=0x10,
            attributes=0x30,
            lower_bound=0,
            upper_bound=3,
            source="turbo_debug_tdinfo",
        ),
    )
    assert restored.debug_type_references == (
        DebugTypeReferenceEvidence(
            name="Pair",
            type_index=0x201,
            symbol_class="TYPEDEF",
            source="turbo_debug_tdinfo",
        ),
    )
    assert restored.debug_symbols == (
        DebugSymbolEvidence(
            name="_main",
            symbol_class="0x0105",
            storage="procedure",
            offset=0x20,
            segment=0,
            linear_addr=0x1020,
            length=0x24,
            type_index=0x220,
            attributes=(("debug_start", "1"), ("flags", "0")),
            source="codeview_nb0204",
        ),
        DebugSymbolEvidence(
            name="local_i",
            symbol_class="AUTO",
            storage="auto",
            offset=0xFFFE,
            signed_offset=-2,
            segment=0,
            linear_addr=0xFFFE,
            type_index=0x74,
            attributes=(("record_index", "2"),),
            source="turbo_debug_tdinfo",
        ),
    )
    assert restored.debug_type_members == (
        DebugTypeMemberEvidence(
            name="left",
            offset=0,
            owner_type_index=0x201,
            type_index=0x74,
            leaf_index=1,
            source="codeview_nb00",
        ),
        DebugTypeMemberEvidence(
            name="right",
            offset=2,
            owner_type_index=0x201,
            type_index=0x74,
            attributes=0x40,
            source="turbo_debug_tdinfo",
        ),
    )
    assert restored.debug_enum_members == (
        DebugEnumMemberEvidence(
            name="RED",
            value=1,
            owner_type_index=0x230,
            attributes=0x80,
            source="turbo_debug_tdinfo",
        ),
    )
    assert restored.debug_identifiers == ("LOCAL_SUM", "RESULT")
    assert restored.debug_line_map == {0x1000: (12, 0)}


def test_codeview_sidecar_load_collects_debug_records_without_labels(monkeypatch):
    parsed = SimpleNamespace(
        code_labels={},
        data_labels={},
        code_ranges={},
        source_files=("DBG.C",),
        type_record_names=("PAIR",),
        publics=(),
        type_members=(
            SimpleNamespace(name="left", offset=0, owner_type_index=0x201, leaf_index=2),
        ),
        debug_identifiers=("local_i",),
        line_map={},
    )
    monkeypatch.setattr(sidecar_metadata, "parse_codeview_nb00", lambda *args, **kwargs: parsed)

    (
        code_labels,
        data_labels,
        code_ranges,
        source_format,
        debug_source_files,
        debug_type_names,
        debug_symbols,
        debug_type_members,
        debug_identifiers,
        debug_line_map,
    ) = sidecar_metadata._load_codeview_or_ne_metadata("dummy.exe", object(), load_base_linear=0)

    assert code_labels == {}
    assert data_labels == {}
    assert code_ranges == {}
    assert source_format == "codeview_nb00"
    assert debug_source_files == ("DBG.C",)
    assert debug_type_names == ("PAIR",)
    assert debug_symbols == ()
    assert debug_type_members == (
        DebugTypeMemberEvidence(
            name="left",
            offset=0,
            owner_type_index=0x201,
            leaf_index=2,
            source="codeview_nb00",
        ),
    )
    assert debug_identifiers == ("local_i",)
    assert debug_line_map == {}


def test_tdinfo_sidecar_load_collects_symbol_only_records(monkeypatch):
    class FakeSymbolClass(IntEnum):
        AUTO = 2

    class FakeRecord:
        index = 1
        type_index = 0x74
        offset = 0xFFFE
        signed_offset = -2
        segment = 0
        symbol_class = FakeSymbolClass.AUTO

        def linear_addr(self, *, load_base_linear: int) -> int:
            return load_base_linear + self.offset

    tdinfo = SimpleNamespace(
        code_labels={},
        data_labels={},
        source_files=(),
        type_names=(),
        type_descriptors=(),
        type_references=(),
        type_members=(),
        enum_members=(),
        named_symbols=(SimpleNamespace(name="local_i", record=FakeRecord()),),
        names_by_class={FakeSymbolClass.AUTO: ("local_i",)},
        symbols_by_class={FakeSymbolClass.AUTO: (FakeRecord(),)},
        stack_variables=(),
        register_symbols=(),
        constant_symbols=(),
        candidate_identifiers=(),
    )
    monkeypatch.setattr(sidecar_metadata, "parse_tdinfo_exe", lambda *args, **kwargs: tdinfo)

    debug_symbols: list[DebugSymbolEvidence] = []
    source_formats: list[str] = []
    sidecar_metadata._load_tdinfo_sidecar(
        "dummy.exe",
        load_base_linear=0x1000,
        code_labels={},
        data_labels={},
        debug_source_files=[],
        debug_type_names=[],
        debug_type_descriptors=[],
        debug_type_references=[],
        debug_symbols=debug_symbols,
        debug_type_members=[],
        debug_enum_members=[],
        debug_identifiers=[],
        source_formats=source_formats,
    )

    assert debug_symbols == [
        DebugSymbolEvidence(
            name="local_i",
            symbol_class="AUTO",
            storage="auto",
            offset=0xFFFE,
            signed_offset=-2,
            segment=0,
            linear_addr=0x10FFE,
            type_index=0x74,
            attributes=(("record_index", "1"),),
            source="turbo_debug_tdinfo",
        ),
    ]
    assert source_formats == ["turbo_debug_tdinfo"]
