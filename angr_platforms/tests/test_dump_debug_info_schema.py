from __future__ import annotations

from dataclasses import fields
from types import SimpleNamespace

from angr_platforms.X86_16.codeview_nb00 import CodeViewNB00Info
from angr_platforms.X86_16.codeview_nb02_nb04 import CodeViewNB0204Info
from angr_platforms.X86_16.turbo_debug_tdinfo import TDInfoEXEInfo, TDInfoHeader

from dump_debug_info import _nb00, _nb0204, _tdinfo


def _empty_nb00_info() -> SimpleNamespace:
    return SimpleNamespace(
        version="NB00",
        debug_base=0,
        subsection_directory_offset=0,
        modules=(),
        publics=(),
        type_definitions=(),
        type_record_names=(),
        type_members=(),
        source_files=(),
        line_map={},
        debug_identifiers=(),
        code_labels={},
        data_labels={},
        code_ranges={},
    )


def _empty_nb0204_info() -> SimpleNamespace:
    return SimpleNamespace(
        version="NB09",
        debug_base=0,
        code_labels={},
        data_labels={},
        procedures=(),
        stack_variables={},
        line_map={},
        modules=(),
        source_files=(),
        type_record_names=(),
        type_members=(),
        debug_identifiers=(),
    )


def _empty_tdinfo_info() -> SimpleNamespace:
    header = SimpleNamespace(
        major_version=0,
        minor_version=0,
        names_pool_size_in_bytes=0,
        names_count=0,
        types_count=0,
        members_count=0,
        symbols_count=0,
        globals_count=0,
        extension_size=0,
        source_modules_count=0,
        local_symbols_count=0,
        scopes_count=0,
        line_entries_count=0,
        include_files_count=0,
        segments_count=0,
        correlations_count=0,
        class_entries_count=0,
        parent_entries_count=0,
        module_class_entries_count=0,
        coverage_offsets_count=0,
    )
    return SimpleNamespace(
        header=header,
        debug_info_offset=0,
        symbols=(),
        names=(),
        name_pool_entries=(),
        source_files=(),
        candidate_identifiers=(),
        public_symbols=(),
        local_identifiers=(),
        named_symbols=(),
        names_by_class={},
        symbols_by_class={},
        stack_variables=(),
        register_symbols=(),
        constant_symbols=(),
        type_names=(),
        type_descriptors=(),
        type_references=(),
        type_members=(),
        enum_members=(),
        member_lists=(),
        class_entries=(),
        parent_class_table=(),
        module_class_entries=(),
        line_entries=(),
        scopes=(),
        correlations=(),
        modules=(),
        source_file_entries=(),
        segments=(),
        coverage_map=(),
        coverage_offsets=(),
        module_flags=(),
        raw_table_spans=(),
        code_labels={},
        data_labels={},
        tds_version_str="",
        tlink_version_str="",
        commandline_hint="",
        products="",
    )


def test_dump_debug_info_nb00_schema_matches_parser_result_fields():
    payload = _nb00(_empty_nb00_info())

    assert payload is not None
    assert set(payload) == {field.name for field in fields(CodeViewNB00Info)}


def test_dump_debug_info_nb0204_schema_matches_parser_result_fields():
    payload = _nb0204(_empty_nb0204_info())

    assert payload is not None
    assert set(payload) == {field.name for field in fields(CodeViewNB0204Info)}


def test_dump_debug_info_tdinfo_schema_matches_parser_result_fields():
    payload = _tdinfo(_empty_tdinfo_info())
    expected = {field.name for field in fields(TDInfoEXEInfo)}
    expected.remove("tds_version_str")
    expected.remove("tlink_version_str")
    expected.update(
        {
            "tds_version",
            "tlink_version",
            "demangled_names",
            "struct_declarations",
            "function_signatures",
        }
    )

    assert payload is not None
    assert set(payload) == expected
    assert set(payload["header"]) == {field.name for field in fields(TDInfoHeader)}
