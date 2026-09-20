"""Classify optional metadata for honest recovery diagnostics.

Layer: CLI/fallback/reporting.
Responsibility: distinguish binary signature matches from local source/debug
evidence using the owned metadata contract, without inferring semantics.
"""

from angr_platforms.X86_16.lst_extract import LSTMetadata


def has_only_binary_signatures(metadata: object) -> bool:
    """Prove that a populated metadata record contains only signature evidence."""
    if not isinstance(metadata, LSTMetadata) or not metadata.signature_code_addrs:
        return False
    source_fields = (
        metadata.data_labels, metadata.function_entry_addrs, metadata.struct_names,
        metadata.debug_source_files, metadata.debug_type_names,
        metadata.debug_type_descriptors, metadata.debug_type_references,
        metadata.debug_symbols, metadata.debug_type_members,
        metadata.debug_enum_members, metadata.debug_identifiers,
        metadata.debug_line_map, metadata.cod_path, metadata.cod_proc_kinds,
    )
    if any(source_fields):
        return False
    labels_are_signatures = metadata.code_labels.keys() <= metadata.signature_code_addrs
    ranges_are_signatures = metadata.code_ranges.keys() <= metadata.signature_code_addrs
    return bool(labels_are_signatures and ranges_are_signatures)
