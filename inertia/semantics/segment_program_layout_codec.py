"""Encode worker-local segment facts without moving semantic ownership to CLI.

Layer: function/program summaries.
Responsibility: reduce and validate typed segment summary records transported by
clean CLI workers. This module does not classify program layout.

Package ownership contract (canonical inertia/semantics package):
Layer: Semantics.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite,
postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from typing import cast

from inertia.frontend.x86_16.declared_external_call_evidence import (
    declared_call_effect_consumption_from_record_8616,
)
from inertia.ir.segment_contract import SegmentFactVerdict

from .segment_function_summary import (
    SegmentControlTransferDistance8616,
    SegmentControlTransferFact8616,
    SegmentControlTransferKind8616,
    SegmentFunctionSummary8616,
)
from .segment_program_layout_contract import (
    SegmentProgramAccessEvidence8616,
    SegmentProgramFunctionEvidence8616,
    validated_segment_program_counts_8616,
)


def segment_program_function_evidence_8616(
    summary: SegmentFunctionSummary8616,
) -> SegmentProgramFunctionEvidence8616:
    """Reduce one typed function summary for deterministic worker transport."""
    counts = validated_segment_program_counts_8616(
        summary.summary,
        owner=f"segment function {summary.function_addr:#x}",
    )
    local = summary.local_contract
    return SegmentProgramFunctionEvidence8616(
        function_addr=summary.function_addr,
        entry_requirements=tuple(sorted(local.entry_requirements)),
        accesses=tuple(
            SegmentProgramAccessEvidence8616(
                block_addr=fact.block_addr,
                instruction_addr=fact.instruction_addr,
                segment_register=fact.segment_register,
                physical_source=fact.physical_source,
                verdict=fact.verdict,
            )
            for fact in local.accesses
        ),
        local_clobbered_registers=tuple(sorted(local.clobbered_registers)),
        restored_registers=tuple(sorted(local.restored_registers)),
        control_transfers=tuple(sorted(summary.control_transfers, key=lambda fact: fact.instruction_addr)),
        summary=counts,
        declared_call_consumptions=tuple(
            sorted(summary.declared_call_consumptions, key=lambda fact: fact.callsite_addr)
        ),
    )


def _int_8616(value: object, *, field_name: str, optional: bool = False) -> int | None:
    """Parse a strict nonnegative integer field."""
    if optional and value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"segment program evidence has invalid {field_name}")
    return value


def _strings_8616(value: object, *, field_name: str) -> tuple[str, ...]:
    """Parse a deterministic string-list field."""
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ValueError(f"segment program evidence has invalid {field_name}")
    parsed = tuple(value)
    if parsed != tuple(sorted(set(parsed))):
        raise ValueError(f"segment program evidence has non-canonical {field_name}")
    return parsed


def _string_8616(value: object, *, field_name: str) -> str:
    """Parse a required nonempty string before enum or contract construction."""
    if not isinstance(value, str) or not value:
        raise ValueError(f"segment program evidence has invalid {field_name}")
    return value


def _optional_string_8616(value: object, *, field_name: str) -> str | None:
    """Parse a strict optional nonempty string field."""
    return None if value is None else _string_8616(value, field_name=field_name)


def segment_program_function_evidence_from_record_8616(record: object) -> SegmentProgramFunctionEvidence8616:
    """Validate one clean-worker program-function evidence record."""
    if not isinstance(record, dict) or _int_8616(record.get("schema"), field_name="schema") != 1:
        raise ValueError("segment program function evidence has an unsupported schema")
    raw_accesses = record.get("accesses")
    raw_transfers = record.get("control_transfers")
    if not isinstance(raw_accesses, list) or not isinstance(raw_transfers, list):
        raise ValueError("segment program function evidence has invalid fact lists")
    accesses = tuple(
        SegmentProgramAccessEvidence8616(
            block_addr=cast(int, _int_8616(item.get("block_addr"), field_name="access block")),
            instruction_addr=_int_8616(item.get("instruction_addr"), field_name="access instruction", optional=True),
            segment_register=_optional_string_8616(
                item.get("segment_register"),
                field_name="access segment register",
            ),
            physical_source=_optional_string_8616(
                item.get("physical_source"),
                field_name="access physical source",
            ),
            verdict=SegmentFactVerdict(_string_8616(item.get("verdict"), field_name="access verdict")),
        )
        for item in raw_accesses
        if isinstance(item, dict)
    )
    if len(accesses) != len(raw_accesses):
        raise ValueError("segment program function evidence has a non-object access")
    transfers = tuple(
        SegmentControlTransferFact8616(
            instruction_addr=cast(int, _int_8616(item.get("instruction_addr"), field_name="transfer instruction")),
            kind=SegmentControlTransferKind8616(_string_8616(item.get("kind"), field_name="transfer kind")),
            distance=SegmentControlTransferDistance8616(_string_8616(item.get("distance"), field_name="transfer distance")),
            target_addr=_int_8616(item.get("target_addr"), field_name="transfer target", optional=True),
            return_addr=_int_8616(item.get("return_addr"), field_name="transfer return", optional=True),
            verdict=SegmentFactVerdict(_string_8616(item.get("verdict"), field_name="transfer verdict")),
        )
        for item in raw_transfers
        if isinstance(item, dict)
    )
    if len(transfers) != len(raw_transfers):
        raise ValueError("segment program function evidence has a non-object transfer")
    raw_consumptions = record.get("declared_call_consumptions")
    if not isinstance(raw_consumptions, list):
        raise ValueError("segment program function evidence has invalid declared consumptions")
    consumptions = tuple(
        declared_call_effect_consumption_from_record_8616(item)
        for item in raw_consumptions
    )
    if len({fact.callsite_addr for fact in consumptions}) != len(consumptions):
        raise ValueError("segment program function evidence has duplicate declared consumptions")
    counts = validated_segment_program_counts_8616(
        record.get("summary"),
        owner="transported segment function",
    )
    return SegmentProgramFunctionEvidence8616(
        function_addr=cast(int, _int_8616(record.get("function_addr"), field_name="function address")),
        entry_requirements=_strings_8616(record.get("entry_requirements"), field_name="entry requirements"),
        accesses=accesses,
        local_clobbered_registers=_strings_8616(
            record.get("local_clobbered_registers"),
            field_name="local clobbers",
        ),
        restored_registers=_strings_8616(record.get("restored_registers"), field_name="restores"),
        control_transfers=tuple(sorted(transfers, key=lambda fact: fact.instruction_addr)),
        summary=counts,
        declared_call_consumptions=tuple(
            sorted(consumptions, key=lambda fact: fact.callsite_addr)
        ),
    )
