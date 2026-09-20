"""Recover exact carry/borrow links from typed function SSA.

Layer: Semantics.
Responsibility: classify the SSA dataflow from a low-word flags definition
through bit extraction into a high-word add/subtract. The proof is same-block
and exact-definition bounded; unsupported dataflow is retained as a refusal.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from ..ir import IRValue, MemSpace
from ..ir.ssa_function import SSAFunctionArtifact
from .carry_borrow_cfg import (
    CarryBorrowBlockSSA8616,
    build_carry_borrow_block_ssa_8616,
    resolve_carry_flags_definition_8616,
)
from .carry_borrow_contracts import (
    CarryBorrowConversion8616,
    CarryBorrowDefinitionSite8616,
    CarryBorrowEvidence8616,
    CarryBorrowFailure8616,
    CarryBorrowIROp8616,
    CarryBorrowKind8616,
    CarryBorrowLink8616,
    CarryBorrowResolution8616,
    CarryBorrowStats8616,
    CarryBorrowVerdict8616,
)
from .carry_borrow_ssa import (
    CarryBorrowDefinitions8616,
    arithmetic_kind_8616,
    conversion_source_8616,
    definition_for_8616,
    dependency_arithmetic_sites_8616,
    ir_op_8616,
    is_constant_8616,
    operand_use_8616,
    same_operands_8616,
    single_source_8616,
    site_value_args_8616,
)


def _refusal(
    candidate: CarryBorrowDefinitionSite8616,
    failure: CarryBorrowFailure8616,
) -> CarryBorrowResolution8616:
    return CarryBorrowResolution8616(
        candidate=candidate,
        verdict=CarryBorrowVerdict8616.UNKNOWN_REFUSE,
        failure=failure,
    )


def _carry_chain(
    carry_value: IRValue,
    definitions: CarryBorrowDefinitions8616,
) -> tuple[
    CarryBorrowDefinitionSite8616,
    CarryBorrowDefinitionSite8616,
    CarryBorrowDefinitionSite8616,
    CarryBorrowDefinitionSite8616,
    CarryBorrowDefinitionSite8616,
] | CarryBorrowFailure8616:
    extend = definition_for_8616(carry_value, definitions)
    if extend is None:
        return CarryBorrowFailure8616.TEMP_DEFINITION_MISSING
    narrow_value = conversion_source_8616(extend, CarryBorrowConversion8616.WIDEN_BIT_TO_WORD)
    if narrow_value is None:
        return CarryBorrowFailure8616.CARRY_CONVERSION_MISMATCH
    narrow = definition_for_8616(narrow_value, definitions)
    if narrow is None:
        return CarryBorrowFailure8616.TEMP_DEFINITION_MISSING
    mask_value = conversion_source_8616(narrow, CarryBorrowConversion8616.NARROW_TO_BIT)
    if mask_value is None:
        return CarryBorrowFailure8616.CARRY_CONVERSION_MISMATCH
    mask = definition_for_8616(mask_value, definitions)
    if mask is None:
        return CarryBorrowFailure8616.TEMP_DEFINITION_MISSING
    mask_args = site_value_args_8616(mask)
    if ir_op_8616(mask.instruction) is not CarryBorrowIROp8616.AND16 or len(mask_args) != 2:
        return CarryBorrowFailure8616.CARRY_MASK_MISMATCH
    if is_constant_8616(mask_args[0], 1):
        shift_value = mask_args[1]
    elif is_constant_8616(mask_args[1], 1):
        shift_value = mask_args[0]
    else:
        return CarryBorrowFailure8616.CARRY_MASK_MISMATCH
    shift = definition_for_8616(shift_value, definitions)
    if shift is None:
        return CarryBorrowFailure8616.TEMP_DEFINITION_MISSING
    shift_args = site_value_args_8616(shift)
    if (
        ir_op_8616(shift.instruction) is not CarryBorrowIROp8616.SHR16
        or len(shift_args) != 2
        or not is_constant_8616(shift_args[1], 0)
    ):
        return CarryBorrowFailure8616.CARRY_SHIFT_MISMATCH
    flags_read = definition_for_8616(shift_args[0], definitions)
    flags_value = None if flags_read is None else single_source_8616(flags_read)
    if (
        flags_read is None
        or flags_value is None
        or flags_value.space is not MemSpace.REG
        or flags_value.name != "flags"
    ):
        return CarryBorrowFailure8616.FLAGS_DEFINITION_MISSING
    return flags_read, shift, mask, narrow, extend


def _low_result(
    flags_definition: CarryBorrowDefinitionSite8616,
    sites: tuple[CarryBorrowDefinitionSite8616, ...],
    definitions: CarryBorrowDefinitions8616,
    kind: CarryBorrowKind8616,
) -> tuple[CarryBorrowDefinitionSite8616, CarryBorrowDefinitionSite8616] | None:
    """Find the unique post-FLAGS register effect owned by the instruction."""
    flags_source = single_source_8616(flags_definition)
    if flags_source is None:
        return None
    flag_arithmetic = dependency_arithmetic_sites_8616(flags_source, definitions, kind)
    signatures = tuple(site_value_args_8616(site) for site in flag_arithmetic)
    matches: list[tuple[CarryBorrowDefinitionSite8616, CarryBorrowDefinitionSite8616]] = []
    for site in sites:
        dst = site.instruction.dst
        if (
            site.instr_index <= flags_definition.instr_index
            or site.instruction.addr != flags_definition.instruction.addr
            or ir_op_8616(site.instruction) is not CarryBorrowIROp8616.MOV
            or dst is None
            or dst.space is not MemSpace.REG
            or dst.name == "flags"
        ):
            continue
        source = single_source_8616(site)
        arithmetic = None if source is None else definition_for_8616(source, definitions)
        if arithmetic is None or arithmetic_kind_8616(arithmetic.instruction) is not kind:
            continue
        if signatures and not any(
            same_operands_8616(site_value_args_8616(arithmetic), signature)
            for signature in signatures
        ):
            continue
        matches.append((site, arithmetic))
    return matches[0] if len(matches) == 1 else None


def _resolve_candidate(
    candidate: CarryBorrowDefinitionSite8616,
    use_block: CarryBorrowBlockSSA8616,
    blocks: tuple[CarryBorrowBlockSSA8616, ...],
    artifact: SSAFunctionArtifact,
) -> CarryBorrowResolution8616:
    definitions = use_block.definitions
    source = single_source_8616(candidate)
    final = None if source is None else definition_for_8616(source, definitions)
    if final is None:
        return _refusal(candidate, CarryBorrowFailure8616.TEMP_DEFINITION_MISSING)
    kind = arithmetic_kind_8616(final.instruction)
    final_args = site_value_args_8616(final)
    if kind is None or len(final_args) != 2:
        return _refusal(candidate, CarryBorrowFailure8616.AMBIGUOUS_BASE_OPERATION)
    base_choices = tuple(
        (index, definition)
        for index, value in enumerate(final_args)
        if (definition := definition_for_8616(value, definitions)) is not None
        and arithmetic_kind_8616(definition.instruction) is kind
    )
    if len(base_choices) != 1:
        return _refusal(candidate, CarryBorrowFailure8616.AMBIGUOUS_BASE_OPERATION)
    base_index, high_base = base_choices[0]
    carry_value = final_args[1 - base_index]
    chain = _carry_chain(carry_value, definitions)
    if isinstance(chain, CarryBorrowFailure8616):
        return _refusal(candidate, chain)
    flags_read, shift, mask, narrow, extend = chain
    flags_resolution = resolve_carry_flags_definition_8616(
        artifact,
        flags_read,
        use_block,
        blocks,
    )
    flags_owner = flags_resolution.definition
    if flags_owner is None:
        return _refusal(
            candidate,
            flags_resolution.failure or CarryBorrowFailure8616.FLAGS_DEFINITION_MISSING,
        )
    flags_definition = flags_owner.site
    low = _low_result(
        flags_definition,
        flags_owner.block.sites,
        flags_owner.block.definitions,
        kind,
    )
    if low is None:
        return _refusal(candidate, CarryBorrowFailure8616.LOW_RESULT_AMBIGUOUS)
    low_write, low_arithmetic = low
    low_args = site_value_args_8616(low_arithmetic)
    high_args = site_value_args_8616(high_base)
    if len(low_args) != 2 or len(high_args) != 2:
        return _refusal(candidate, CarryBorrowFailure8616.FLAGS_PROVENANCE_MISMATCH)
    operand_uses = tuple(
        operand_use_8616(
            value,
            flags_owner.block.definitions,
            artifact.logical_memory,
        )
        for value in low_args
    ) + tuple(
        operand_use_8616(value, definitions, artifact.logical_memory)
        for value in high_args
    )
    if any(item is None for item in operand_uses):
        return _refusal(candidate, CarryBorrowFailure8616.OPERAND_DEFINITION_MISSING)
    low_lhs, low_rhs, high_lhs, high_rhs = operand_uses
    assert low_lhs is not None and low_rhs is not None
    assert high_lhs is not None and high_rhs is not None
    link = CarryBorrowLink8616(
        function_addr=artifact.function_addr,
        kind=kind,
        low_result_write=low_write,
        low_arithmetic=low_arithmetic,
        low_lhs=low_lhs,
        low_rhs=low_rhs,
        flags_definition=flags_definition,
        flags_read=flags_read,
        carry_shift=shift,
        carry_mask=mask,
        carry_narrow=narrow,
        carry_extend=extend,
        high_base_arithmetic=high_base,
        high_final_arithmetic=final,
        high_result_write=candidate,
        high_lhs=high_lhs,
        high_rhs=high_rhs,
    )
    return CarryBorrowResolution8616(
        candidate=candidate,
        verdict=CarryBorrowVerdict8616.PROVEN,
        link=link,
    )


def _candidate_sites(
    sites: tuple[CarryBorrowDefinitionSite8616, ...],
    definitions: CarryBorrowDefinitions8616,
) -> tuple[CarryBorrowDefinitionSite8616, ...]:
    candidates: list[CarryBorrowDefinitionSite8616] = []
    for site in sites:
        dst = site.instruction.dst
        source = single_source_8616(site)
        final = None if source is None else definition_for_8616(source, definitions)
        if (
            dst is None
            or dst.space is not MemSpace.REG
            or dst.name == "flags"
            or final is None
            or arithmetic_kind_8616(final.instruction) is None
        ):
            continue
        args = site_value_args_8616(final)
        if len(args) == 2 and any(
            (base := definition_for_8616(value, definitions)) is not None
            and arithmetic_kind_8616(base.instruction) is arithmetic_kind_8616(final.instruction)
            for value in args
        ):
            candidates.append(site)
    return tuple(candidates)


def analyze_carry_borrow_links_8616(artifact: SSAFunctionArtifact) -> CarryBorrowEvidence8616:
    """Classify carry/borrow candidates from exact SSA and CFG definitions."""
    resolutions: list[CarryBorrowResolution8616] = []
    blocks = build_carry_borrow_block_ssa_8616(artifact)
    for block in blocks:
        for candidate in _candidate_sites(block.sites, block.definitions):
            resolutions.append(
                _resolve_candidate(candidate, block, blocks, artifact)
            )
    materialized = sum(item.link is not None for item in resolutions)
    failures = len(resolutions) - materialized
    stats = CarryBorrowStats8616(
        raw_fact_count=len(resolutions),
        normalized_fact_count=len(resolutions),
        classified_fact_count=materialized,
        materialized_count=materialized,
        failure_count=failures,
    )
    return CarryBorrowEvidence8616(
        function_addr=artifact.function_addr,
        resolutions=tuple(resolutions),
        stats=stats,
    )


__all__ = ["analyze_carry_borrow_links_8616"]
