"""Widening-layer exports.

Layer: Widening.
Responsibility: owns exports for alias-proven widening helpers.
Consumes alias-proven storage identity before joining values or propagating
widths.
Do not join values from rendered text, cosmetic shape, postprocess, or
CLI/reporting evidence.
"""

from __future__ import annotations

from .carry_borrow_pipeline import (
    CarryBorrowWideningPipeline8616,
    apply_carry_borrow_widening_pipeline_8616,
    build_carry_borrow_widening_pipeline_8616,
)
from .carry_borrow_storage import (
    WideCarryBorrowStorage8616,
    WideCarryBorrowStorageEvidence8616,
    WideCarryBorrowStorageFailure8616,
    WideCarryBorrowStorageVerdict8616,
    widen_carry_borrow_storage_8616,
)
from .carry_borrow_values import (
    WideCarryBorrowEvidence8616,
    WideCarryBorrowFailure8616,
    WideCarryBorrowValue8616,
    WideCarryBorrowVerdict8616,
    widen_carry_borrow_values_8616,
)
from .register_widening import (
    RegisterWideningCandidate,
    can_join_adjacent_register_slices,
    join_adjacent_register_slices,
)
from .stack_subview_projection import (
    materialize_contained_stack_subviews_8616,
)
from .stack_widening import (
    WIDENING_PIPELINE,
    StorageJoinAnalysis,
    StorageSubviewProof,
    WideningCandidate,
    WideningPipelineSpec,
    WideningProof,
    analyze_adjacent_storage_slices,
    can_join_adjacent_storage_slices,
    collect_widening_candidates,
    describe_widening_candidates,
    describe_x86_16_widening_pipeline,
    merge_storage_slice_domains,
    prove_adjacent_storage_slices,
    prove_contained_stack_subview,
)
from .word_projection_recomposition import (
    WordProjectionRecompositionStats8616,
    materialize_word_projection_recompositions_8616,
)

__all__ = [
    "WIDENING_PIPELINE",
    "CarryBorrowWideningPipeline8616",
    "RegisterWideningCandidate",
    "StorageJoinAnalysis",
    "StorageSubviewProof",
    "WideCarryBorrowEvidence8616",
    "WideCarryBorrowFailure8616",
    "WideCarryBorrowStorage8616",
    "WideCarryBorrowStorageEvidence8616",
    "WideCarryBorrowStorageFailure8616",
    "WideCarryBorrowStorageVerdict8616",
    "WideCarryBorrowValue8616",
    "WideCarryBorrowVerdict8616",
    "WideningCandidate",
    "WideningPipelineSpec",
    "WideningProof",
    "WordProjectionRecompositionStats8616",
    "analyze_adjacent_storage_slices",
    "apply_carry_borrow_widening_pipeline_8616",
    "build_carry_borrow_widening_pipeline_8616",
    "can_join_adjacent_register_slices",
    "can_join_adjacent_storage_slices",
    "collect_widening_candidates",
    "describe_widening_candidates",
    "describe_x86_16_widening_pipeline",
    "join_adjacent_register_slices",
    "materialize_contained_stack_subviews_8616",
    "materialize_word_projection_recompositions_8616",
    "merge_storage_slice_domains",
    "prove_adjacent_storage_slices",
    "prove_contained_stack_subview",
    "widen_carry_borrow_storage_8616",
    "widen_carry_borrow_values_8616",
]
