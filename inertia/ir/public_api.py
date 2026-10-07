"""IR-layer package exports.

Layer: IR.
Responsibility: owns typed Value, Address, Condition, instruction facts, and lossless
normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

# isort: off
# Publish core contracts before platform registration imports their consumers.
from .core import (
    AddressStatus as AddressStatus,
    IRAddress as IRAddress,
    IRBinaryValue as IRBinaryValue,
    IRBlock as IRBlock,
    IRCallOutputProvenance8616 as IRCallOutputProvenance8616,
    IRCallOutputShape8616 as IRCallOutputShape8616,
    IRCallStackEffect8616 as IRCallStackEffect8616,
    IRCondition as IRCondition,
    IRFunctionArtifact as IRFunctionArtifact,
    IRInstr as IRInstr,
    IRRefusal as IRRefusal,
    IRValue as IRValue,
    MemSpace as MemSpace,
    SegmentOrigin as SegmentOrigin,
)

# isort: on
from .indexed_address_contracts import (
    IndexedAddressAccessKind8616 as IndexedAddressAccessKind8616,
)
from .indexed_address_contracts import (
    IndexedAddressDefinitionSite8616 as IndexedAddressDefinitionSite8616,
)
from .indexed_address_contracts import (
    IndexedAddressEvidence8616 as IndexedAddressEvidence8616,
)
from .indexed_address_contracts import (
    IndexedAddressFact8616 as IndexedAddressFact8616,
)
from .indexed_address_contracts import (
    IndexedAddressFailureKind8616 as IndexedAddressFailureKind8616,
)
from .indexed_address_contracts import (
    IndexedAddressRefusal8616 as IndexedAddressRefusal8616,
)
from .indexed_address_contracts import (
    IndexedAddressStats8616 as IndexedAddressStats8616,
)
from .indexed_address_copy_contracts import (
    IndexedAddressCopyEvidence8616 as IndexedAddressCopyEvidence8616,
)
from .indexed_address_copy_contracts import (
    IndexedAddressCopyFact8616 as IndexedAddressCopyFact8616,
)
from .indexed_address_copy_contracts import (
    IndexedAddressCopyFailureKind8616 as IndexedAddressCopyFailureKind8616,
)
from .indexed_address_copy_contracts import (
    IndexedAddressCopyLane8616 as IndexedAddressCopyLane8616,
)
from .indexed_address_copy_contracts import (
    IndexedAddressCopyRefusal8616 as IndexedAddressCopyRefusal8616,
)
from .indexed_address_copy_contracts import (
    IndexedAddressCopyStats8616 as IndexedAddressCopyStats8616,
)
from .indexed_address_copy_contracts import (
    IndexedAddressCopyStep8616 as IndexedAddressCopyStep8616,
)
from .indexed_address_copy_contracts import (
    IndexedAddressCopyStepKind8616 as IndexedAddressCopyStepKind8616,
)
from .indexed_address_copy_contracts import (
    IndexedAddressCopyValuePath8616 as IndexedAddressCopyValuePath8616,
)
from .indexed_address_copy_evidence import (
    collect_indexed_address_copy_evidence_8616 as collect_indexed_address_copy_evidence_8616,
)
from .indexed_address_evidence import (
    collect_indexed_address_evidence_8616 as collect_indexed_address_evidence_8616,
)
from .logical_memory_capture import (
    IRLogicalMemoryCaptureCollection8616 as IRLogicalMemoryCaptureCollection8616,
)
from .logical_memory_capture import (
    IRLogicalMemoryCaptureRecord8616 as IRLogicalMemoryCaptureRecord8616,
)
from .logical_memory_contracts import (
    IRLogicalMemoryAccess8616 as IRLogicalMemoryAccess8616,
)
from .logical_memory_contracts import (
    IRLogicalMemoryAccessKey8616 as IRLogicalMemoryAccessKey8616,
)
from .logical_memory_contracts import (
    IRLogicalMemoryArtifact8616 as IRLogicalMemoryArtifact8616,
)
from .logical_memory_contracts import (
    IRLogicalMemoryFailureKind8616 as IRLogicalMemoryFailureKind8616,
)
from .logical_memory_contracts import (
    IRLogicalMemoryRefusal8616 as IRLogicalMemoryRefusal8616,
)
from .logical_memory_contracts import (
    IRLogicalMemoryStats8616 as IRLogicalMemoryStats8616,
)
from .logical_memory_contracts import (
    IRMemoryAccessKind8616 as IRMemoryAccessKind8616,
)
from .logical_memory_contracts import (
    IRMemoryExecutionSlice8616 as IRMemoryExecutionSlice8616,
)
from .logical_memory_resolution import (
    resolve_logical_memory_accesses_8616 as resolve_logical_memory_accesses_8616,
)
from .scalar_affine_contracts import (
    ScalarAffineExpression8616 as ScalarAffineExpression8616,
)
from .scalar_affine_contracts import (
    ScalarAffineFailure8616 as ScalarAffineFailure8616,
)
from .scalar_affine_contracts import (
    ScalarAffineTerm8616 as ScalarAffineTerm8616,
)
from .scalar_affine_contracts import (
    ScalarAffineTrace8616 as ScalarAffineTrace8616,
)
from .scalar_affine_contracts import (
    ScalarAffineTraceStats8616 as ScalarAffineTraceStats8616,
)
from .scalar_affine_trace import (
    trace_scalar_affine_expression_8616 as trace_scalar_affine_expression_8616,
)
from .segment_contract import (
    SegmentAccessFact as SegmentAccessFact,
)
from .segment_contract import (
    SegmentAccessKind as SegmentAccessKind,
)
from .segment_contract import (
    SegmentFactVerdict as SegmentFactVerdict,
)
from .segment_contract import (
    SegmentFunctionContract as SegmentFunctionContract,
)
from .segment_contract import (
    SegmentWriteFact as SegmentWriteFact,
)
from .segment_contract import (
    SegmentWriteKind as SegmentWriteKind,
)
from .segment_contract import (
    apply_x86_16_segment_function_contract as apply_x86_16_segment_function_contract,
)
from .segment_contract import (
    build_x86_16_segment_function_contract as build_x86_16_segment_function_contract,
)
from .segment_state import (
    SegmentRegisterState as SegmentRegisterState,
)
from .segment_state import (
    SegmentRestoreSource as SegmentRestoreSource,
)
from .segment_state import (
    SegmentStateArtifact as SegmentStateArtifact,
)
from .segment_state import (
    SegmentValueKind8616 as SegmentValueKind8616,
)
from .segment_state import (
    apply_x86_16_segment_state_artifact as apply_x86_16_segment_state_artifact,
)
from .segment_state import (
    build_x86_16_segment_state_artifact as build_x86_16_segment_state_artifact,
)
from .ssa import (
    SSABinding as SSABinding,
)
from .ssa import (
    SSABlock as SSABlock,
)
from .ssa import (
    build_x86_16_block_local_ssa as build_x86_16_block_local_ssa,
)
from .ssa_function import (
    SSAFunctionArtifact as SSAFunctionArtifact,
)
from .ssa_function import (
    SSAIncomingValue as SSAIncomingValue,
)
from .ssa_function import (
    SSAPhiNode as SSAPhiNode,
)
from .ssa_function import (
    build_x86_16_function_ssa as build_x86_16_function_ssa,
)
from .ssa_memory_contracts import (
    SSAFunctionMemoryResult8616 as SSAFunctionMemoryResult8616,
)
from .ssa_memory_contracts import (
    SSAMemoryAccess8616 as SSAMemoryAccess8616,
)
from .ssa_memory_contracts import (
    SSAMemoryAccessKind8616 as SSAMemoryAccessKind8616,
)
from .ssa_memory_contracts import (
    SSAMemoryAccessSlice8616 as SSAMemoryAccessSlice8616,
)
from .ssa_memory_contracts import (
    SSAMemoryBinding8616 as SSAMemoryBinding8616,
)
from .ssa_memory_contracts import (
    SSAMemoryIncomingValue8616 as SSAMemoryIncomingValue8616,
)
from .ssa_memory_contracts import (
    SSAMemoryOverlap8616 as SSAMemoryOverlap8616,
)
from .ssa_memory_contracts import (
    SSAMemoryOverlapRelation8616 as SSAMemoryOverlapRelation8616,
)
from .ssa_memory_contracts import (
    SSAMemoryPhiNode8616 as SSAMemoryPhiNode8616,
)
from .ssa_memory_contracts import (
    SSAMemoryStats8616 as SSAMemoryStats8616,
)
from .string_effects import (
    IRStringEffectArtifact as IRStringEffectArtifact,
)
from .string_effects import (
    IRStringEffectRecord as IRStringEffectRecord,
)
from .string_effects import (
    apply_x86_16_typed_string_effect_artifact as apply_x86_16_typed_string_effect_artifact,
)
from .string_effects import (
    build_x86_16_typed_string_effect_artifact as build_x86_16_typed_string_effect_artifact,
)
from .vex_import import (
    apply_x86_16_vex_ir_artifact as apply_x86_16_vex_ir_artifact,
)
from .vex_import import (
    build_x86_16_ir_function_artifact as build_x86_16_ir_function_artifact,
)
from .vex_import import (
    build_x86_16_ir_function_artifact_summary as build_x86_16_ir_function_artifact_summary,
)

