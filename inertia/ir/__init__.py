"""IR-layer public exports.

Layer: IR.
Responsibility: expose existing typed IR contracts while keeping pure helper
imports independent of platform registration and decompiler initialization.

Package ownership contract (canonical inertia/ir package):
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite,
postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from .source_graph_import import install_source_graph_import
lazy from .public_api import (
    AddressStatus as AddressStatus,
)
lazy from .public_api import (
    IndexedAddressAccessKind8616 as IndexedAddressAccessKind8616,
)
lazy from .public_api import (
    IndexedAddressCopyEvidence8616 as IndexedAddressCopyEvidence8616,
)
lazy from .public_api import (
    IndexedAddressCopyFact8616 as IndexedAddressCopyFact8616,
)
lazy from .public_api import (
    IndexedAddressCopyFailureKind8616 as IndexedAddressCopyFailureKind8616,
)
lazy from .public_api import (
    IndexedAddressCopyLane8616 as IndexedAddressCopyLane8616,
)
lazy from .public_api import (
    IndexedAddressCopyRefusal8616 as IndexedAddressCopyRefusal8616,
)
lazy from .public_api import (
    IndexedAddressCopyStats8616 as IndexedAddressCopyStats8616,
)
lazy from .public_api import (
    IndexedAddressCopyStep8616 as IndexedAddressCopyStep8616,
)
lazy from .public_api import (
    IndexedAddressCopyStepKind8616 as IndexedAddressCopyStepKind8616,
)
lazy from .public_api import (
    IndexedAddressCopyValuePath8616 as IndexedAddressCopyValuePath8616,
)
lazy from .public_api import (
    IndexedAddressDefinitionSite8616 as IndexedAddressDefinitionSite8616,
)
lazy from .public_api import (
    IndexedAddressEvidence8616 as IndexedAddressEvidence8616,
)
lazy from .public_api import (
    IndexedAddressFact8616 as IndexedAddressFact8616,
)
lazy from .public_api import (
    IndexedAddressFailureKind8616 as IndexedAddressFailureKind8616,
)
lazy from .public_api import (
    IndexedAddressRefusal8616 as IndexedAddressRefusal8616,
)
lazy from .public_api import (
    IndexedAddressStats8616 as IndexedAddressStats8616,
)
lazy from .public_api import (
    IRAddress as IRAddress,
)
lazy from .public_api import (
    IRBinaryValue as IRBinaryValue,
)
lazy from .public_api import (
    IRBlock as IRBlock,
)
lazy from .public_api import (
    IRCallOutputProvenance8616 as IRCallOutputProvenance8616,
)
lazy from .public_api import (
    IRCallOutputShape8616 as IRCallOutputShape8616,
)
lazy from .public_api import (
    IRCallStackEffect8616 as IRCallStackEffect8616,
)
lazy from .public_api import (
    IRCondition as IRCondition,
)
lazy from .public_api import (
    IRFunctionArtifact as IRFunctionArtifact,
)
lazy from .public_api import (
    IRInstr as IRInstr,
)
lazy from .public_api import (
    IRLogicalMemoryAccess8616 as IRLogicalMemoryAccess8616,
)
lazy from .public_api import (
    IRLogicalMemoryAccessKey8616 as IRLogicalMemoryAccessKey8616,
)
lazy from .public_api import (
    IRLogicalMemoryArtifact8616 as IRLogicalMemoryArtifact8616,
)
lazy from .public_api import (
    IRLogicalMemoryCaptureCollection8616 as IRLogicalMemoryCaptureCollection8616,
)
lazy from .public_api import (
    IRLogicalMemoryCaptureRecord8616 as IRLogicalMemoryCaptureRecord8616,
)
lazy from .public_api import (
    IRLogicalMemoryFailureKind8616 as IRLogicalMemoryFailureKind8616,
)
lazy from .public_api import (
    IRLogicalMemoryRefusal8616 as IRLogicalMemoryRefusal8616,
)
lazy from .public_api import (
    IRLogicalMemoryStats8616 as IRLogicalMemoryStats8616,
)
lazy from .public_api import (
    IRMemoryAccessKind8616 as IRMemoryAccessKind8616,
)
lazy from .public_api import (
    IRMemoryExecutionSlice8616 as IRMemoryExecutionSlice8616,
)
lazy from .public_api import (
    IRRefusal as IRRefusal,
)
lazy from .public_api import (
    IRStringEffectArtifact as IRStringEffectArtifact,
)
lazy from .public_api import (
    IRStringEffectRecord as IRStringEffectRecord,
)
lazy from .public_api import (
    IRValue as IRValue,
)
lazy from .public_api import (
    MemSpace as MemSpace,
)
lazy from .public_api import (
    ScalarAffineExpression8616 as ScalarAffineExpression8616,
)
lazy from .public_api import (
    ScalarAffineFailure8616 as ScalarAffineFailure8616,
)
lazy from .public_api import (
    ScalarAffineTerm8616 as ScalarAffineTerm8616,
)
lazy from .public_api import (
    ScalarAffineTrace8616 as ScalarAffineTrace8616,
)
lazy from .public_api import (
    ScalarAffineTraceStats8616 as ScalarAffineTraceStats8616,
)
lazy from .public_api import (
    SegmentAccessFact as SegmentAccessFact,
)
lazy from .public_api import (
    SegmentAccessKind as SegmentAccessKind,
)
lazy from .public_api import (
    SegmentFactVerdict as SegmentFactVerdict,
)
lazy from .public_api import (
    SegmentFunctionContract as SegmentFunctionContract,
)
lazy from .public_api import (
    SegmentOrigin as SegmentOrigin,
)
lazy from .public_api import (
    SegmentRegisterState as SegmentRegisterState,
)
lazy from .public_api import (
    SegmentRestoreSource as SegmentRestoreSource,
)
lazy from .public_api import (
    SegmentStateArtifact as SegmentStateArtifact,
)
lazy from .public_api import (
    SegmentValueKind8616 as SegmentValueKind8616,
)
lazy from .public_api import (
    SegmentWriteFact as SegmentWriteFact,
)
lazy from .public_api import (
    SegmentWriteKind as SegmentWriteKind,
)
lazy from .public_api import (
    SSABinding as SSABinding,
)
lazy from .public_api import (
    SSABlock as SSABlock,
)
lazy from .public_api import (
    SSAFunctionArtifact as SSAFunctionArtifact,
)
lazy from .public_api import (
    SSAFunctionMemoryResult8616 as SSAFunctionMemoryResult8616,
)
lazy from .public_api import (
    SSAIncomingValue as SSAIncomingValue,
)
lazy from .public_api import (
    SSAMemoryAccess8616 as SSAMemoryAccess8616,
)
lazy from .public_api import (
    SSAMemoryAccessKind8616 as SSAMemoryAccessKind8616,
)
lazy from .public_api import (
    SSAMemoryAccessSlice8616 as SSAMemoryAccessSlice8616,
)
lazy from .public_api import (
    SSAMemoryBinding8616 as SSAMemoryBinding8616,
)
lazy from .public_api import (
    SSAMemoryIncomingValue8616 as SSAMemoryIncomingValue8616,
)
lazy from .public_api import (
    SSAMemoryOverlap8616 as SSAMemoryOverlap8616,
)
lazy from .public_api import (
    SSAMemoryOverlapRelation8616 as SSAMemoryOverlapRelation8616,
)
lazy from .public_api import (
    SSAMemoryPhiNode8616 as SSAMemoryPhiNode8616,
)
lazy from .public_api import (
    SSAMemoryStats8616 as SSAMemoryStats8616,
)
lazy from .public_api import (
    SSAPhiNode as SSAPhiNode,
)
lazy from .public_api import (
    apply_x86_16_segment_function_contract as apply_x86_16_segment_function_contract,
)
lazy from .public_api import (
    apply_x86_16_segment_state_artifact as apply_x86_16_segment_state_artifact,
)
lazy from .public_api import (
    apply_x86_16_typed_string_effect_artifact as apply_x86_16_typed_string_effect_artifact,
)
lazy from .public_api import (
    apply_x86_16_vex_ir_artifact as apply_x86_16_vex_ir_artifact,
)
lazy from .public_api import (
    build_x86_16_block_local_ssa as build_x86_16_block_local_ssa,
)
lazy from .public_api import (
    build_x86_16_function_ssa as build_x86_16_function_ssa,
)
lazy from .public_api import (
    build_x86_16_ir_function_artifact as build_x86_16_ir_function_artifact,
)
lazy from .public_api import (
    build_x86_16_ir_function_artifact_summary as build_x86_16_ir_function_artifact_summary,
)
lazy from .public_api import (
    build_x86_16_segment_function_contract as build_x86_16_segment_function_contract,
)
lazy from .public_api import (
    build_x86_16_segment_state_artifact as build_x86_16_segment_state_artifact,
)
lazy from .public_api import (
    build_x86_16_typed_string_effect_artifact as build_x86_16_typed_string_effect_artifact,
)
lazy from .public_api import (
    collect_indexed_address_copy_evidence_8616 as collect_indexed_address_copy_evidence_8616,
)
lazy from .public_api import (
    collect_indexed_address_evidence_8616 as collect_indexed_address_evidence_8616,
)
lazy from .public_api import (
    resolve_logical_memory_accesses_8616 as resolve_logical_memory_accesses_8616,
)
lazy from .public_api import (
    trace_scalar_affine_expression_8616 as trace_scalar_affine_expression_8616,
)

install_source_graph_import()

__all__: list[str] = ['AddressStatus', 'IRAddress', 'IRBinaryValue', 'IRBlock', 'IRCallOutputProvenance8616', 'IRCallOutputShape8616', 'IRCallStackEffect8616', 'IRCondition', 'IRFunctionArtifact', 'IRInstr', 'IRLogicalMemoryAccess8616', 'IRLogicalMemoryAccessKey8616', 'IRLogicalMemoryArtifact8616', 'IRLogicalMemoryCaptureCollection8616', 'IRLogicalMemoryCaptureRecord8616', 'IRLogicalMemoryFailureKind8616', 'IRLogicalMemoryRefusal8616', 'IRLogicalMemoryStats8616', 'IRMemoryAccessKind8616', 'IRMemoryExecutionSlice8616', 'IRRefusal', 'IRStringEffectArtifact', 'IRStringEffectRecord', 'IRValue', 'IndexedAddressAccessKind8616', 'IndexedAddressCopyEvidence8616', 'IndexedAddressCopyFact8616', 'IndexedAddressCopyFailureKind8616', 'IndexedAddressCopyLane8616', 'IndexedAddressCopyRefusal8616', 'IndexedAddressCopyStats8616', 'IndexedAddressCopyStep8616', 'IndexedAddressCopyStepKind8616', 'IndexedAddressCopyValuePath8616', 'IndexedAddressDefinitionSite8616', 'IndexedAddressEvidence8616', 'IndexedAddressFact8616', 'IndexedAddressFailureKind8616', 'IndexedAddressRefusal8616', 'IndexedAddressStats8616', 'MemSpace', 'SSABinding', 'SSABlock', 'SSAFunctionArtifact', 'SSAFunctionMemoryResult8616', 'SSAIncomingValue', 'SSAMemoryAccess8616', 'SSAMemoryAccessKind8616', 'SSAMemoryAccessSlice8616', 'SSAMemoryBinding8616', 'SSAMemoryIncomingValue8616', 'SSAMemoryOverlap8616', 'SSAMemoryOverlapRelation8616', 'SSAMemoryPhiNode8616', 'SSAMemoryStats8616', 'SSAPhiNode', 'ScalarAffineExpression8616', 'ScalarAffineFailure8616', 'ScalarAffineTerm8616', 'ScalarAffineTrace8616', 'ScalarAffineTraceStats8616', 'SegmentAccessFact', 'SegmentAccessKind', 'SegmentFactVerdict', 'SegmentFunctionContract', 'SegmentOrigin', 'SegmentRegisterState', 'SegmentRestoreSource', 'SegmentStateArtifact', 'SegmentValueKind8616', 'SegmentWriteFact', 'SegmentWriteKind', 'apply_x86_16_segment_function_contract', 'apply_x86_16_segment_state_artifact', 'apply_x86_16_typed_string_effect_artifact', 'apply_x86_16_vex_ir_artifact', 'build_x86_16_block_local_ssa', 'build_x86_16_function_ssa', 'build_x86_16_ir_function_artifact', 'build_x86_16_ir_function_artifact_summary', 'build_x86_16_segment_function_contract', 'build_x86_16_segment_state_artifact', 'build_x86_16_typed_string_effect_artifact', 'collect_indexed_address_copy_evidence_8616', 'collect_indexed_address_evidence_8616', 'resolve_logical_memory_accesses_8616', 'trace_scalar_affine_expression_8616']
