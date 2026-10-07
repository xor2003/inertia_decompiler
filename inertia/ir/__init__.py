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

from typing import TYPE_CHECKING

__all__: list[str] = ['AddressStatus', 'IRAddress', 'IRBinaryValue', 'IRBlock', 'IRCallOutputProvenance8616', 'IRCallOutputShape8616', 'IRCallStackEffect8616', 'IRCondition', 'IRFunctionArtifact', 'IRInstr', 'IRLogicalMemoryAccess8616', 'IRLogicalMemoryAccessKey8616', 'IRLogicalMemoryArtifact8616', 'IRLogicalMemoryCaptureCollection8616', 'IRLogicalMemoryCaptureRecord8616', 'IRLogicalMemoryFailureKind8616', 'IRLogicalMemoryRefusal8616', 'IRLogicalMemoryStats8616', 'IRMemoryAccessKind8616', 'IRMemoryExecutionSlice8616', 'IRRefusal', 'IRStringEffectArtifact', 'IRStringEffectRecord', 'IRValue', 'IndexedAddressAccessKind8616', 'IndexedAddressCopyEvidence8616', 'IndexedAddressCopyFact8616', 'IndexedAddressCopyFailureKind8616', 'IndexedAddressCopyLane8616', 'IndexedAddressCopyRefusal8616', 'IndexedAddressCopyStats8616', 'IndexedAddressCopyStep8616', 'IndexedAddressCopyStepKind8616', 'IndexedAddressCopyValuePath8616', 'IndexedAddressDefinitionSite8616', 'IndexedAddressEvidence8616', 'IndexedAddressFact8616', 'IndexedAddressFailureKind8616', 'IndexedAddressRefusal8616', 'IndexedAddressStats8616', 'MemSpace', 'SSABinding', 'SSABlock', 'SSAFunctionArtifact', 'SSAFunctionMemoryResult8616', 'SSAIncomingValue', 'SSAMemoryAccess8616', 'SSAMemoryAccessKind8616', 'SSAMemoryAccessSlice8616', 'SSAMemoryBinding8616', 'SSAMemoryIncomingValue8616', 'SSAMemoryOverlap8616', 'SSAMemoryOverlapRelation8616', 'SSAMemoryPhiNode8616', 'SSAMemoryStats8616', 'SSAPhiNode', 'ScalarAffineExpression8616', 'ScalarAffineFailure8616', 'ScalarAffineTerm8616', 'ScalarAffineTrace8616', 'ScalarAffineTraceStats8616', 'SegmentAccessFact', 'SegmentAccessKind', 'SegmentFactVerdict', 'SegmentFunctionContract', 'SegmentOrigin', 'SegmentRegisterState', 'SegmentRestoreSource', 'SegmentStateArtifact', 'SegmentValueKind8616', 'SegmentWriteFact', 'SegmentWriteKind', 'apply_x86_16_segment_function_contract', 'apply_x86_16_segment_state_artifact', 'apply_x86_16_typed_string_effect_artifact', 'apply_x86_16_vex_ir_artifact', 'build_x86_16_block_local_ssa', 'build_x86_16_function_ssa', 'build_x86_16_ir_function_artifact', 'build_x86_16_ir_function_artifact_summary', 'build_x86_16_segment_function_contract', 'build_x86_16_segment_state_artifact', 'build_x86_16_typed_string_effect_artifact', 'collect_indexed_address_copy_evidence_8616', 'collect_indexed_address_evidence_8616', 'resolve_logical_memory_accesses_8616', 'trace_scalar_affine_expression_8616']

if TYPE_CHECKING:
    from .public_api import (
        AddressStatus as AddressStatus,
    )
    from .public_api import (
        IndexedAddressAccessKind8616 as IndexedAddressAccessKind8616,
    )
    from .public_api import (
        IndexedAddressCopyEvidence8616 as IndexedAddressCopyEvidence8616,
    )
    from .public_api import (
        IndexedAddressCopyFact8616 as IndexedAddressCopyFact8616,
    )
    from .public_api import (
        IndexedAddressCopyFailureKind8616 as IndexedAddressCopyFailureKind8616,
    )
    from .public_api import (
        IndexedAddressCopyLane8616 as IndexedAddressCopyLane8616,
    )
    from .public_api import (
        IndexedAddressCopyRefusal8616 as IndexedAddressCopyRefusal8616,
    )
    from .public_api import (
        IndexedAddressCopyStats8616 as IndexedAddressCopyStats8616,
    )
    from .public_api import (
        IndexedAddressCopyStep8616 as IndexedAddressCopyStep8616,
    )
    from .public_api import (
        IndexedAddressCopyStepKind8616 as IndexedAddressCopyStepKind8616,
    )
    from .public_api import (
        IndexedAddressCopyValuePath8616 as IndexedAddressCopyValuePath8616,
    )
    from .public_api import (
        IndexedAddressDefinitionSite8616 as IndexedAddressDefinitionSite8616,
    )
    from .public_api import (
        IndexedAddressEvidence8616 as IndexedAddressEvidence8616,
    )
    from .public_api import (
        IndexedAddressFact8616 as IndexedAddressFact8616,
    )
    from .public_api import (
        IndexedAddressFailureKind8616 as IndexedAddressFailureKind8616,
    )
    from .public_api import (
        IndexedAddressRefusal8616 as IndexedAddressRefusal8616,
    )
    from .public_api import (
        IndexedAddressStats8616 as IndexedAddressStats8616,
    )
    from .public_api import (
        IRAddress as IRAddress,
    )
    from .public_api import (
        IRBinaryValue as IRBinaryValue,
    )
    from .public_api import (
        IRBlock as IRBlock,
    )
    from .public_api import (
        IRCallOutputProvenance8616 as IRCallOutputProvenance8616,
    )
    from .public_api import (
        IRCallOutputShape8616 as IRCallOutputShape8616,
    )
    from .public_api import (
        IRCallStackEffect8616 as IRCallStackEffect8616,
    )
    from .public_api import (
        IRCondition as IRCondition,
    )
    from .public_api import (
        IRFunctionArtifact as IRFunctionArtifact,
    )
    from .public_api import (
        IRInstr as IRInstr,
    )
    from .public_api import (
        IRLogicalMemoryAccess8616 as IRLogicalMemoryAccess8616,
    )
    from .public_api import (
        IRLogicalMemoryAccessKey8616 as IRLogicalMemoryAccessKey8616,
    )
    from .public_api import (
        IRLogicalMemoryArtifact8616 as IRLogicalMemoryArtifact8616,
    )
    from .public_api import (
        IRLogicalMemoryCaptureCollection8616 as IRLogicalMemoryCaptureCollection8616,
    )
    from .public_api import (
        IRLogicalMemoryCaptureRecord8616 as IRLogicalMemoryCaptureRecord8616,
    )
    from .public_api import (
        IRLogicalMemoryFailureKind8616 as IRLogicalMemoryFailureKind8616,
    )
    from .public_api import (
        IRLogicalMemoryRefusal8616 as IRLogicalMemoryRefusal8616,
    )
    from .public_api import (
        IRLogicalMemoryStats8616 as IRLogicalMemoryStats8616,
    )
    from .public_api import (
        IRMemoryAccessKind8616 as IRMemoryAccessKind8616,
    )
    from .public_api import (
        IRMemoryExecutionSlice8616 as IRMemoryExecutionSlice8616,
    )
    from .public_api import (
        IRRefusal as IRRefusal,
    )
    from .public_api import (
        IRStringEffectArtifact as IRStringEffectArtifact,
    )
    from .public_api import (
        IRStringEffectRecord as IRStringEffectRecord,
    )
    from .public_api import (
        IRValue as IRValue,
    )
    from .public_api import (
        MemSpace as MemSpace,
    )
    from .public_api import (
        ScalarAffineExpression8616 as ScalarAffineExpression8616,
    )
    from .public_api import (
        ScalarAffineFailure8616 as ScalarAffineFailure8616,
    )
    from .public_api import (
        ScalarAffineTerm8616 as ScalarAffineTerm8616,
    )
    from .public_api import (
        ScalarAffineTrace8616 as ScalarAffineTrace8616,
    )
    from .public_api import (
        ScalarAffineTraceStats8616 as ScalarAffineTraceStats8616,
    )
    from .public_api import (
        SegmentAccessFact as SegmentAccessFact,
    )
    from .public_api import (
        SegmentAccessKind as SegmentAccessKind,
    )
    from .public_api import (
        SegmentFactVerdict as SegmentFactVerdict,
    )
    from .public_api import (
        SegmentFunctionContract as SegmentFunctionContract,
    )
    from .public_api import (
        SegmentOrigin as SegmentOrigin,
    )
    from .public_api import (
        SegmentRegisterState as SegmentRegisterState,
    )
    from .public_api import (
        SegmentRestoreSource as SegmentRestoreSource,
    )
    from .public_api import (
        SegmentStateArtifact as SegmentStateArtifact,
    )
    from .public_api import (
        SegmentValueKind8616 as SegmentValueKind8616,
    )
    from .public_api import (
        SegmentWriteFact as SegmentWriteFact,
    )
    from .public_api import (
        SegmentWriteKind as SegmentWriteKind,
    )
    from .public_api import (
        SSABinding as SSABinding,
    )
    from .public_api import (
        SSABlock as SSABlock,
    )
    from .public_api import (
        SSAFunctionArtifact as SSAFunctionArtifact,
    )
    from .public_api import (
        SSAFunctionMemoryResult8616 as SSAFunctionMemoryResult8616,
    )
    from .public_api import (
        SSAIncomingValue as SSAIncomingValue,
    )
    from .public_api import (
        SSAMemoryAccess8616 as SSAMemoryAccess8616,
    )
    from .public_api import (
        SSAMemoryAccessKind8616 as SSAMemoryAccessKind8616,
    )
    from .public_api import (
        SSAMemoryAccessSlice8616 as SSAMemoryAccessSlice8616,
    )
    from .public_api import (
        SSAMemoryBinding8616 as SSAMemoryBinding8616,
    )
    from .public_api import (
        SSAMemoryIncomingValue8616 as SSAMemoryIncomingValue8616,
    )
    from .public_api import (
        SSAMemoryOverlap8616 as SSAMemoryOverlap8616,
    )
    from .public_api import (
        SSAMemoryOverlapRelation8616 as SSAMemoryOverlapRelation8616,
    )
    from .public_api import (
        SSAMemoryPhiNode8616 as SSAMemoryPhiNode8616,
    )
    from .public_api import (
        SSAMemoryStats8616 as SSAMemoryStats8616,
    )
    from .public_api import (
        SSAPhiNode as SSAPhiNode,
    )
    from .public_api import (
        apply_x86_16_segment_function_contract as apply_x86_16_segment_function_contract,
    )
    from .public_api import (
        apply_x86_16_segment_state_artifact as apply_x86_16_segment_state_artifact,
    )
    from .public_api import (
        apply_x86_16_typed_string_effect_artifact as apply_x86_16_typed_string_effect_artifact,
    )
    from .public_api import (
        apply_x86_16_vex_ir_artifact as apply_x86_16_vex_ir_artifact,
    )
    from .public_api import (
        build_x86_16_block_local_ssa as build_x86_16_block_local_ssa,
    )
    from .public_api import (
        build_x86_16_function_ssa as build_x86_16_function_ssa,
    )
    from .public_api import (
        build_x86_16_ir_function_artifact as build_x86_16_ir_function_artifact,
    )
    from .public_api import (
        build_x86_16_ir_function_artifact_summary as build_x86_16_ir_function_artifact_summary,
    )
    from .public_api import (
        build_x86_16_segment_function_contract as build_x86_16_segment_function_contract,
    )
    from .public_api import (
        build_x86_16_segment_state_artifact as build_x86_16_segment_state_artifact,
    )
    from .public_api import (
        build_x86_16_typed_string_effect_artifact as build_x86_16_typed_string_effect_artifact,
    )
    from .public_api import (
        collect_indexed_address_copy_evidence_8616 as collect_indexed_address_copy_evidence_8616,
    )
    from .public_api import (
        collect_indexed_address_evidence_8616 as collect_indexed_address_evidence_8616,
    )
    from .public_api import (
        resolve_logical_memory_accesses_8616 as resolve_logical_memory_accesses_8616,
    )
    from .public_api import (
        trace_scalar_affine_expression_8616 as trace_scalar_affine_expression_8616,
    )

def __getattr__(name: str) -> object:
    """Load the established IR exports only when an exported name is requested."""
    if name not in __all__:
        raise AttributeError(name)
    import inertia.ir.public_api as public_api

    # Python's public module attribute protocol supplies this symbolic name;
    # the static imports above preserve typing and the implementation identities.
    return public_api.__dict__[name]
