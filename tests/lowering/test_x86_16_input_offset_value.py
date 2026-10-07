"""Real IR/SSA tests for numeric 16-bit input-offset Value preservation."""

from __future__ import annotations

from dataclasses import replace

from inertia.semantics.callsite_summary import (
    CallsitePushSourceKind8616,
    CallsiteSummary8616,
)
from inertia.ir import (
    AddressStatus,
    IRAddress,
    MemSpace,
    ScalarAffineFailure8616,
    SegmentOrigin,
)
from inertia.ir.scalar_affine_contracts import (
    ScalarAffineEntryRegister8616,
)
from inertia.ir.ssa_function import (
    SSAFunctionArtifact,
)
from inertia.frontend.x86_16.lift_86_16 import Lifter86_16  # noqa: F401
from inertia.lowering.input_offset_value import (
    InputOffsetValue8616,
    InputOffsetValueFailure8616,
    InputOffsetValueStats8616,
    collect_input_offset_value_8616,
)
from inertia.lowering.interprocedural_storage_contracts import (
    StorageReachingDefinition8616,
    StorageUseEvidence8616,
)
from inertia.lowering.interprocedural_storage_logical_input_contracts import (
    LogicalInputRootBinding8616,
    LogicalPushValue8616,
)
from inertia.lowering.interprocedural_storage_physical_defs import (
    logical_push_value_8616,
)
from inertia.lowering.interprocedural_storage_reaching_contracts import (
    PhysicalCallArgumentPiece8616,
    SSAInstructionSite8616,
)
from inertia.lowering.interprocedural_storage_reaching_defs import (
    CallArgumentDefinitionVerdict8616,
    resolve_call_argument_reaching_definition_8616,
)
from tests.lowering.x86_16_native_call_fixtures import NativeCallFixture8616, lift_native_call_fixture_8616


def _lift_ssa(code: bytes) -> SSAFunctionArtifact:
    """Return raw SSA while retaining native CALL effects and exact bounds."""
    return lift_native_call_fixture_8616(code).ssa


def _sites(ssa: SSAFunctionArtifact) -> tuple[SSAInstructionSite8616, ...]:
    return tuple(
        SSAInstructionSite8616(block, instr_index, instr)
        for block in ssa.blocks
        for instr_index, instr in enumerate(block.instrs)
    )


def _call_use(
    sites: tuple[SSAInstructionSite8616, ...], callsite_addr: int, fixture: NativeCallFixture8616
) -> tuple[StorageUseEvidence8616, int]:
    calls = tuple(
        site
        for site in sites
        if site.instr.op == "CALL" and site.instr.addr == callsite_addr
    )
    assert len(calls) == 1
    site = calls[0]
    assert site.instr.addr is not None
    target_addr = fixture.proven_target(callsite_addr)
    use = StorageUseEvidence8616(
        block_addr=site.block.addr,
        instr_index=site.instr_index,
        instr_addr=site.instr.addr,
        callsite_addr=site.instr.addr,
    )
    return use, target_addr


def _slice_definition(
    logical: LogicalPushValue8616, push_addr: int, slice_index: int
) -> StorageReachingDefinition8616:
    item = logical.slices[slice_index]
    return StorageReachingDefinition8616(
        value=item.value,
        block_addr=item.site.block.addr,
        instr_index=item.site.instr_index,
        instr_addr=push_addr,
        source_storage=None,
        logical_push=logical,
    )


def _piece_binding(
    ssa: SSAFunctionArtifact,
    use: StorageUseEvidence8616,
    callee_addr: int,
    logical: LogicalPushValue8616,
    push_addr: int,
    piece_index: int,
    *,
    argument_size: int = 2,
) -> LogicalInputRootBinding8616:
    storage = IRAddress(
        space=MemSpace.SS,
        base=("bp",),
        offset=4,
        size=argument_size,
        status=AddressStatus.STABLE,
        segment_origin=SegmentOrigin.PROVEN,
    )
    item = logical.slices[piece_index]
    return LogicalInputRootBinding8616(
        callee_addr=callee_addr,
        caller_addr=ssa.function_addr,
        callsite_addr=use.callsite_addr,
        logical_index=0,
        piece_index=piece_index,
        piece_count=len(logical.slices),
        push_addr=push_addr,
        source_offset=item.source_offset,
        argument_offset=item.source_offset,
        byte_width=item.address.size,
        argument_storage=storage,
        logical_push=logical,
        call_use=use,
    )


def _bound_piece(
    code: bytes,
    push_addr: int,
    callsite_addr: int,
    *,
    piece_index: int = 0,
    argument_size: int = 2,
) -> tuple[
    SSAFunctionArtifact,
    LogicalInputRootBinding8616,
    StorageReachingDefinition8616,
    StorageUseEvidence8616,
]:
    """Bind one real lifted PUSH to an exact piece definition and CALL use."""
    fixture = lift_native_call_fixture_8616(code)
    ssa = fixture.ssa
    sites = _sites(ssa)
    piece = PhysicalCallArgumentPiece8616(width=2, source=(), push_addr=push_addr)
    logical, failure = logical_push_value_8616(sites, piece)
    assert failure is None and logical is not None and logical.complete
    use, callee_addr = _call_use(sites, callsite_addr, fixture)
    definition = _slice_definition(logical, push_addr, piece_index)
    binding = _piece_binding(
        ssa, use, callee_addr, logical, push_addr, piece_index,
        argument_size=argument_size,
    )
    assert binding.complete
    return ssa, binding, definition, use


def test_immediate_push_preserves_exact_numeric_root() -> None:
    ssa, binding, definition, use = _bound_piece(
        bytes.fromhex("6a05e80000"), push_addr=0x1000, callsite_addr=0x1002
    )

    result = collect_input_offset_value_8616(
        binding, artifact=ssa, definition=definition, use=use
    )

    assert result.complete
    assert result.failure is None
    assert result.stats.complete
    assert result.value is binding.root
    assert result.value is not None and result.value.const == 5
    assert result.trace is not None and result.trace.complete
    assert result.expression is result.trace.expression
    assert result.expression is not None
    assert result.expression.constant == 5
    assert result.expression.terms == ()


def test_every_push_piece_preserves_the_same_numeric_root() -> None:
    ssa, binding, _definition, use = _bound_piece(
        bytes.fromhex("8d46fc50e80000"), push_addr=0x1003, callsite_addr=0x1004
    )
    logical = binding.logical_push
    results = []
    for piece_index in range(len(logical.slices)):
        piece_binding = _piece_binding(
            ssa, use, binding.callee_addr, logical, binding.push_addr, piece_index
        )
        piece_definition = _slice_definition(logical, binding.push_addr, piece_index)
        results.append(
            collect_input_offset_value_8616(
                piece_binding, artifact=ssa, definition=piece_definition, use=use
            )
        )
    assert all(result.complete for result in results)
    assert all(result.value is binding.root for result in results)


def test_bp_address_input_recovers_numeric_affine_evidence() -> None:
    """A BP_ADDRESS push keeps only definitions upstream; the binding adds value."""
    fixture = lift_native_call_fixture_8616(bytes.fromhex("8d46fc50e80000"))
    ssa = fixture.ssa
    summary = CallsiteSummary8616(
        callsite_addr=0x1004,
        target_addr=0x1007,
        return_addr=0x1007,
        kind="near",
        arg_count=1,
        arg_widths=(2,),
        stack_cleanup=2,
        return_register=None,
        return_used=None,
        push_arg_sources=((CallsitePushSourceKind8616.BP_ADDRESS.value, -4),),
        push_arg_instruction_addrs=(0x1003,),
    )
    reaching = resolve_call_argument_reaching_definition_8616(
        ssa, summary, 0, project=fixture.project, callsite_index=fixture.index,
    )
    assert reaching.verdict is CallArgumentDefinitionVerdict8616.PROVEN
    assert reaching.affine_expression is None
    assert reaching.use is not None
    piece_definition = next(
        item
        for item in reaching.definitions
        if item.logical_push is not None
        and (item_slice := item.logical_push.definition_slice(item)) is not None
        and item_slice.source_offset == 0
    )
    logical = piece_definition.logical_push
    assert logical is not None
    binding = _piece_binding(
        ssa, reaching.use, 0x1007, logical, 0x1003, 0
    )

    result = collect_input_offset_value_8616(
        binding, artifact=ssa, definition=piece_definition, use=reaching.use
    )

    assert result.complete
    expression = result.expression
    assert expression is not None and expression.width == 2
    assert expression.constant == 0xFFFC
    assert len(expression.terms) == 1
    term = expression.terms[0]
    assert isinstance(term.source, ScalarAffineEntryRegister8616)
    assert term.source.register_name == "bp" and term.coefficient == 1


def test_loaded_scalar_push_stays_numeric_only() -> None:
    """A proven stack-load scalar is preserved as a numeric affine term."""
    ssa, binding, definition, use = _bound_piece(
        bytes.fromhex("8b460450e80000"), push_addr=0x1003, callsite_addr=0x1004
    )

    result = collect_input_offset_value_8616(
        binding, artifact=ssa, definition=definition, use=use
    )

    assert result.complete
    expression = result.expression
    assert expression is not None and expression.width == 2
    assert expression.constant == 0
    assert len(expression.terms) == 1
    term = expression.terms[0]
    assert isinstance(term.source, IRAddress)
    assert (
        term.source.space is MemSpace.SS
        and term.source.base == ("bp",)
        and term.source.offset == 4
        and term.source.size == 2
    )
    assert term.coefficient == 1
    assert result.value is binding.root
    assert result.value is not None and result.value.space is MemSpace.REG


def test_frame_arithmetic_push_stays_numeric_only() -> None:
    """Frame arithmetic like LEA AX,[BP-4] is numeric evidence, not an address."""
    ssa, binding, definition, use = _bound_piece(
        bytes.fromhex("8d46fc50e80000"), push_addr=0x1003, callsite_addr=0x1004
    )

    result = collect_input_offset_value_8616(
        binding, artifact=ssa, definition=definition, use=use
    )

    assert result.complete
    expression = result.expression
    assert expression is not None and expression.width == 2
    assert expression.constant == 0xFFFC
    assert len(expression.terms) == 1
    term = expression.terms[0]
    assert isinstance(term.source, ScalarAffineEntryRegister8616)
    assert term.source.register_name == "bp" and term.coefficient == 1
    assert result.value is binding.root
    assert result.value is not None and result.value.const is None


def test_missing_logical_root_refuses_without_trace() -> None:
    ssa, _binding, definition, use = _bound_piece(
        bytes.fromhex("6a05e80000"), push_addr=0x1000, callsite_addr=0x1002
    )

    result = collect_input_offset_value_8616(
        None, artifact=ssa, definition=definition, use=use
    )

    assert not result.complete
    assert result.failure is InputOffsetValueFailure8616.MISSING_LOGICAL_ROOT
    assert result.trace is None
    assert result.value is None and result.expression is None
    assert result.stats == InputOffsetValueStats8616(1, 0, 0, 0, 1)


def test_incomplete_binding_refuses() -> None:
    ssa, binding, definition, use = _bound_piece(
        bytes.fromhex("6a05e80000"), push_addr=0x1000, callsite_addr=0x1002
    )
    malformed = replace(binding, byte_width=2)
    assert not malformed.complete

    result = collect_input_offset_value_8616(
        malformed, artifact=ssa, definition=definition, use=use
    )

    assert not result.complete
    assert result.failure is InputOffsetValueFailure8616.BINDING_INCOMPLETE
    assert result.stats == InputOffsetValueStats8616(1, 0, 0, 0, 1)


def test_split_logical_argument_refuses() -> None:
    """A two-push logical word argument is split, not one covered 16-bit root."""
    ssa, binding, definition, use = _bound_piece(
        bytes.fromhex("6a026a01e80000"),
        push_addr=0x1000,
        callsite_addr=0x1004,
        argument_size=4,
    )
    assert not binding.covers_logical_argument

    result = collect_input_offset_value_8616(
        binding, artifact=ssa, definition=definition, use=use
    )

    assert not result.complete
    assert result.failure is InputOffsetValueFailure8616.SPLIT_LOGICAL_ARGUMENT
    assert result.stats == InputOffsetValueStats8616(1, 1, 0, 0, 1)


def test_foreign_caller_artifact_refuses() -> None:
    ssa, binding, definition, use = _bound_piece(
        bytes.fromhex("6a05e80000"), push_addr=0x1000, callsite_addr=0x1002
    )
    foreign = replace(ssa, function_addr=0x2000)

    result = collect_input_offset_value_8616(
        binding, artifact=foreign, definition=definition, use=use
    )

    assert not result.complete
    assert result.failure is InputOffsetValueFailure8616.FOREIGN_CALLER_ARTIFACT
    assert result.stats == InputOffsetValueStats8616(1, 1, 0, 0, 1)


def test_foreign_push_site_refuses() -> None:
    """An equal-shaped artifact with different block objects is foreign."""
    _ssa, binding, definition, use = _bound_piece(
        bytes.fromhex("6a05e80000"), push_addr=0x1000, callsite_addr=0x1002
    )
    twin = _lift_ssa(bytes.fromhex("6a05e80000"))
    assert twin.function_addr == binding.caller_addr
    assert twin.blocks[0] is not binding.slices[0].site.block

    result = collect_input_offset_value_8616(
        binding, artifact=twin, definition=definition, use=use
    )

    assert not result.complete
    assert result.failure is InputOffsetValueFailure8616.FOREIGN_PUSH_SITE
    assert result.stats == InputOffsetValueStats8616(1, 1, 0, 0, 1)


def test_sibling_slice_definition_refuses() -> None:
    """A definition for the sibling byte slice is foreign to piece zero."""
    ssa, binding, _definition, use = _bound_piece(
        bytes.fromhex("6a05e80000"), push_addr=0x1000, callsite_addr=0x1002
    )
    sibling = _slice_definition(binding.logical_push, binding.push_addr, 1)
    assert sibling.is_complete

    result = collect_input_offset_value_8616(
        binding, artifact=ssa, definition=sibling, use=use
    )

    assert not result.complete
    assert result.failure is InputOffsetValueFailure8616.DEFINITION_MISMATCH
    assert result.stats == InputOffsetValueStats8616(1, 1, 0, 0, 1)


def test_unbound_definition_and_use_refuse() -> None:
    ssa, binding, definition, use = _bound_piece(
        bytes.fromhex("6a05e80000"), push_addr=0x1000, callsite_addr=0x1002
    )

    no_root = replace(definition, logical_push=None)
    result_definition = collect_input_offset_value_8616(
        binding, artifact=ssa, definition=no_root, use=use
    )
    foreign_use = replace(use, instr_index=use.instr_index + 1)
    result_use = collect_input_offset_value_8616(
        binding, artifact=ssa, definition=definition, use=foreign_use
    )

    assert result_definition.failure is InputOffsetValueFailure8616.DEFINITION_MISMATCH
    assert not result_definition.complete
    assert result_use.failure is InputOffsetValueFailure8616.CALL_USE_MISMATCH
    assert not result_use.complete


def test_untraceable_root_retains_upstream_refusal() -> None:
    """A bare entry AX push keeps the typed upstream trace refusal."""
    ssa, binding, definition, use = _bound_piece(
        bytes.fromhex("50e80000"), push_addr=0x1000, callsite_addr=0x1001
    )

    result = collect_input_offset_value_8616(
        binding, artifact=ssa, definition=definition, use=use
    )

    assert not result.complete
    assert result.failure is InputOffsetValueFailure8616.TRACE_REFUSED
    assert result.trace is not None and not result.trace.complete
    assert result.trace.failure is ScalarAffineFailure8616.DEFINITION_MISSING
    assert result.expression is None and result.value is None
    assert result.stats == InputOffsetValueStats8616(1, 1, 0, 0, 1)


def test_complete_rechecks_retained_evidence_not_cached_verdict() -> None:
    ssa, binding, definition, use = _bound_piece(
        bytes.fromhex("6a05e80000"), push_addr=0x1000, callsite_addr=0x1002
    )
    result = collect_input_offset_value_8616(
        binding, artifact=ssa, definition=definition, use=use
    )
    assert isinstance(result, InputOffsetValue8616) and result.complete
    assert result.trace is not None and result.trace.expression is not None

    corrupted = (
        replace(result, trace=None),
        replace(result, trace=replace(result.trace, expression=replace(result.trace.expression, constant=6))),
        replace(result, binding=replace(binding, byte_width=2)),
        replace(result, definition=replace(definition, logical_push=None)),
        replace(result, use=replace(use, instr_index=0)),
        replace(result, stats=InputOffsetValueStats8616(1, 1, 1, 0, 0)),
    )
    for candidate in corrupted:
        assert not candidate.complete
        assert candidate.expression is None
        assert candidate.value is None
