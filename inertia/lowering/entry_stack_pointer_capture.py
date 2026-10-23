"""Capture one architectural entry-SP scalar for independent Types consumers.

Layer: Types/Lowering.
Responsibility: own the dominating immutable word capture, exact runtime input
expression and source-bound use census shared by return and call consumers.
Every retained use is freshly reproduced; a marker never supplies authority.
"""
from __future__ import annotations

from collections.abc import MutableMapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen import c
from angr.sim_type import SimType, SimTypeInt, SimTypeLong, SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimTemporaryVariable, SimVariable

from inertia.alias.call_stack_positions import CallStackPosition8616, call_stack_position_is_current_8616
from inertia.alias.scoped_call_stack_context import ScopedCallStackContext8616
from inertia.alias.scoped_call_stack_positions import (
    ScopedCallStackPositionResult8616,
    prove_scoped_call_stack_position_8616,
)
from inertia.ir.core import IRFunctionArtifact
from inertia.ir.real16_invocation_domain import Real16InvocationDomain8616
from inertia.semantics.numeric_stack_pointer_returns import (
    NumericStackPointerReturn8616,
    prove_numeric_stack_pointer_return_8616,
)

from .c_ast_utils import _iter_c_nodes_deep_8616
from .gp_register_state import _record_runtime_gp_global_8616, runtime_gp_state_expr_8616

_CAPTURE_TAG = "inertia_entry_sp_capture_8616"
_WORD_MASK = 0xffff


class ScopedCallPositionAuthority8616:
    """Read-only scoped authority; projections never replace live Alias proof.

    A plain class, never a dataclass: ``dataclasses.asdict`` must not recurse
    the retained project/domain runtime objects. It retains a single
    ``ScopedCallStackPositionResult8616`` — the only source of coordinates
    and proof ownership — and projects it read-only. Copying retains the live
    handle; diagnostics are handled explicitly by the snapshot encoder.
    """

    __slots__ = ("_result",)

    def __init__(self, result: ScopedCallStackPositionResult8616) -> None:
        """Retain the single source of coordinates and proof ownership."""
        self._result = result

    @property
    def result(self) -> ScopedCallStackPositionResult8616:
        """Return the retained Alias publication without a separate scalar state."""
        return self._result

    @property
    def position(self) -> CallStackPosition8616 | None:
        """Project coordinates for layout; consumption still requires revalidation."""
        return self.result.proof

    def _identity_key(self) -> tuple[CallStackPosition8616 | None, int, int, int, int, int, int]:
        """Distinguish proof ownership even when all scalar coordinates agree."""
        result = self.result
        return (self.position, id(result.artifact), id(result.call), id(result.carrier),
                id(result.caller_scope), id(result.callee_scope), id(result.context))

    def __eq__(self, other: object) -> bool:
        """Compare coordinates and every retained provenance identity."""
        return type(other) is ScopedCallPositionAuthority8616 and self._identity_key() == other._identity_key()

    def __hash__(self) -> int:
        """Use the same live provenance identity as equality."""
        return hash(self._identity_key())

    def __copy__(self) -> ScopedCallPositionAuthority8616:
        """Keep the live authority when copying syntax in this process."""
        return self

    def __deepcopy__(self, memo: dict[int, object]) -> ScopedCallPositionAuthority8616:
        """Copy syntax without cloning or downgrading its proof capability."""
        memo[id(self)] = self
        return self

    def __repr__(self) -> str:
        """Keep runtime project and domain objects out of diagnostics."""
        return f"ScopedCallPositionAuthority8616(position={self.position!r})"

    def is_current_for(
        self, source: IRFunctionArtifact, *,
        scoped_context: ScopedCallStackContext8616 | None,
        scoped_caller_scope: Real16InvocationDomain8616 | None,
    ) -> bool:
        """Authenticate retained and offered proof contexts against current Alias."""
        result, position = self.result, self.position
        if position is None or result.artifact is not source:
            return False
        if scoped_context is None or type(scoped_context) is not ScopedCallStackContext8616:
            return False
        binding = scoped_context.for_callsite(position.callsite_addr)
        if binding is None or binding.carrier is not result.carrier:
            return False
        if result.position_for(scoped_caller_scope, binding.callee_scope) != position:
            return False
        if scoped_context is result.context:
            return True
        fresh = prove_scoped_call_stack_position_8616(
            source, result.block_addr, result.instruction_index,
            scoped_caller_scope, binding.callee_scope, context=scoped_context,
        )
        return fresh.failure is None and fresh.proof == position


type EntryStackPointerUse8616 = (
    NumericStackPointerReturn8616
    | CallStackPosition8616
    | ScopedCallPositionAuthority8616
)


class EntryStackPointerCaptureFailure8616(StrEnum):
    """Source or storage defects preventing a shared architectural capture."""

    SOURCE_CHANGED = "source_changed"
    FUNCTION_SCOPE_MISMATCH = "function_scope_mismatch"
    INVALID_CAPTURE = "invalid_capture"
    NO_ENTRY_SEQUENCE = "no_entry_sequence"


@dataclass(frozen=True, slots=True)
class EntryStackPointerCapture8616:
    """Candidate capture scope and uses; current source and initializer must verify."""

    function_addr: int
    uses: tuple[EntryStackPointerUse8616, ...]


@dataclass(frozen=True, slots=True)
class EntryStackPointerCaptureResult8616:
    """Closed outcome of one capture request without serializing native objects."""

    value: c.CVariable | None
    changed_count: int
    source_proven: bool
    failure: EntryStackPointerCaptureFailure8616 | None

    def to_dict(self) -> dict[str, object]:
        """Expose the source-to-storage census and typed failure to diagnostics."""
        return {
            "raw_fact_count": 1, "normalized_fact_count": 1,
            "classified_fact_count": int(self.source_proven),
            "materialized_count": int(self.value is not None),
            "failure_count": int(self.failure is not None),
            "changed_count": self.changed_count,
            "failure": self.failure.value if self.failure is not None else None,
        }


class _VariableManager8616(Protocol):
    """Native variable type publication boundary used by scalar capture."""

    def set_variable_type(self, variable: SimVariable, type_: SimType) -> None:
        """Register a newly materialized local with its exact storage type."""

    def get_variable_type(self, variable: SimVariable) -> SimType | None:
        """Read the actual local declaration used by native code generation."""
        ...



class StackPointerCaptureFunction8616(Protocol):
    """Native function declaration and entry-sequence boundary."""

    addr: int
    statements: object
    variables_in_use: MutableMapping[SimVariable, c.CVariable]
    variable_manager: _VariableManager8616

    def refresh(self) -> None:
        """Rebuild local declarations after storage publication."""



def _unsigned_width(expression: c.CExpression, bits: int) -> bool:
    """Check an architecture-bound native unsigned scalar type."""
    type_ = expression.type
    return (isinstance(type_, SimTypeInt) and not type_.signed
            and type_._arch is not None and type_.size == bits)



def _same_runtime_read(actual: object, expected: object, depth: int = 0) -> bool:
    """Validate only the canonical runtime helper's bounded expression shape."""
    if depth > 3 or type(actual) is not type(expected):
        return False
    if isinstance(actual, c.CVariable) and isinstance(expected, c.CVariable):
        left, right = actual.variable, expected.variable
        return (isinstance(left, SimMemoryVariable) and isinstance(right, SimMemoryVariable)
                and actual.unified_variable is None and _unsigned_width(actual, 32)
                and (left.addr, left.size, left.name, left.region, left.category)
                == (right.addr, right.size, right.name, right.region, right.category))
    if isinstance(actual, c.CConstant) and isinstance(expected, c.CConstant):
        return actual.value == expected.value and _unsigned_width(actual, 32)
    if isinstance(actual, c.CBinaryOp) and isinstance(expected, c.CBinaryOp):
        return (actual.op == expected.op
                and _same_runtime_read(actual.lhs, expected.lhs, depth + 1)
                and _same_runtime_read(actual.rhs, expected.rhs, depth + 1))
    return False



def _same_local(node: object, value: c.CVariable) -> bool:
    """Match exact local temporary storage, never an architectural register name."""
    return (isinstance(node, c.CVariable) and isinstance(node.variable, SimTemporaryVariable)
            and isinstance(value.variable, SimTemporaryVariable)
            and node.variable.tmp_id == value.variable.tmp_id
            and node.variable.size == value.variable.size == 2
            and node.unified_variable is None and _unsigned_width(node, 16))



def _capture_is_immutable(root: object, assignment: c.CAssignment) -> bool:
    """Require one dominating definition and no address-taking of the local."""
    value = assignment.lhs
    if not isinstance(value, c.CVariable) or not _same_local(value, value):
        return False
    writes = [node for node in _iter_c_nodes_deep_8616(root)
              if isinstance(node, c.CAssignment) and _same_local(node.lhs, value)]
    if writes != [assignment]:
        return False
    for node in _iter_c_nodes_deep_8616(root):
        if isinstance(node, c.CUnaryOp) and any(
            _same_local(child, value) for child in _iter_c_nodes_deep_8616(node)
        ):
            return False
    return True



def entry_stack_pointer_projection_8616(value: c.CVariable, offset: int, codegen: object) -> c.CBinaryOp:
    """Emit exact modulo-16 addition without signed promotion or pointer recovery."""
    wide = SimTypeLong(False)
    added = c.CBinaryOp("Add", value, c.CConstant(offset & _WORD_MASK, wide, codegen=codegen), codegen=codegen)
    return c.CBinaryOp("And", added, c.CConstant(_WORD_MASK, wide, codegen=codegen), codegen=codegen)



def is_entry_stack_pointer_projection_8616(expression: object, value: c.CVariable, offset: int) -> bool:
    """Recognize only an already materialized exact owned scalar projection."""
    if not isinstance(expression, c.CBinaryOp) or expression.op != "And":
        return False
    added, mask = expression.lhs, expression.rhs
    if not isinstance(added, c.CBinaryOp) or added.op != "Add":
        return False
    delta = added.rhs
    return (isinstance(mask, c.CConstant) and mask.value == _WORD_MASK
            and isinstance(delta, c.CConstant) and delta.value == (offset & _WORD_MASK)
            and _same_local(added.lhs, value) and _unsigned_width(mask, 32)
            and _unsigned_width(delta, 32))



def _existing_capture_value_8616(
    function: StackPointerCaptureFunction8616, assignment: c.CAssignment, expected: c.CExpression,
) -> c.CVariable | None:
    """Authenticate the initializer and storage without changing native state."""
    root = function.statements
    marker = assignment.tags[_CAPTURE_TAG]
    if (not isinstance(root, c.CStatements) or not root.statements
            or root.statements[0] is not assignment):
        return None
    if (not isinstance(marker, EntryStackPointerCapture8616)
            or marker.function_addr != function.addr or not _same_runtime_read(assignment.rhs, expected)
            or not _capture_is_immutable(root, assignment)):
        return None
    return cast(c.CVariable, assignment.lhs)


def _prepare_entry_capture(
    codegen: object, function: StackPointerCaptureFunction8616, nodes: tuple[object, ...],
    captures: list[c.CAssignment], ordered_proofs: tuple[EntryStackPointerUse8616, ...],
) -> tuple[c.CVariable | None, int, EntryStackPointerCaptureFailure8616 | None]:
    """Verify an existing entry capture or publish one fresh scalar local."""
    root = function.statements
    expected = runtime_gp_state_expr_8616("sp", codegen=codegen, function_addr=function.addr)
    if expected is None:
        return None, 0, EntryStackPointerCaptureFailure8616.NO_ENTRY_SEQUENCE
    if captures:
        assignment = captures[0]
        marker = assignment.tags[_CAPTURE_TAG]
        value = _existing_capture_value_8616(function, assignment, expected)
        if value is None or not isinstance(marker, EntryStackPointerCapture8616):
            return None, 0, EntryStackPointerCaptureFailure8616.INVALID_CAPTURE
        changed = int(marker.uses != ordered_proofs)
        if changed:
            assignment.tags[_CAPTURE_TAG] = EntryStackPointerCapture8616(function.addr, ordered_proofs)
    else:
        if not isinstance(root, c.CStatement):
            return None, 0, EntryStackPointerCaptureFailure8616.NO_ENTRY_SEQUENCE
        used = {node.variable.tmp_id for node in nodes
                if isinstance(node, c.CVariable) and isinstance(node.variable, SimTemporaryVariable)}
        used.update(var.tmp_id for var in function.variables_in_use if isinstance(var, SimTemporaryVariable))
        temporary = SimTemporaryVariable(max(used, default=-1) + 1, 2)
        word_type = SimTypeShort(False)
        value = c.CVariable(temporary, variable_type=word_type, codegen=codegen)
        assignment = c.CAssignment(value, expected, codegen=codegen,
                                  tags={_CAPTURE_TAG: EntryStackPointerCapture8616(function.addr, ordered_proofs)})
        if isinstance(root, c.CStatements):
            root.statements = [assignment, *root.statements]
        else:
            function.statements = c.CStatements([assignment, root], codegen=codegen)
        function.variables_in_use[temporary] = value
        assert value.variable_type is not None
        function.variable_manager.set_variable_type(temporary, value.variable_type)
        _record_runtime_gp_global_8616(codegen, "esp")
        changed = 1
    return value, changed, None



class _CodegenCapture8616(Protocol):
    """Native codegen boundary retaining its active function declaration."""

    cfunc: StackPointerCaptureFunction8616 | None
    _inertia_vex_ir_artifact: IRFunctionArtifact | None


def _published_source_is_current_8616(codegen: object, source: IRFunctionArtifact) -> bool:
    """Require the current source publication at the dynamic native boundary."""
    try:
        published = cast(_CodegenCapture8616, codegen)._inertia_vex_ir_artifact
    except AttributeError:
        return False
    return published is source


def _use_position(use: EntryStackPointerUse8616) -> CallStackPosition8616 | None:
    """Project scalar coordinates for ordering; never authority by itself."""
    if isinstance(use, ScopedCallPositionAuthority8616):
        return use.position
    if isinstance(use, CallStackPosition8616):
        return use
    return None


def _use_order(use: EntryStackPointerUse8616) -> tuple[int, int, int, int, int]:
    """Order uniquely reproduced source occurrences without caller iteration order."""
    if isinstance(use, NumericStackPointerReturn8616):
        assignment = use.assignment
        return (0, assignment.block_addr, assignment.instruction_index, assignment.instruction_addr, use.path.return_addr)
    position = _use_position(use)
    if position is None:
        return (2, 0, 0, 0, 0)
    return (1, position.block_addr, position.instruction_index, position.callsite_addr, position.target_addr)


def _use_is_current(
    source: IRFunctionArtifact,
    use: EntryStackPointerUse8616,
    scoped_context: ScopedCallStackContext8616 | None,
    scoped_caller_scope: Real16InvocationDomain8616 | None,
) -> bool:
    """Delegate current authority to the owning source proof, never the marker."""
    if isinstance(use, NumericStackPointerReturn8616):
        current = prove_numeric_stack_pointer_return_8616(source, use.assignment.block_addr, use.path.return_addr)
        return cast(bool, current == use)
    if isinstance(use, ScopedCallPositionAuthority8616):
        return use.is_current_for(source, scoped_context=scoped_context,
                                  scoped_caller_scope=scoped_caller_scope)
    if not isinstance(use, CallStackPosition8616):
        return False
    return cast(bool, call_stack_position_is_current_8616(source, use))


def _retained_uses(captures: list[c.CAssignment]) -> tuple[EntryStackPointerUse8616, ...] | None:
    """Admit at most one explicit owned marker, preserving every prior consumer."""
    if not captures:
        return ()
    if len(captures) != 1:
        return None
    marker = captures[0].tags[_CAPTURE_TAG]
    if not isinstance(marker, EntryStackPointerCapture8616) or not isinstance(marker.uses, tuple):
        return None
    if not all(isinstance(use, (NumericStackPointerReturn8616, CallStackPosition8616,
                                ScopedCallPositionAuthority8616)) for use in marker.uses):
        return None
    return marker.uses


def prepare_entry_stack_pointer_capture_8616(
    codegen: object, source: IRFunctionArtifact, uses: tuple[EntryStackPointerUse8616, ...],
    *,
    scoped_context: ScopedCallStackContext8616 | None = None,
    scoped_caller_scope: Real16InvocationDomain8616 | None = None,
) -> EntryStackPointerCaptureResult8616 | None:
    """Share one dominating capture only after all retained and requested uses reprove.

    An empty request observes an existing capture but never creates one. Adding
    a second consumer extends the canonical use census without a second write
    or local variable. Invalidating either consumer invalidates reuse for both.
    Scoped uses revalidate only under the offered binding context and caller
    domain — omitting either keeps every retained scoped use unproven and
    refuses the capture.
    """
    function = cast(_CodegenCapture8616, codegen).cfunc
    if function is None:
        return None if not uses else EntryStackPointerCaptureResult8616(
            None, 0, False, EntryStackPointerCaptureFailure8616.NO_ENTRY_SEQUENCE,
        )
    nodes = tuple(_iter_c_nodes_deep_8616(function.statements))
    captures = [node for node in nodes if isinstance(node, c.CAssignment) and _CAPTURE_TAG in node.tags]
    if not captures and not uses:
        return None
    if function.addr != source.function_addr:
        return EntryStackPointerCaptureResult8616(None, 0, False, EntryStackPointerCaptureFailure8616.FUNCTION_SCOPE_MISMATCH)
    if not _published_source_is_current_8616(codegen, source):
        return EntryStackPointerCaptureResult8616(None, 0, False, EntryStackPointerCaptureFailure8616.SOURCE_CHANGED)
    retained = _retained_uses(captures)
    if retained is None:
        return EntryStackPointerCaptureResult8616(None, 0, False, EntryStackPointerCaptureFailure8616.INVALID_CAPTURE)
    combined_uses = {*retained, *uses}
    if not combined_uses or not all(
            _use_is_current(source, use, scoped_context, scoped_caller_scope) for use in combined_uses):
        return EntryStackPointerCaptureResult8616(None, 0, False, EntryStackPointerCaptureFailure8616.SOURCE_CHANGED)
    combined = tuple(sorted(combined_uses, key=_use_order))
    value, changed, failure = _prepare_entry_capture(codegen, function, nodes, captures, combined)
    if value is not None and changed:
        function.refresh()
    return EntryStackPointerCaptureResult8616(value, changed, True, failure)


@dataclass(frozen=True, slots=True)
class EntryStackPointerCaptureObservation8616:
    """Pure validated view for consumers that must never materialize or repair."""

    assignment: c.CAssignment
    value: c.CVariable
    uses: tuple[EntryStackPointerUse8616, ...]


def observe_entry_stack_pointer_capture_8616(
    codegen: object, source: IRFunctionArtifact,
    *,
    scoped_context: ScopedCallStackContext8616 | None = None,
    scoped_caller_scope: Real16InvocationDomain8616 | None = None,
) -> EntryStackPointerCaptureObservation8616 | None:
    """Reprove the current source and real capture without modifying either.

    Retained scoped uses revalidate only under the offered binding context
    and caller domain; without both a capture carrying scoped evidence
    observes as unproven.
    """
    function = cast(_CodegenCapture8616, codegen).cfunc
    if function is None or function.addr != source.function_addr or not _published_source_is_current_8616(codegen, source):
        return None
    captures = [node for node in _iter_c_nodes_deep_8616(function.statements)
                if isinstance(node, c.CAssignment) and _CAPTURE_TAG in node.tags]
    uses = _retained_uses(captures)
    if (len(captures) != 1 or not uses or not all(
            _use_is_current(source, use, scoped_context, scoped_caller_scope) for use in uses)):
        return None
    expected = runtime_gp_state_expr_8616("sp", codegen=codegen, function_addr=function.addr)
    if expected is None:
        return None
    value = _existing_capture_value_8616(function, captures[0], expected)
    return None if value is None else EntryStackPointerCaptureObservation8616(captures[0], value, uses)
