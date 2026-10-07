"""Layer: dosunit joint recursive proof admission (staging).

Responsibility: require exact transition coverage, full modeled state and closed
same-coordinate dispatch before any local solver fact enters a joint report.
These structural checks do not grant physical or whole-function equivalence.
"""
from __future__ import annotations

from typing import Any

from tools.dosunit.compare import straightline_ssa as S
from tools.dosunit.compare.flat32_call_contracts import _initial_state as flat_initial_state
from tools.dosunit.compare.flat32_call_contracts import _register_widths
from tools.dosunit.compare.real16_call_contracts import initial_state
from tools.dosunit.compare.real16_control_targets import ControlDomainFailure
from tools.dosunit.contracts.proof_contracts import Architecture
from tools.dosunit.contracts.register_state_relations import MachineState
from tools.dosunit.recursive_proofs.recursive_joint_contracts import (
    JointNodeId,
    JointProvedControl,
    JointReason,
    JointStepKind,
    JointStepPair,
    JointSystem,
)
from tools.dosunit.recursive_proofs.recursive_joint_identity import control_view_model_hash
from tools.dosunit.recursive_proofs.recursive_static_control import (
    StaticControlLimits,
    StaticControlReason,
    resolve_static_control,
)
from tools.dosunit.recursive_proofs.stack.recursive_stack_domains import StackWordLayout


class JointRefusal(Exception):
    """An explicit unclosed joint requirement; no solver failure is swallowed."""

    def __init__(self, reason: JointReason, detail: str) -> None:
        """Keep the exact typed boundary and useful diagnostic context."""
        self.reason = reason
        self.detail = detail
        super().__init__(detail)


def static_destinations(term: object, *, deadline: float = -1.0,
                        limits: StaticControlLimits | None = None) -> frozenset[int] | None:
    """Require complete bounded literal/ITE evidence under the original deadline."""
    result = resolve_static_control(term, limits=limits, deadline=deadline)
    return result.targets if result.complete else None


def admit_joint_system(system: JointSystem, *, deadline: float = -1.0) -> StackWordLayout:
    """Validate the proposal and derive its exact near-frame layout.

    Missing nodes, duplicate facts, missing state and open dependencies refuse.
    This first relation requires identical block coordinates; different layouts
    must later provide a proved address/control relation, never normalization.
    """
    layout = derive_joint_frame_layout(system)
    by_node = {step.node: step for step in system.steps}
    for step in system.steps:
        _check_dispatch(system, step.node, by_node, deadline=deadline)
    return layout


def derive_joint_frame_layout(system: JointSystem) -> StackWordLayout:
    """Validate structural closure and derive layout without proving dispatch.

    Declared graph reachability is metadata closure only. Consumers must prove
    actual full-width control under their established domain before progress;
    this result never substitutes for strict joint admission.
    """
    _check_manifest(system)
    _check_outputs(system)
    _check_ranges_and_states(system)
    by_node = {step.node: step for step in system.steps}
    for step in system.steps:
        _check_dispatch_metadata(step, by_node)
    _check_reachable(system, by_node)
    continuations = tuple(sorted({by_node[step.continuation].original_address for step in system.steps
                                  if step.continuation is not None}))
    if not continuations:
        raise JointRefusal(JointReason.DISPATCH, "recursive near-frame system requires actual CALL continuations")
    segmented = system.contract.architecture is Architecture.REAL16
    # Real16 operand32 and mixed-size frames require an explicit frame relation.
    # The real16 builder currently refuses those before constructing this slice.
    return StackWordLayout(16 if segmented else 32, 16 if segmented else 32,
                           segmented, continuations, system.component_ranges)


def _check_manifest(system: JointSystem) -> None:
    """Require complete distinct nodes and exact component membership."""
    nodes = [step.node for step in system.steps]
    if (not nodes or len(set(nodes)) != len(nodes) or len(set(system.expected_nodes)) != len(system.expected_nodes)
            or set(nodes) != set(system.expected_nodes) or system.root not in nodes):
        raise JointRefusal(JointReason.MANIFEST, "paired steps must cover the entire admitted node manifest exactly once")
    if system.external_dependencies:
        raise JointRefusal(JointReason.EXTERNAL, "external components require independently closed dependencies")
    members = set(system.members)
    if len(members) != len(system.members) or {node.function for node in nodes} != members:
        raise JointRefusal(JointReason.COMPONENT, "members must cover all and only the proposed component functions")


def _check_outputs(system: JointSystem) -> None:
    """Require the authoritative complete machine identity at entry."""
    required = set(S._ssa_register_widths()) | {"memory", "io", system.control_field}
    if system.contract.architecture is Architecture.REAL16:
        baseline = initial_state()
        if system.control_field != "control_ip" or system.initial_state != baseline:
            raise JointRefusal(JointReason.OUTPUTS, "real16 initiation requires the authoritative full identity state")
    else:
        baseline = flat_initial_state(_register_widths())
        baseline["ip"] = {"op": "input", "name": "ip", "width": 32}
        required = set(baseline)
        if system.control_field != "ip" or system.initial_state != baseline:
            raise JointRefusal(JointReason.OUTPUTS, "flat32 initiation requires installed full native identity state")
    if (set(system.required_outputs) != required or len(system.required_outputs) != len(required)
            or system.initial_state is None or set(system.initial_state) != required):
        raise JointRefusal(JointReason.OUTPUTS, "initiation and every step require all native modeled state components")


def _check_ranges_and_states(system: JointSystem) -> None:
    """Keep both state projections and all matched native coordinates exact."""
    required = set(system.required_outputs)
    for step in system.steps:
        if step.original_address != step.candidate_address:
            raise JointRefusal(JointReason.LAYOUT, "different native coordinates require a separately proved relation")
        if not any(start <= step.original_address < end for start, end in system.component_ranges):
            raise JointRefusal(JointReason.LAYOUT, "every native block must lie in the declared component")
        if not step.original_hash or not step.candidate_hash:
            raise JointRefusal(JointReason.MANIFEST, "every transition requires both binary identities")
        if set(step.original) != required or set(step.candidate) != required:
            raise JointRefusal(JointReason.OUTPUTS, "a transition lost or added a modeled state component")
        for state in (step.original, step.candidate):
            if state[system.control_field].get("width") != 32:
                raise JointRefusal(JointReason.OUTPUTS, "loaded control must preserve the complete native address width")


def _check_reachable(system: JointSystem, by_node: dict[JointNodeId, JointStepPair]) -> None:
    """Verify finite closure including actual call continuations without inlining."""
    reachable = {system.root}
    pending = [system.root]
    while pending:
        step = by_node[pending.pop()]
        targets = set(step.successors)
        if step.continuation is not None:
            targets.add(step.continuation)
        for target in targets - reachable:
            reachable.add(target)
            pending.append(target)
    if reachable != set(by_node):
        raise JointRefusal(JointReason.MANIFEST, "all proposed cutpoints must be covered by the closed reachable system")


def _dispatch_term(system: JointSystem, step: JointStepPair, state: MachineState,
                   view: JointProvedControl | None, address: int,
                   targets: frozenset[int], *, deadline: float) -> dict[str, Any]:
    """Return a re-verified proved control term, else the raw state term.

    A view is consumed only while it still binds this exact step: its node,
    its own loaded linear coordinate, the paired state's untouched raw
    ``control_ip`` term, the recorded fetch-domain head, the embedded proving
    block's ``control_domain``/covered-code identity and the current
    control-owner model must all agree. The retained ``block`` then re-runs
    the same bounded fetch-domain boundary proof on the bound ``raw`` term;
    only a fresh product whose own resolved destinations equal the declared
    dispatch set authorizes the view's term — metadata alone never
    authorizes a destination. Stale or tampered evidence refuses, and absent
    views keep the original structural resolution path unchanged.
    """
    raw: dict[str, Any] = state[system.control_field]
    if view is None:
        return raw
    domain = view.domain if isinstance(view.domain, dict) else {}
    source_raw: Any = view.block.get("source") if isinstance(view.block, dict) else None
    source: dict[str, Any] = source_raw if isinstance(source_raw, dict) else {}
    if (view.node != step.node or view.address != address or view.raw != raw
            or S._optional_int(domain.get("head_linear")) != address):
        raise JointRefusal(JointReason.DISPATCH,
                           "proved control view no longer binds this paired effect")
    if (domain != source.get("control_domain")
            or view.code_sha256 != source.get("machine_code_sha256")):
        raise JointRefusal(JointReason.DISPATCH,
                           "proved control view no longer binds this proving block")
    if view.model_hash != control_view_model_hash() or not isinstance(view.normalized, dict):
        raise JointRefusal(JointReason.DISPATCH,
                           "proved control view predates the current control-owner model")
    proved = S._proved_composed_control(
        view.block, view.raw, state,
        compose_stats={"deadline": deadline if deadline >= 0 else None})
    if proved is None or proved.normalized is None:
        failure = proved.failure if proved is not None else None
        reason = (JointReason.DEADLINE if failure is ControlDomainFailure.BUDGET_EXHAUSTED
                  else JointReason.DISPATCH)
        raise JointRefusal(reason,
                           "proved control view did not re-verify under its bound block/domain")
    proved_targets = resolve_static_control(proved.normalized, deadline=deadline)
    if not proved_targets.complete or proved_targets.targets != targets:
        proved.unconsumed()
        reason = (JointReason.DEADLINE
                  if proved_targets.reason is StaticControlReason.DEADLINE else JointReason.DISPATCH)
        raise JointRefusal(reason,
                           "re-proved control does not reach the declared dispatch destinations")
    proved.consume()
    return view.normalized


def _check_dispatch(system: JointSystem, node: JointNodeId, by_node: dict[JointNodeId, JointStepPair],
                    *, deadline: float) -> None:
    """Check actual full control on both sides against complete dispatch metadata."""
    step = by_node[node]
    _check_dispatch_metadata(step, by_node)
    if step.kind is JointStepKind.RETURN:
        return
    targets = frozenset(by_node[target].original_address for target in step.successors)
    for state, view, address in ((step.original, step.original_control, step.original_address),
                                 (step.candidate, step.candidate_control, step.candidate_address)):
        term = _dispatch_term(system, step, state, view, address, targets, deadline=deadline)
        control = resolve_static_control(term, deadline=deadline)
        if not control.complete:
            reason = JointReason.DEADLINE if control.reason is StaticControlReason.DEADLINE else JointReason.DISPATCH
            raise JointRefusal(reason, f"static control refused: {control.reason.value}; nodes={control.node_count}")
        if control.targets != targets:
            raise JointRefusal(JointReason.DISPATCH, "actual loaded control does not cover exactly the declared successors")


def _check_dispatch_metadata(step: JointStepPair, by_node: dict[JointNodeId, JointStepPair]) -> None:
    """Validate edge declarations without treating them as execution evidence."""
    if len(set(step.successors)) != len(step.successors) or any(target not in by_node for target in step.successors):
        raise JointRefusal(JointReason.DISPATCH, "successors must be unique declared nodes")
    if step.kind is JointStepKind.RETURN:
        if step.successors or step.callee is not None or step.continuation is not None:
            raise JointRefusal(JointReason.DISPATCH, "dynamic return closure must come from frame proof")
        return
    if step.kind is JointStepKind.CALL:
        _check_call(step, by_node)
    elif step.callee is not None or step.continuation is not None or not step.successors:
        raise JointRefusal(JointReason.DISPATCH, "ordinary transition requires exact nonempty branch successors")


def _check_call(step: JointStepPair, by_node: dict[JointNodeId, JointStepPair]) -> None:
    """Require a member entry, actual retained continuation and exact call edge."""
    if step.callee is None or step.continuation is None:
        raise JointRefusal(JointReason.DISPATCH, "CALL target and continuation are required")
    if (step.callee not in by_node or step.continuation not in by_node or step.successors != (step.callee,)
            or step.callee.delta != 0 or step.continuation.function != step.node.function):
        raise JointRefusal(JointReason.DISPATCH, "CALL must enter a member entry and retain its caller continuation")
