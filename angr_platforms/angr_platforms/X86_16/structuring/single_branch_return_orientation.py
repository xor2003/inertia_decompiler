"""Typed return-target evidence for orienting one structured branch.

Layer: Structuring.
Responsibility: classify whether a no-else return body belongs to the taken or
fallthrough CFG edge using recovered return expressions and exact reachability.
Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery,
rewrite cleanup, postprocess, or CLI/reporting work here.
Forbidden: instruction decoding, condition inference, text matching, or AST mutation.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum

from ..ir.condition_ir import ConditionIR

type ExpressionEquivalent8616 = Callable[[object, object], bool]
type TargetOrientationClassifier8616 = Callable[
    [ConditionIR, int, dict[int, tuple[int, ...]]],
    bool | None,
]

__all__ = (
    "SingleBranchReturnOrientation8616",
    "SingleBranchReturnOrientationEvidence8616",
    "StructuredArmOrientationEvidence8616",
    "StructuredBinaryArmOrientationEvidence8616",
    "classify_cfg_arm_orientation_8616",
    "classify_cfg_binary_arm_orientation_8616",
    "classify_direct_or_one_hop_target_orientation_8616",
    "classify_single_branch_return_orientation_8616",
)


class SingleBranchReturnOrientation8616(StrEnum):
    """Typed verdict for one no-else return body's CFG ownership."""

    TAKEN = "taken"
    FALLTHROUGH = "fallthrough"
    UNKNOWN_REFUSE = "unknown_refuse"

    def as_taken_polarity(self) -> bool | None:
        """Return direct-condition polarity, or ``None`` when proof is incomplete."""
        if self is SingleBranchReturnOrientation8616.TAKEN:
            return True
        if self is SingleBranchReturnOrientation8616.FALLTHROUGH:
            return False
        return None


@dataclass(frozen=True, slots=True)
class SingleBranchReturnOrientationEvidence8616:
    """Closed evidence record for one return-expression ownership decision."""

    orientation: SingleBranchReturnOrientation8616
    matching_targets: tuple[int, ...]
    taken_owned_targets: tuple[int, ...]
    fallthrough_owned_targets: tuple[int, ...]
    ambiguous_targets: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class StructuredArmOrientationEvidence8616:
    """Closed CFG ownership census for one structured branch arm."""

    orientation: SingleBranchReturnOrientation8616
    exclusive_taken_targets: tuple[int, ...]
    exclusive_fallthrough_targets: tuple[int, ...]
    shared_targets: tuple[int, ...]
    unreachable_targets: tuple[int, ...]
    direct_shared_orientations: tuple[bool, ...]


@dataclass(frozen=True, slots=True)
class StructuredBinaryArmOrientationEvidence8616:
    """Closed evidence for complementary true/false structured CFG arms."""

    true_arm: StructuredArmOrientationEvidence8616
    false_arm: StructuredArmOrientationEvidence8616
    true_polarity: bool | None
    false_polarity: bool | None
    inferred_empty_arm_count: int

    @property
    def is_complementary(self) -> bool:
        """Return whether both arms have proven opposite edge ownership."""
        return (
            self.true_polarity is not None
            and self.false_polarity is not None
            and self.true_polarity is not self.false_polarity
        )


def classify_direct_or_one_hop_target_orientation_8616(
    condition: ConditionIR,
    body_target: int,
    successors: Mapping[int, tuple[int, ...]],
) -> bool | None:
    """Classify one body reached directly by exactly one condition edge."""
    if not isinstance(condition.taken_target, int) or not isinstance(condition.fallthrough_target, int):
        return None
    taken_owns = body_target == condition.taken_target or body_target in successors.get(condition.taken_target, ())
    fallthrough_owns = (
        body_target == condition.fallthrough_target
        or body_target in successors.get(condition.fallthrough_target, ())
    )
    if taken_owns == fallthrough_owns:
        return None
    return taken_owns


def _cfg_reaches_target_8616(
    successors: Mapping[int, tuple[int, ...]],
    start: int,
    target: int,
    *,
    stop_at: int | None,
) -> bool:
    """Return whether one bounded CFG path reaches a target."""
    pending = [start]
    visited: set[int] = set()
    while pending and len(visited) < 128:
        address = pending.pop()
        if address == target:
            return True
        if address == stop_at or address in visited:
            continue
        visited.add(address)
        pending.extend(successors.get(address, ()))
    return False


def _classify_targets_8616(
    condition: ConditionIR,
    body_targets: Iterable[int],
    successors: Mapping[int, tuple[int, ...]],
) -> tuple[list[int], list[int], list[int], list[int]]:
    """Bucket each body target by exclusive or shared reachability."""
    assert isinstance(condition.taken_target, int)
    assert isinstance(condition.fallthrough_target, int)
    taken: list[int] = []
    fallthrough: list[int] = []
    shared: list[int] = []
    unreachable: list[int] = []
    for target in sorted(set(body_targets)):
        taken_reaches = _cfg_reaches_target_8616(
            successors,
            condition.taken_target,
            target,
            stop_at=condition.block_addr,
        )
        fallthrough_reaches = _cfg_reaches_target_8616(
            successors,
            condition.fallthrough_target,
            target,
            stop_at=condition.block_addr,
        )
        if taken_reaches and not fallthrough_reaches:
            taken.append(target)
        elif fallthrough_reaches and not taken_reaches:
            fallthrough.append(target)
        elif taken_reaches and fallthrough_reaches:
            shared.append(target)
        else:
            unreachable.append(target)
    return taken, fallthrough, shared, unreachable


def classify_cfg_arm_orientation_8616(
    condition: ConditionIR,
    body_targets: Iterable[int],
    successors: Mapping[int, tuple[int, ...]],
) -> StructuredArmOrientationEvidence8616:
    """Classify one whole arm from exclusive reachability or an immediate shared exit."""
    if not isinstance(condition.taken_target, int) or not isinstance(condition.fallthrough_target, int):
        return StructuredArmOrientationEvidence8616(
            SingleBranchReturnOrientation8616.UNKNOWN_REFUSE,
            (),
            (),
            (),
            tuple(sorted(set(body_targets))),
            (),
        )
    taken, fallthrough, shared, unreachable = _classify_targets_8616(
        condition,
        body_targets,
        successors,
    )
    orientation = SingleBranchReturnOrientation8616.UNKNOWN_REFUSE
    direct_shared: tuple[bool, ...] = ()
    if unreachable:
        orientation = SingleBranchReturnOrientation8616.UNKNOWN_REFUSE
    elif taken and not fallthrough:
        orientation = SingleBranchReturnOrientation8616.TAKEN
    elif fallthrough and not taken:
        orientation = SingleBranchReturnOrientation8616.FALLTHROUGH
    elif not taken and not fallthrough:
        direct_shared = tuple(
            direct
            for target in shared
            if (
                direct := classify_direct_or_one_hop_target_orientation_8616(
                    condition,
                    target,
                    successors,
                )
            )
            is not None
        )
        if direct_shared and all(item is direct_shared[0] for item in direct_shared):
            orientation = (
                SingleBranchReturnOrientation8616.TAKEN
                if direct_shared[0]
                else SingleBranchReturnOrientation8616.FALLTHROUGH
            )
    return StructuredArmOrientationEvidence8616(
        orientation,
        tuple(taken),
        tuple(fallthrough),
        tuple(shared),
        tuple(unreachable),
        direct_shared,
    )


def classify_cfg_binary_arm_orientation_8616(
    condition: ConditionIR,
    true_body_targets: Iterable[int],
    false_body_targets: Iterable[int],
    successors: Mapping[int, tuple[int, ...]],
) -> StructuredBinaryArmOrientationEvidence8616:
    """Classify two arms, inferring only an empty arm's proven complement."""
    true_targets = tuple(sorted(set(true_body_targets)))
    false_targets = tuple(sorted(set(false_body_targets)))
    true_arm = classify_cfg_arm_orientation_8616(condition, true_targets, successors)
    false_arm = classify_cfg_arm_orientation_8616(condition, false_targets, successors)
    true_polarity = true_arm.orientation.as_taken_polarity()
    false_polarity = false_arm.orientation.as_taken_polarity()
    inferred_empty_arm_count = 0
    if true_polarity is None and not true_targets and false_polarity is not None:
        true_polarity = not false_polarity
        inferred_empty_arm_count = 1
    elif false_polarity is None and not false_targets and true_polarity is not None:
        false_polarity = not true_polarity
        inferred_empty_arm_count = 1
    if true_polarity is not None and true_polarity is false_polarity:
        true_polarity = None
        false_polarity = None
        inferred_empty_arm_count = 0
    return StructuredBinaryArmOrientationEvidence8616(
        true_arm=true_arm,
        false_arm=false_arm,
        true_polarity=true_polarity,
        false_polarity=false_polarity,
        inferred_empty_arm_count=inferred_empty_arm_count,
    )


def classify_single_branch_return_orientation_8616(
    condition: ConditionIR,
    expected_return: object,
    exit_expressions: Mapping[int, object | None],
    successors: dict[int, tuple[int, ...]],
    expressions_equivalent: ExpressionEquivalent8616,
    classify_target_orientation: TargetOrientationClassifier8616,
) -> SingleBranchReturnOrientationEvidence8616:
    """Classify return-body ownership from equivalent target returns and CFG reachability."""
    matching: list[int] = []
    taken: list[int] = []
    fallthrough: list[int] = []
    ambiguous: list[int] = []
    for target, recovered_return in sorted(exit_expressions.items()):
        if recovered_return is None or not expressions_equivalent(recovered_return, expected_return):
            continue
        matching.append(target)
        target_orientation = classify_target_orientation(condition, target, successors)
        if target_orientation is True:
            taken.append(target)
        elif target_orientation is False:
            fallthrough.append(target)
        else:
            ambiguous.append(target)

    orientation = SingleBranchReturnOrientation8616.UNKNOWN_REFUSE
    if taken and not fallthrough:
        orientation = SingleBranchReturnOrientation8616.TAKEN
    elif fallthrough and not taken:
        orientation = SingleBranchReturnOrientation8616.FALLTHROUGH
    return SingleBranchReturnOrientationEvidence8616(
        orientation=orientation,
        matching_targets=tuple(matching),
        taken_owned_targets=tuple(taken),
        fallthrough_owned_targets=tuple(fallthrough),
        ambiguous_targets=tuple(ambiguous),
    )
