"""Represent direct and helper-backed pytest assertion evidence.

Layer: Tooling/gates.
Responsibility: classify explicit test expectations and resolve assertions
reached through helpers defined in the same test module.
"""

from __future__ import annotations

from dataclasses import dataclass, replace


@dataclass(frozen=True, slots=True)
class PytestNodeFacts:
    """Static cost and assertion facts for one collectable pytest node."""

    call_names: tuple[str, ...] = ()
    effective_call_names: tuple[str, ...] = ()
    assertion_count: int = 0
    effective_assertion_count: int = 0
    assertion_kinds: tuple[str, ...] = ()
    expectation_count: int = 0
    effective_expectation_count: int = 0
    expectation_kinds: tuple[str, ...] = ()
    assertion_sources: tuple[str, ...] = ()
    evidence_hints: tuple[str, ...] = ()
    module_hints: tuple[str, ...] = ()
    function_address_hints: tuple[int, ...] = ()
    effective_function_address_hints: tuple[int, ...] = ()
    input_hints: tuple[str, ...] = ()
    effective_input_hints: tuple[str, ...] = ()
    option_hints: tuple[str, ...] = ()
    effective_option_hints: tuple[str, ...] = ()
    subprocess_call_count: int = 0
    effective_subprocess_call_count: int = 0
    cost_sources: tuple[str, ...] = ()


def expectation_kind(call_name: str) -> str | None:
    """Classify calls that make a test fail when an expectation is unmet."""

    if call_name in {"pytest.raises", "pytest.warns"}:
        return call_name
    leaf = call_name.rsplit(".", 1)[-1]
    if leaf.startswith(("assert_", "assertCalled")):
        return "assertion-call"
    if call_name.startswith("self.assert"):
        return "unittest-assertion"
    return None


def _local_call_target(selector: str, call_name: str, known: set[str]) -> str | None:
    """Resolve a direct call to a helper defined in the same test module."""

    if call_name in known:
        return call_name
    class_name = selector.split("::", 1)[0] if "::" in selector else None
    leaf = call_name.rsplit(".", 1)[-1]
    if class_name is not None:
        class_target = f"{class_name}::{leaf}"
        if class_target in known:
            return class_target
    return None


def resolve_local_helper_facts(selector: str, direct_facts: dict[str, PytestNodeFacts]) -> PytestNodeFacts:
    """Merge assertions reached through local helpers into one test contract."""

    root = direct_facts[selector]
    known = set(direct_facts)
    reachable: set[str] = {selector}
    pending = [selector]
    while pending:
        current = pending.pop()
        for call_name in direct_facts[current].call_names:
            target = _local_call_target(current, call_name, known)
            if target is not None and target not in reachable:
                reachable.add(target)
                pending.append(target)
    assertion_sources = sorted(
        name
        for name in reachable
        if name != selector and (direct_facts[name].assertion_count or direct_facts[name].expectation_count)
    )
    cost_sources = sorted(
        name
        for name in reachable
        if name != selector
        and (
            direct_facts[name].subprocess_call_count
            or direct_facts[name].input_hints
            or direct_facts[name].option_hints
        )
    )
    return replace(
        root,
        effective_call_names=tuple(sorted({call for name in reachable for call in direct_facts[name].call_names})),
        effective_assertion_count=sum(direct_facts[name].assertion_count for name in reachable),
        effective_expectation_count=sum(direct_facts[name].expectation_count for name in reachable),
        assertion_sources=tuple(assertion_sources),
        effective_function_address_hints=tuple(
            sorted({address for name in reachable for address in direct_facts[name].function_address_hints})
        ),
        effective_input_hints=tuple(sorted({hint for name in reachable for hint in direct_facts[name].input_hints})),
        effective_option_hints=tuple(sorted({hint for name in reachable for hint in direct_facts[name].option_hints})),
        effective_subprocess_call_count=sum(direct_facts[name].subprocess_call_count for name in reachable),
        cost_sources=tuple(cost_sources),
        evidence_hints=tuple(sorted({hint for name in reachable for hint in direct_facts[name].evidence_hints})),
        module_hints=tuple(sorted({module for name in reachable for module in direct_facts[name].module_hints})),
    )
