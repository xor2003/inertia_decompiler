"""Build per-node pytest purpose, cost, assertion, and memory inventory.

Layer: Tooling/gates.
Responsibility: derive deterministic static test facts and hold measured
per-test profile fields without changing pytest selection or execution.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Final

import pytest

from tools.dev.pytest_assertion_facts import PytestNodeFacts
from tools.dev.pytest_call_hints import concrete_function_addresses
from tools.dev.pytest_inventory_review import REVIEWED_TEST_MODULE_LAYERS
from tools.dev.pytest_source_index import load_pytest_source_index
from tools.dev.pytest_test_record import TestRecord
from tools.dev.test_ownership_manifest import TEST_OWNERSHIP_RULES

REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[2]


@dataclass(frozen=True, slots=True)
class _OwnershipTarget:
    """Describe one manifest test selector and its owned source layers."""

    selector: str
    owner: str
    layers: tuple[str, ...]


def _owned_path_layer(path: str) -> str:
    """Map a manifest-owned source path to the project architecture layer."""

    if path.startswith("inertia/"):
        parts = Path(path).parts
        return "/".join(parts[:2]) if len(parts) > 1 else "inertia"
    if "dosunit" in path:
        return "dosunit"
    if "compiler_flag" in path or "compiler_match" in path:
        return "compiler-flags"
    if path.startswith(("scripts/", "tools/dev/", "tests/")) or path in {"Makefile", "pyproject.toml"}:
        return "tooling/gates"
    return "project"


def _module_layer(module: str) -> str | None:
    """Map an imported project module to a conservative owner layer."""

    if module.startswith("inertia."):
        return "/".join(module.split(".")[:2])
    if "dosunit" in module:
        return "dosunit"
    if "compiler_flag" in module or "compiler_match" in module:
        return "compiler-flags"
    if module.startswith(("scripts.", "tools.dev.")):
        return "tooling/gates"
    return None


def _build_ownership_target_index() -> Mapping[str, tuple[_OwnershipTarget, ...]]:
    """Index reviewed ownership contracts by test path once per process."""

    by_path: dict[str, list[_OwnershipTarget]] = {}
    for rule in TEST_OWNERSHIP_RULES:
        layers = tuple(sorted({_owned_path_layer(path) for path in rule.paths}))
        for target in rule.tests:
            parts = target.split("::")
            by_path.setdefault(parts[0], []).append(
                _OwnershipTarget(selector="::".join(parts[1:]), owner=rule.owner, layers=layers)
            )
    return MappingProxyType({path: tuple(targets) for path, targets in by_path.items()})


_OWNERSHIP_TARGETS: Final[Mapping[str, tuple[_OwnershipTarget, ...]]] = _build_ownership_target_index()


def _ownership_metadata(path: str, nodeid: str) -> tuple[list[str], list[str]]:
    """Return reviewed owner contracts and layers that include this node."""

    selector = "::".join(
        part.split("[", 1)[0].split("@", 1)[0] for part in nodeid.split("::")[1:]
    )
    owners: set[str] = set()
    layers: set[str] = set()
    for target in _OWNERSHIP_TARGETS.get(path, ()):
        if not target.selector or target.selector == selector:
            owners.add(target.owner)
            layers.update(target.layers)
    return sorted(owners), sorted(layers)


def _inventory_hints(path: str, nodeid: str) -> tuple[str, str, list[str], PytestNodeFacts]:
    """Derive conservative purpose, owner, evidence, and cost hints."""

    selector = "::".join(nodeid.split("::")[1:])
    facts = load_pytest_source_index(REPO_ROOT / path, frozenset()).facts(selector)
    lowered = " ".join(
        (
            path,
            nodeid,
            *facts.effective_call_names,
            *facts.effective_input_hints,
            *facts.effective_option_hints,
        )
    ).lower()
    if "architecture" in lowered or "ownership_manifest" in lowered:
        purpose = "repository-contract"
        owner = "tooling/gates"
    elif "sortdemo" in lowered or "msc6" in lowered or "recompil" in lowered:
        purpose = "whole-file-acceptance"
        owner = "inertia/cli"
    elif "tail_validation" in lowered or "validation" in lowered:
        purpose = "validation-contract"
        owner = "inertia/validation"
    elif "cache" in lowered:
        purpose = "cache-contract"
        owner = "inertia/cli"
    elif "/tests/" in f"/{path}" or path.startswith("tests/"):
        purpose = "unit-or-layer-contract"
        owner = "test-owner-undetermined"
    else:
        purpose = "unclassified"
        owner = "owner-undetermined"

    return purpose, owner, _inventory_evidence(facts, lowered), facts


def _inventory_evidence(facts: PytestNodeFacts, lowered: str) -> list[str]:
    """Collect assertion and observed-purpose evidence without assigning owners."""
    evidence: set[str] = set(facts.evidence_hints)
    if facts.effective_assertion_count > 0:
        evidence.add("assertion")
    if facts.effective_expectation_count > 0:
        evidence.add("explicit-expectation")
    if not evidence and facts.call_names:
        evidence.add("completion-without-exception")
    for token, label in (
        ("tail", "tail-validation"),
        ("compile", "recompilation"),
        ("exitcode", "exit-code"),
        ("returncode", "exit-code"),
        ("stderr", "diagnostics"),
        ("stdout", "output"),
        ("sidecar", "sidecar-evidence"),
        ("source", "source-oracle"),
    ):
        if token in lowered:
            evidence.add(label)
    return sorted(evidence)


def record_for_item(item: pytest.Item) -> TestRecord:
    """Build one static inventory record from a collected pytest item."""

    location = item.location
    line = int(location[1]) + 1 if location[1] is not None else None
    markers = sorted(mark.name for mark in item.iter_markers())
    keywords = sorted(str(keyword) for keyword in item.keywords)
    path = str((REPO_ROOT / location[0]).resolve().relative_to(REPO_ROOT))
    purpose, owner_layer, evidence, facts = _inventory_hints(path, item.nodeid)
    owner_contracts, owner_layers = _ownership_metadata(path, item.nodeid)
    reviewed_module_layers = list(REVIEWED_TEST_MODULE_LAYERS.get(path, ()))
    if not owner_layers:
        owner_layers = reviewed_module_layers or sorted(
            {layer for module in facts.module_hints if (layer := _module_layer(module)) is not None}
        )
    if owner_layers:
        owner_layer = owner_layers[0] if len(owner_layers) == 1 else "multiple-owned-layers"
    has_contract_evidence = bool(evidence)
    if owner_contracts and owner_layers and has_contract_evidence:
        inventory_status = "reviewed-manifest"
    elif reviewed_module_layers and has_contract_evidence:
        inventory_status = "reviewed-module"
    elif not owner_layer.endswith("undetermined") and has_contract_evidence:
        inventory_status = "classified-static"
    else:
        inventory_status = "review-needed"
    direct_addresses = concrete_function_addresses(item, facts.function_address_hints)
    effective_addresses = concrete_function_addresses(item, facts.effective_function_address_hints)
    return TestRecord(
        nodeid=item.nodeid,
        path=path,
        line=line,
        markers=markers,
        keywords=keywords,
        purpose=purpose,
        owner_layer=owner_layer,
        owner_layers=owner_layers,
        owner_contracts=owner_contracts,
        evidence=evidence,
        required_pipeline_evidence=evidence,
        inventory_status=inventory_status,
        direct_static_subprocess_count=facts.subprocess_call_count,
        static_subprocess_count=facts.effective_subprocess_call_count,
        assertion_count=facts.assertion_count,
        effective_assertion_count=facts.effective_assertion_count,
        assertion_kinds=list(facts.assertion_kinds),
        expectation_count=facts.expectation_count,
        effective_expectation_count=facts.effective_expectation_count,
        expectation_kinds=list(facts.expectation_kinds),
        assertion_sources=list(facts.assertion_sources),
        cost_sources=list(facts.cost_sources),
        direct_function_address_hints=list(direct_addresses),
        function_address_hints=list(effective_addresses),
        direct_input_hints=list(facts.input_hints),
        input_hints=list(facts.effective_input_hints),
        direct_option_hints=list(facts.option_hints),
        option_hints=list(facts.effective_option_hints),
        cache_hints=[name for name in facts.effective_call_names if "cache" in name.lower()],
        module_hints=list(facts.module_hints),
    )
