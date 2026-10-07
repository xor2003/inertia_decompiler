"""Define the serialized pytest purpose and execution record.

Layer: Tooling/gates.
Responsibility: keep one typed schema for static test facts and measured runtime
cost without owning collection or classification policy.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class TestRecord:
    """Accumulate collection and execution evidence for one pytest node."""

    nodeid: str
    path: str
    line: int | None
    markers: list[str]
    keywords: list[str]
    purpose: str
    owner_layer: str
    owner_layers: list[str]
    owner_contracts: list[str]
    evidence: list[str]
    required_pipeline_evidence: list[str]
    inventory_status: str
    direct_static_subprocess_count: int
    static_subprocess_count: int
    assertion_count: int
    effective_assertion_count: int
    assertion_kinds: list[str]
    expectation_count: int
    effective_expectation_count: int
    expectation_kinds: list[str]
    assertion_sources: list[str]
    cost_sources: list[str]
    direct_function_address_hints: list[int]
    function_address_hints: list[int]
    direct_input_hints: list[str]
    input_hints: list[str]
    direct_option_hints: list[str]
    option_hints: list[str]
    cache_hints: list[str]
    module_hints: list[str]
    cache_keys: list[str] = field(default_factory=list)
    cache_operations: list[dict[str, object]] = field(default_factory=list)
    cache_hit_count: int = 0
    cache_miss_count: int = 0
    cache_invalid_count: int = 0
    cache_store_count: int = 0
    cache_store_failed_count: int = 0
    validation_statuses: list[str] = field(default_factory=list)
    setup_seconds: float = 0.0
    call_seconds: float = 0.0
    teardown_seconds: float = 0.0
    outcome: str = "not-run"
    was_skipped: bool = False
    was_xfailed: bool = False
    failure_count: int = 0
    rss_start_kib: int | None = None
    rss_peak_kib: int | None = None
    rss_finish_kib: int | None = None
    child_cpu_measured: bool = False
    child_user_seconds: float = 0.0
    child_system_seconds: float = 0.0

    @property
    def total_seconds(self) -> float:
        """Return observed setup, call, and teardown time."""

        return self.setup_seconds + self.call_seconds + self.teardown_seconds

    @property
    def child_cpu_seconds(self) -> float:
        """Return measured user plus system CPU consumed by waited descendants."""

        return self.child_user_seconds + self.child_system_seconds

    def record_child_cpu(self, *, user_seconds: float, system_seconds: float) -> None:
        """Accumulate one complete test-protocol child-CPU measurement."""

        self.child_cpu_measured = True
        self.child_user_seconds += user_seconds
        self.child_system_seconds += system_seconds

    def as_dict(self) -> dict[str, Any]:
        """Serialize stable inventory fields and measured timings."""

        return {
            "nodeid": self.nodeid,
            "path": self.path,
            "line": self.line,
            "markers": self.markers,
            "keywords": self.keywords,
            "purpose": self.purpose,
            "owner_layer": self.owner_layer,
            "owner_layers": self.owner_layers,
            "owner_contracts": self.owner_contracts,
            "evidence": self.evidence,
            "required_pipeline_evidence": self.required_pipeline_evidence,
            "inventory_status": self.inventory_status,
            "direct_static_subprocess_count": self.direct_static_subprocess_count,
            "static_subprocess_count": self.static_subprocess_count,
            "assertion_count": self.assertion_count,
            "effective_assertion_count": self.effective_assertion_count,
            "assertion_kinds": self.assertion_kinds,
            "expectation_count": self.expectation_count,
            "effective_expectation_count": self.effective_expectation_count,
            "expectation_kinds": self.expectation_kinds,
            "assertion_sources": self.assertion_sources,
            "cost_sources": self.cost_sources,
            "direct_function_address_hints": self.direct_function_address_hints,
            "function_address_hints": self.function_address_hints,
            "direct_input_hints": self.direct_input_hints,
            "input_hints": self.input_hints,
            "direct_option_hints": self.direct_option_hints,
            "option_hints": self.option_hints,
            "cache_hints": self.cache_hints,
            "module_hints": self.module_hints,
            "cache_keys": self.cache_keys,
            "cache_operations": self.cache_operations,
            "cache_hit_count": self.cache_hit_count,
            "cache_miss_count": self.cache_miss_count,
            "cache_invalid_count": self.cache_invalid_count,
            "cache_store_count": self.cache_store_count,
            "cache_store_failed_count": self.cache_store_failed_count,
            "validation_statuses": self.validation_statuses,
            "setup_seconds": self.setup_seconds,
            "call_seconds": self.call_seconds,
            "teardown_seconds": self.teardown_seconds,
            "total_seconds": self.total_seconds,
            "outcome": self.outcome,
            "was_skipped": self.was_skipped,
            "was_xfailed": self.was_xfailed,
            "failure_count": self.failure_count,
            "rss_start_kib": self.rss_start_kib,
            "rss_peak_kib": self.rss_peak_kib,
            "rss_finish_kib": self.rss_finish_kib,
            "rss_delta_kib": (
                self.rss_finish_kib - self.rss_start_kib
                if self.rss_start_kib is not None and self.rss_finish_kib is not None
                else None
            ),
            "child_cpu_measured": self.child_cpu_measured,
            "child_user_seconds": self.child_user_seconds,
            "child_system_seconds": self.child_system_seconds,
            "child_cpu_seconds": self.child_cpu_seconds,
        }
