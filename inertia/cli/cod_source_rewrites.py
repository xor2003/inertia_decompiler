"""Layer: Optional evidence/reporting.

Responsibility: expose inactive source-backed rewrite debt as an explicit compatibility surface.
Forbidden: active source-backed C body replacement or semantic recovery.

Package ownership contract (canonical inertia/cli package):
Layer: CLI/fallback/reporting.
Owns command entrypoints, fallback orchestration, diagnostics, and reporting of recovered evidence.
Do not perform frontend, IR, semantic, alias, widening, lowering, structuring, rewrite,
postprocess, or validation work here.
"""

from __future__ import annotations

from collections.abc import ItemsView, Iterator, KeysView, Mapping, ValuesView
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType

from inertia.frontend.x86_16.cod_extract import CODProcMetadata

__all__ = [
    "COD_SOURCE_REWRITE_REGISTRY",
    "COD_SOURCE_REWRITE_SPECS",
    "COD_SOURCE_REWRITE_SPECS_BY_NAME",
    "CODSourceRewriteRegistry",
    "CODSourceRewriteSpec",
    "CODSourceRewriteStatus",
    "CODSourceRewriteStatusKind",
    "apply_cod_source_rewrites",
    "cod_source_rewrite_description",
    "cod_source_rewrite_names",
    "cod_source_rewrite_summary",
    "describe_x86_16_source_backed_rewrite_debt",
    "describe_x86_16_source_backed_rewrite_status",
    "get_cod_source_rewrite_spec",
    "rewrite_cod_proc_from_source",
    "rewrite_cod_source_stage",
    "rewrite_known_cod_object_bindings_from_source",
    "rewrite_known_cod_object_condition_blocks_from_source",
    "rewrite_known_cod_object_fields_from_source",
]


class CODSourceRewriteStatusKind(StrEnum):
    """Lifecycle state for disabled source-backed rewrite debt."""

    TEMPORARY_RESCUE = "temporary_rescue"
    PERMANENT_GUARDED_ORACLE = "permanent_guarded_oracle"
    ALREADY_SUBSUMED_BY_GENERAL_RECOVERY = "already_subsumed_by_general_recovery"

    @classmethod
    def coerce(cls, value: object) -> CODSourceRewriteStatusKind:
        """Normalize legacy status values into the typed rewrite-status enum."""
        if isinstance(value, cls):
            return value
        if value is None:
            return cls.TEMPORARY_RESCUE
        return cls(str(value))

    @property
    def is_active(self) -> bool:
        """Return whether this status still represents active rewrite debt."""
        return self in {self.TEMPORARY_RESCUE, self.PERMANENT_GUARDED_ORACLE}


@dataclass(frozen=True)
class CODSourceRewriteSpec:
    """Disabled source-backed rewrite specification retained as explicit debt."""

    name: str
    header_regex: str
    rewritten: str
    rewrite_status: CODSourceRewriteStatusKind = CODSourceRewriteStatusKind.TEMPORARY_RESCUE
    required_lines: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Normalize the stored rewrite status after dataclass initialization."""
        object.__setattr__(self, "rewrite_status", CODSourceRewriteStatusKind.coerce(self.rewrite_status))

    def apply(self, c_text: str, metadata: CODProcMetadata | None) -> str:
        """Apply this disabled compatibility spec; currently returns text unchanged."""
        return rewrite_cod_proc_from_source(
            c_text,
            metadata,
            header_regex=self.header_regex,
            rewritten=self.rewritten,
            required_lines=self.required_lines,
        )

    def __repr__(self) -> str:
        """Return a compact debug representation of the disabled rewrite spec."""
        return (
            f"CODSourceRewriteSpec(name={self.name!r}, "
            f"rewrite_status={self.rewrite_status.value!r}, "
            f"required_lines={self.required_lines!r})"
        )


@dataclass(frozen=True, slots=True)
class CODSourceRewriteStatus:
    """Serializable status row for source-backed rewrite debt reporting."""

    name: str
    rewrite_status: CODSourceRewriteStatusKind
    required_lines: tuple[str, ...] = ()
    header_regex: str = ""
    owner: str = "source-backed rewrite compatibility surface"

    def __post_init__(self) -> None:
        """Normalize the stored rewrite status after dataclass initialization."""
        object.__setattr__(self, "rewrite_status", CODSourceRewriteStatusKind.coerce(self.rewrite_status))


@dataclass(frozen=True)
class CODSourceRewriteRegistry:
    """Immutable registry for disabled source-backed rewrite specs."""

    specs: tuple[CODSourceRewriteSpec, ...]
    by_name: Mapping[str, CODSourceRewriteSpec]

    def apply(self, c_text: str, metadata: CODProcMetadata | None) -> str:
        """Apply registered disabled rewrites; source-backed rewrites are intentionally inert."""
        return c_text

    def get(self, name: str) -> CODSourceRewriteSpec:
        """Return the disabled rewrite spec for an exact name."""
        return self.by_name[name]

    def names(self) -> tuple[str, ...]:
        """Return registered disabled rewrite names in deterministic order."""
        return tuple(self.by_name)

    def keys(self) -> KeysView[str]:
        """Return registry name view for mapping-compatible callers."""
        return self.by_name.keys()

    def values(self) -> ValuesView[CODSourceRewriteSpec]:
        """Return registry spec view for mapping-compatible callers."""
        return self.by_name.values()

    def items(self) -> ItemsView[str, CODSourceRewriteSpec]:
        """Return registry item view for mapping-compatible callers."""
        return self.by_name.items()

    def __getitem__(self, name: str) -> CODSourceRewriteSpec:
        """Return the disabled rewrite spec for mapping-style access."""
        return self.get(name)

    def __contains__(self, name: object) -> bool:
        """Return whether a disabled rewrite spec name is registered."""
        return isinstance(name, str) and name in self.by_name

    def __iter__(self) -> Iterator[CODSourceRewriteSpec]:
        """Iterate disabled rewrite specs in deterministic order."""
        return iter(self.specs)

    def __len__(self) -> int:
        """Return the disabled rewrite spec count."""
        return len(self.specs)

    def summary(self) -> dict[str, object]:
        """Summarize disabled source-backed rewrite debt for architecture reports."""
        rows = _source_backed_rewrite_status_rows_8616(self.specs)
        status_counts: dict[str, int] = {}
        for row in rows:
            status = row.rewrite_status.value
            status_counts[status] = status_counts.get(status, 0) + 1
        return {
            "count": len(rows),
            "names": tuple(row.name for row in rows),
            "status_counts": dict(sorted(status_counts.items())),
            "active_count": sum(1 for row in rows if row.rewrite_status.is_active),
            "oracle_count": sum(
                1 for row in rows if row.rewrite_status is CODSourceRewriteStatusKind.PERMANENT_GUARDED_ORACLE
            ),
            "subsumed_count": sum(
                1
                for row in rows
                if row.rewrite_status is CODSourceRewriteStatusKind.ALREADY_SUBSUMED_BY_GENERAL_RECOVERY
            ),
        }

    def describe(self) -> dict[str, object]:
        """Describe disabled source-backed rewrite specs for audit output."""
        rows = _source_backed_rewrite_status_rows_8616(self.specs)
        return {
            "count": len(rows),
            "names": tuple(row.name for row in rows),
            "specs": tuple(
                {
                    "name": row.name,
                    "rewrite_status": row.rewrite_status.value,
                    "required_lines": row.required_lines,
                    "header_regex": row.header_regex,
                    "owner": row.owner,
                }
                for row in rows
            ),
        }

    def __repr__(self) -> str:
        """Return a compact debug representation of the disabled rewrite registry."""
        return f"CODSourceRewriteRegistry(count={len(self.specs)}, names={self.names()!r})"


COD_SOURCE_REWRITE_SPECS: tuple[CODSourceRewriteSpec, ...] = ()

COD_SOURCE_REWRITE_SPECS_BY_NAME: Mapping[str, CODSourceRewriteSpec] = MappingProxyType(
    {spec.name: spec for spec in COD_SOURCE_REWRITE_SPECS}
)

COD_SOURCE_REWRITE_REGISTRY: CODSourceRewriteRegistry = CODSourceRewriteRegistry(
    specs=COD_SOURCE_REWRITE_SPECS,
    by_name=MappingProxyType(COD_SOURCE_REWRITE_SPECS_BY_NAME),
)


def _source_backed_rewrite_status_rows_8616(
    specs: tuple[CODSourceRewriteSpec, ...]
) -> tuple[CODSourceRewriteStatus, ...]:
    """Build typed status rows for disabled source-backed rewrite specs."""
    return tuple(
        CODSourceRewriteStatus(
            name=spec.name,
            rewrite_status=spec.rewrite_status,
            required_lines=spec.required_lines,
            header_regex=spec.header_regex,
            owner="disabled source-backed rewrite registry",
        )
        for spec in specs
    )


def get_cod_source_rewrite_spec(name: str) -> CODSourceRewriteSpec:
    """Return a disabled COD source rewrite spec by name."""
    return COD_SOURCE_REWRITE_REGISTRY.get(name)


def apply_cod_source_rewrites(c_text: str, metadata: CODProcMetadata | None) -> str:
    """Apply the disabled COD source rewrite stage without changing generated C."""
    return rewrite_cod_source_stage(c_text, metadata)


def rewrite_cod_source_stage(c_text: str, metadata: CODProcMetadata | None) -> str:
    """Keep generated C unchanged because source-backed rewrites are forbidden."""
    return c_text


def cod_source_rewrite_summary() -> dict[str, object]:
    """Return summary counters for disabled source-backed rewrite debt."""
    return COD_SOURCE_REWRITE_REGISTRY.summary()


def cod_source_rewrite_description() -> dict[str, object]:
    """Return detailed rows for disabled source-backed rewrite debt."""
    return COD_SOURCE_REWRITE_REGISTRY.describe()


def cod_source_rewrite_names() -> tuple[str, ...]:
    """Return disabled source-backed rewrite names in deterministic order."""
    return COD_SOURCE_REWRITE_REGISTRY.names()


def describe_x86_16_source_backed_rewrite_status() -> dict[str, object]:
    """Describe the disabled source-backed rewrite compatibility surface."""
    registry_description = COD_SOURCE_REWRITE_REGISTRY.describe()
    registry_summary = COD_SOURCE_REWRITE_REGISTRY.summary()
    return {
        "count": registry_description["count"],
        "names": registry_description["names"],
        "specs": registry_description["specs"],
        "status_counts": registry_summary["status_counts"],
        "active_count": registry_summary["active_count"],
        "oracle_count": registry_summary["oracle_count"],
        "subsumed_count": registry_summary["subsumed_count"],
    }


def describe_x86_16_source_backed_rewrite_debt() -> dict[str, object]:
    """Return architecture-debt details for disabled source-backed rewrites."""
    summary = COD_SOURCE_REWRITE_REGISTRY.summary()
    rows = _source_backed_rewrite_status_rows_8616(COD_SOURCE_REWRITE_REGISTRY.specs)
    active_names = tuple(row.name for row in rows if row.rewrite_status.is_active)
    oracle_names = tuple(
        row.name for row in rows if row.rewrite_status is CODSourceRewriteStatusKind.PERMANENT_GUARDED_ORACLE
    )
    subsumed_names = tuple(
        row.name
        for row in rows
        if row.rewrite_status is CODSourceRewriteStatusKind.ALREADY_SUBSUMED_BY_GENERAL_RECOVERY
    )
    return {
        **summary,
        "active_names": active_names,
        "oracle_names": oracle_names,
        "subsumed_names": subsumed_names,
    }


def rewrite_cod_proc_from_source(
    c_text: str,
    metadata: CODProcMetadata | None,
    *,
    header_regex: str,
    rewritten: str,
    required_lines: tuple[str, ...] = (),
) -> str:
    """Refuse source-backed procedure replacement and return generated C unchanged."""
    return c_text


def rewrite_known_cod_object_fields_from_source(c_text: str, metadata: CODProcMetadata | None) -> str:
    """Refuse source-backed object-field rewrites and return generated C unchanged."""
    return c_text


def rewrite_known_cod_object_bindings_from_source(c_text: str, metadata: CODProcMetadata | None) -> str:
    """Refuse source-backed object-binding rewrites and return generated C unchanged."""
    return c_text


def rewrite_known_cod_object_condition_blocks_from_source(c_text: str, metadata: CODProcMetadata | None) -> str:
    """Refuse source-backed condition-block rewrites and return generated C unchanged."""
    return c_text
