"""Layer: Recovery/reporting.

Responsibility: list golden readability anchors used by bounded diagnostics and tests.
Forbidden: substituting source-backed output or treating anchors as semantic proof.

Package ownership contract (canonical inertia/cli package):
Layer: CLI/fallback/reporting.
Owns command entrypoints, fallback orchestration, diagnostics, and reporting of recovered evidence.
Do not perform frontend, IR, semantic, alias, widening, lowering, structuring, rewrite,
postprocess, or validation work here.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class GoldenReadabilityCase:
    """Describe one bounded readability fixture and the anchors it should keep."""

    source: str
    proc_name: str
    anchors: tuple[str, ...]


GOLDEN_READABILITY_SET: tuple[GoldenReadabilityCase, ...] = (
    GoldenReadabilityCase(
        source="cod/f14/MONOPRIN.COD",
        proc_name="_mset_pos",
        anchors=(
            "% 80",
            "% 25",
            "int _mset_pos(int x, int y)",
            "[bp+0x4] = x",
            "[bp+0x6] = y",
        ),
    ),
    GoldenReadabilityCase(
        source="cod/f14/NHORZ.COD",
        proc_name="_ChangeWeather",
        anchors=(
            "if (BadWeather)",
            "BadWeather = 0;",
            "BadWeather = 1;",
            "CLOUDHEIGHT = 8150;",
            "CLOUDTHICK = 1000;",
        ),
    ),
    GoldenReadabilityCase(
        source="angr_platforms/x16_samples/ICOMDO.COM",
        proc_name="_start",
        anchors=(
            "dos_get_version()",
            'dos_print_dollar_string("DOS sample")',
            "dos_exit(0)",
        ),
    ),
    GoldenReadabilityCase(
        source="cod/f14/MAX.COD",
        proc_name="_max",
        anchors=(
            "if (x > y)",
            "return x;",
            "return y;",
        ),
    ),
    GoldenReadabilityCase(
        source="angr_platforms/x16_samples/COCKPIT.COD",
        proc_name="_ConfigCrts",
        anchors=(
            "for (i = 0; i < 8; i++)",
            "CrtDisplays[i] = CrtConfig[i];",
            "int i;",
        ),
    ),
)


def describe_x86_16_golden_readability_set() -> tuple[GoldenReadabilityCase, ...]:
    """Return the deterministic golden readability fixture set."""
    return GOLDEN_READABILITY_SET


def summarize_x86_16_golden_readability_set() -> tuple[tuple[str, str, int], ...]:
    """Return compact fixture summaries for reports and milestone checks."""
    return tuple((case.source, case.proc_name, len(case.anchors)) for case in GOLDEN_READABILITY_SET)


__all__ = [
    "GOLDEN_READABILITY_SET",
    "GoldenReadabilityCase",
    "describe_x86_16_golden_readability_set",
    "summarize_x86_16_golden_readability_set",
]
