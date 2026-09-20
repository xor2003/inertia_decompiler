"""Layer: Tooling/gates.

Responsibility: check emitted SORTD function contracts against regression oracles.
These checks diagnose output only and never participate in semantic recovery.
"""

from __future__ import annotations

import re

from scripts.runmenu_behavior import RunMenuExecutionEvidence

_WORD_TYPE_RE = r"(?:unsigned\s+)?short"
_RUNMENU_SIGNATURE_RE = re.compile(r"\bvoid\s+sub_102e0\s*\(\s*void\s*\)")
_RUNMENU_EXIT_CASE_RE = re.compile(r"\bcase\s+27\s*:\s*return\s*;")
_RUNMENU_REDUNDANT_TAIL_RE = re.compile(
    r"\b(?:goto\s+LABEL_10488|LABEL_10488\s*:)", re.IGNORECASE
)
_DRAWTIME_SIGNATURE_RE = re.compile(
    rf"\bvoid\s+sub_10498\s*\(\s*(?P<row_type>{_WORD_TYPE_RE})\s+(?P<row>[A-Za-z_]\w*)\s*\)"
)
_EMPTY_IF_ELSE_RE = re.compile(r"\bif\s*\([^{};]*\)\s*\{\s*\}\s*else\s*\{\s*\}")
_RAW_SS_LINEAR_RE = re.compile(r"\binertia_ss\s*<<\s*4\b")
_BEEP_SIGNATURE_RE = re.compile(
    rf"\bvoid\s+sub_10e70\s*\(\s*{_WORD_TYPE_RE}\s+(?P<frequency>[A-Za-z_]\w*)\s*,\s*"
    rf"{_WORD_TYPE_RE}\s+(?P<duration>[A-Za-z_]\w*)\s*\)"
)
_UNINITIALIZED_BP4_LOCAL_RE = re.compile(r"^[^/\n;]+;\s*//\s*\[bp\+0x4\]", re.MULTILINE)



def runmenu_contract_violations(
    runmenu_segment: str, runmenu_execution: RunMenuExecutionEvidence | None,
) -> list[str]:
    """Require the emitted void menu to preserve ESC behavior and execution."""
    violations: list[str] = []
    escape_proven = (
        runmenu_execution.accepts(runmenu_segment)
        if runmenu_execution is not None
        else _RUNMENU_EXIT_CASE_RE.search(runmenu_segment) is not None
    )
    if not _RUNMENU_SIGNATURE_RE.search(runmenu_segment) or not escape_proven:
        violations.append("RunMenu lacks its void binary-proven ESC exit")
    if runmenu_execution is not None and runmenu_execution.failure is not None:
        violations.append(f"RunMenu execution gate failed: {runmenu_execution.failure}")
    if _RUNMENU_REDUNDANT_TAIL_RE.search(runmenu_segment):
        violations.append("RunMenu retains a redundant switch-to-loop-tail goto")
    return violations


def drawtime_contract_violations(drawtime_segment: str) -> list[str]:
    """Require canonical arguments and the exact frequency and duration call."""
    violations: list[str] = []
    drawtime_signature = _DRAWTIME_SIGNATURE_RE.search(drawtime_segment)
    if drawtime_signature is None or _UNINITIALIZED_BP4_LOCAL_RE.search(drawtime_segment):
        violations.append("DrawTime lacks its canonical void positive-BP signature")
    elif re.search(
        rf"\bsub_10e70\s*\(\s*(?P<wrapped>\()?\s*"
        rf"(?:\(\s*{re.escape(drawtime_signature.group('row_type'))}\s*\)\s*)?"
        rf"{re.escape(drawtime_signature.group('row'))}\s*(?(wrapped)\))\s*\*\s*60\s*,\s*75\s*\)",
        drawtime_segment,
    ) is None:
        violations.append("DrawTime lacks its binary-proven frequency and duration arguments")
    if _EMPTY_IF_ELSE_RE.search(drawtime_segment):
        violations.append("DrawTime retains an empty flag-only branch")
    if _RAW_SS_LINEAR_RE.search(drawtime_segment):
        violations.append("DrawTime retains raw SS linear-address arithmetic")
    return violations


def beep_contract_violations(beep_segment: str) -> list[str]:
    """Require both positive-BP parameters and the minimum-duration guard."""
    violations: list[str] = []
    beep_signature = _BEEP_SIGNATURE_RE.search(beep_segment)
    if beep_signature is None or _UNINITIALIZED_BP4_LOCAL_RE.search(beep_segment):
        violations.append("Beep lacks its void two-argument positive-BP signature")
    elif re.search(rf"\bif\s*\(\s*{re.escape(beep_signature.group('duration'))}\s*<\s*75\s*\)", beep_segment) is None:
        violations.append("Beep lacks its binary-proven minimum-duration guard")
    return violations
