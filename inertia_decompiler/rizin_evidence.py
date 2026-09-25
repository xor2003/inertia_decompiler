"""Collect optional rizin evidence for diagnostics and candidate ranking.

Layer: CLI/fallback/reporting.
Responsibility: collect optional rizin diagnostics without making them semantic proof.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

_RIZIN_FUNCTION_ANALYSIS_COMMAND = "aa;aflj"


class RizinEvidenceStatus(Enum):
    """Status of one optional rizin evidence collection attempt."""

    OK = "ok"
    UNAVAILABLE = "unavailable"
    TIMEOUT = "timeout"
    ERROR = "error"


@dataclass(frozen=True)
class RizinFunctionFact:
    """Function-level fact reported by rizin for diagnostics."""

    addr: int
    size: int
    name: str
    n_blocks: int
    n_callrefs: int


@dataclass(frozen=True)
class RizinXrefFact:
    """Cross-reference fact reported by rizin for diagnostics."""

    src: int
    dst: int
    kind: str


@dataclass(frozen=True)
class RizinStringFact:
    """String fact reported by rizin for diagnostics."""

    vaddr: int
    value: str


@dataclass(frozen=True)
class RizinSymbolFact:
    """Symbol fact reported by rizin for diagnostics."""

    vaddr: int
    name: str
    kind: str


@dataclass(frozen=True)
class RizinStackVarFact:
    """Stack-variable fact reported by rizin for diagnostics."""

    function_addr: int
    name: str
    kind: str
    offset: int | None


@dataclass(frozen=True)
class RizinCcFact:
    """Calling-convention fact reported by rizin for diagnostics."""

    function_addr: int
    cc: str
    nargs: int | None


@dataclass(frozen=True)
class RizinEvidence:
    """Collected optional rizin evidence for one binary."""

    status: RizinEvidenceStatus
    elapsed_ms: float
    detail: str
    functions: tuple[RizinFunctionFact, ...]
    xrefs: tuple[RizinXrefFact, ...]
    strings: tuple[RizinStringFact, ...]
    symbols: tuple[RizinSymbolFact, ...]
    stack_vars: tuple[RizinStackVarFact, ...]
    calling_conventions: tuple[RizinCcFact, ...]

    @property
    def function_offsets(self) -> tuple[int, ...]:
        """Return discovered function offsets from optional rizin evidence."""
        return tuple(f.addr for f in self.functions)

    @property
    def function_name_by_addr(self) -> dict[int, str]:
        """Return rizin function names keyed by address."""
        out: dict[int, str] = {}
        for fact in self.functions:
            if fact.name:
                out[fact.addr] = fact.name
        return out


def _rizin_available() -> bool:
    return shutil.which("rizin") is not None


def _run_json(binary_path: Path, command: str, *, timeout_sec: int) -> object:
    cmd = ["rizin", "-2", "-q", "-c", command, str(binary_path)]
    completed = subprocess.run(
        cmd,
        check=False,
        capture_output=True,
        text=True,
        timeout=max(1, int(timeout_sec)),
    )
    if completed.returncode != 0:
        return None
    try:
        return json.loads(completed.stdout)
    except Exception:
        return None


def _empty_evidence(status: RizinEvidenceStatus, elapsed_ms: float, detail: str) -> RizinEvidence:
    """Return an evidence record carrying only a status and detail."""
    return RizinEvidence(
        status=status,
        elapsed_ms=elapsed_ms,
        detail=detail,
        functions=(),
        xrefs=(),
        strings=(),
        symbols=(),
        stack_vars=(),
        calling_conventions=(),
    )


def _optional_int(raw: object) -> int | None:
    """Decode an optional integer field without failing the fact."""
    if raw is None:
        return None
    try:
        return int(raw)
    except Exception:
        return None


def _function_facts(payload: object) -> tuple[RizinFunctionFact, ...]:
    """Decode function facts from the aflj payload."""
    facts: list[RizinFunctionFact] = []
    if isinstance(payload, list):
        for item in payload:
            if not isinstance(item, dict):
                continue
            try:
                addr = int(item.get("offset", 0) or 0)
            except Exception:
                continue
            if addr <= 0:
                continue
            facts.append(
                RizinFunctionFact(
                    addr=addr,
                    size=int(item.get("size", 0) or 0),
                    name=str(item.get("name", "") or ""),
                    n_blocks=int(item.get("nbbs", 0) or 0),
                    n_callrefs=int(item.get("ncallrefs", 0) or 0),
                )
            )
    return tuple(facts)


def _xref_facts(payload: object) -> tuple[RizinXrefFact, ...]:
    """Decode cross-reference facts from the axtj payload."""
    facts: list[RizinXrefFact] = []
    if isinstance(payload, list):
        for item in payload:
            if not isinstance(item, dict):
                continue
            src = int(item.get("from", 0) or 0)
            dst = int(item.get("to", 0) or 0)
            if src > 0 and dst > 0:
                facts.append(RizinXrefFact(src=src, dst=dst, kind=str(item.get("type", "") or "")))
    return tuple(facts)


def _string_facts(payload: object) -> tuple[RizinStringFact, ...]:
    """Decode string facts from the izj payload."""
    facts: list[RizinStringFact] = []
    if isinstance(payload, list):
        for item in payload:
            if not isinstance(item, dict):
                continue
            vaddr = int(item.get("vaddr", 0) or 0)
            value = str(item.get("string", "") or "")
            if vaddr > 0 and value:
                facts.append(RizinStringFact(vaddr=vaddr, value=value))
    return tuple(facts)


def _symbol_facts(payload: object) -> tuple[RizinSymbolFact, ...]:
    """Decode symbol facts from the isj payload."""
    facts: list[RizinSymbolFact] = []
    if isinstance(payload, list):
        for item in payload:
            if not isinstance(item, dict):
                continue
            vaddr = int(item.get("vaddr", 0) or 0)
            name = str(item.get("name", "") or "")
            if vaddr > 0 and name:
                facts.append(RizinSymbolFact(vaddr=vaddr, name=name, kind=str(item.get("type", "") or "")))
    return tuple(facts)


def _stack_var_facts(payload: object) -> tuple[RizinStackVarFact, ...]:
    """Decode stack-variable facts from the afvrj payload."""
    facts: list[RizinStackVarFact] = []
    if isinstance(payload, list):
        for item in payload:
            if not isinstance(item, dict):
                continue
            fn = int(item.get("fcn_addr", 0) or 0)
            name = str(item.get("name", "") or "")
            if fn <= 0 or not name:
                continue
            facts.append(
                RizinStackVarFact(
                    function_addr=fn,
                    name=name,
                    kind=str(item.get("kind", "") or ""),
                    offset=_optional_int(item.get("delta", None)),
                )
            )
    return tuple(facts)


def _cc_facts(payload: object) -> tuple[RizinCcFact, ...]:
    """Decode calling-convention facts from the afcfj payload."""
    facts: list[RizinCcFact] = []
    if isinstance(payload, list):
        for item in payload:
            if not isinstance(item, dict):
                continue
            fn = int(item.get("addr", 0) or 0)
            if fn <= 0:
                continue
            facts.append(
                RizinCcFact(
                    function_addr=fn,
                    cc=str(item.get("cc", "") or ""),
                    nargs=_optional_int(item.get("nargs", None)),
                )
            )
    return tuple(facts)


def collect_rizin_evidence(binary_path: Path, *, timeout_sec: int = 8) -> RizinEvidence:
    """Collect optional rizin facts for diagnostics and candidate ranking."""
    started = time.perf_counter()
    if not _rizin_available():
        return _empty_evidence(RizinEvidenceStatus.UNAVAILABLE, 0.0, "rizin not found")
    try:
        # Aggressive Rizin analysis is not segment-safe for DOS MZ binaries.
        # Collect conservative function facts; they remain optional evidence.
        fn_payload = _run_json(binary_path, _RIZIN_FUNCTION_ANALYSIS_COMMAND, timeout_sec=timeout_sec)
        xref_payload = _run_json(binary_path, "axtj", timeout_sec=timeout_sec)
        str_payload = _run_json(binary_path, "izj", timeout_sec=timeout_sec)
        sym_payload = _run_json(binary_path, "isj", timeout_sec=timeout_sec)
        # `afvrj` and `afcfj` are function-scoped in rizin. If unavailable, keep empty.
        stack_payload = _run_json(binary_path, "afvrj", timeout_sec=timeout_sec)
        cc_payload = _run_json(binary_path, "afcfj", timeout_sec=timeout_sec)
    except subprocess.TimeoutExpired:
        return _empty_evidence(
            RizinEvidenceStatus.TIMEOUT,
            (time.perf_counter() - started) * 1000.0,
            "subprocess timeout",
        )
    except Exception as ex:
        return _empty_evidence(
            RizinEvidenceStatus.ERROR,
            (time.perf_counter() - started) * 1000.0,
            str(ex),
        )

    return RizinEvidence(
        status=RizinEvidenceStatus.OK,
        elapsed_ms=(time.perf_counter() - started) * 1000.0,
        detail="ok",
        functions=_function_facts(fn_payload),
        xrefs=_xref_facts(xref_payload),
        strings=_string_facts(str_payload),
        symbols=_symbol_facts(sym_payload),
        stack_vars=_stack_var_facts(stack_payload),
        calling_conventions=_cc_facts(cc_payload),
    )
