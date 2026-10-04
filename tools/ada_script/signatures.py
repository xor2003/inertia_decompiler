"""Layer: optional signature evidence.

Responsibility: name ada_script library matches using the shared PAT engine,
preserving explicit annotations and recording ambiguity without changing semantics.
"""

from __future__ import annotations

import json
import sqlite3
from collections import defaultdict
from dataclasses import asdict, dataclass
from enum import StrEnum
from pathlib import Path

from inertia_decompiler.signature_matching_policy import signature_matching_disabled
from omf_pat import load_cached_pat_regex_specs, match_pat_modules


class MatchStatus(StrEnum):
    """Disposition of optional library naming evidence."""

    NAMED = "named"
    PRESERVED = "preserved_user_name"
    AMBIGUOUS = "ambiguous"
    COLLISION = "name_collision"
    DATA_CONFLICT = "data_conflict"


@dataclass(frozen=True)
class Candidate:
    """One public symbol returned by the shared, unique-body PAT matcher."""

    address: int
    name: str
    catalog: str
    source: str
    compiler: str
    function_start: bool


@dataclass(frozen=True)
class MatchEvidence:
    """Persistent evidence for one address, including rejected naming proposals."""

    address: int
    names: tuple[str, ...]
    status: MatchStatus
    candidates: tuple[Candidate, ...]


@dataclass(frozen=True)
class SignatureReport:
    """Counts separate proposed matches, materialized evidence and actual renames."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int
    named_count: int
    disabled: bool
    matches: tuple[MatchEvidence, ...]

    def write(self, path: Path) -> None:
        """Write stable naming provenance, never an equivalence verdict."""
        path.write_text(json.dumps({"schema": "inertia.ada.signatures.v1", **asdict(self)}, indent=2) + "\n")


def _collect_candidates(image: bytes, base: int, catalogs: tuple[Path, ...],
                        cache_dir: Path, backend: str | None) -> dict[int, list[Candidate]]:
    """Retain every catalog proposal instead of letting first-match naming win."""
    grouped: dict[int, list[Candidate]] = defaultdict(list)
    for catalog in sorted({path.resolve() for path in catalogs}):
        if not catalog.is_file():
            raise FileNotFoundError(f"Signature catalog not found: {catalog}")
        specs = load_cached_pat_regex_specs(catalog, cache_dir)
        for spec in specs:
            labels, ranges, _ = match_pat_modules(image, base, [spec], backend=backend)
            for address, name in labels.items():
                if not base <= address < base + len(image):
                    raise ValueError(f"Signature public address outside image: {address:#x} ({catalog})")
                grouped[address].append(Candidate(address, name, str(catalog), spec.source_path,
                                                    spec.compiler_name, address in ranges))
    return grouped


def _disposition(conn: sqlite3.Connection, address: int, names: tuple[str, ...]) -> MatchStatus:
    """Classify conflicts before modifying symbols or function names."""
    if len(names) != 1:
        return MatchStatus.AMBIGUOUS
    if conn.execute("SELECT 1 FROM data_items WHERE addr<=? AND addr+size*count>?",
                    (address, address)).fetchone():
        return MatchStatus.DATA_CONFLICT
    if conn.execute("SELECT 1 FROM symbols WHERE addr=? AND auto=0", (address,)).fetchone():
        return MatchStatus.PRESERVED
    if conn.execute("SELECT 1 FROM symbols WHERE addr<>? AND lower(name)=lower(?) UNION ALL "
                    "SELECT 1 FROM functions WHERE start<>? AND lower(name)=lower(?)",
                    (address, names[0], address, names[0])).fetchone():
        return MatchStatus.COLLISION
    return MatchStatus.NAMED


def _name_candidate(conn: sqlite3.Connection, address: int, name: str,
                    candidates: tuple[Candidate, ...]) -> None:
    """Publish optional labels before analyzer context and operand rendering."""
    conn.execute("INSERT INTO symbols(addr,name,auto,kind) VALUES(?,?,0,'name') "
                 "ON CONFLICT(addr) DO UPDATE SET name=excluded.name,auto=0,kind='name'", (address, name))
    conn.execute("UPDATE functions SET name=? WHERE start=?", (name, address))
    if any(candidate.function_start for candidate in candidates):
        # A module extent is not a proven function end. Let analysis recover it.
        conn.execute("INSERT OR IGNORE INTO functions(start,end,name,flags) VALUES(?,?,?,0)",
                     (address, address, name))
        conn.execute("INSERT OR IGNORE INTO code_seeds(addr) VALUES(?)", (address,))


def apply_signatures(conn: sqlite3.Connection, *, image: bytes, base: int,
                     catalogs: tuple[Path, ...], cache_dir: Path,
                     backend: str = "python_regex", enabled: bool = True) -> SignatureReport:
    """Apply unique names, retaining user names and all rejected evidence in SQLite."""
    disabled = not enabled or signature_matching_disabled()
    selected_backend = None if backend == "auto" else backend
    grouped = {} if disabled else _collect_candidates(image, base, catalogs, cache_dir, selected_backend)
    evidence: list[MatchEvidence] = []
    with conn:
        conn.execute("CREATE TABLE IF NOT EXISTS signature_matches "
                     "(addr INTEGER PRIMARY KEY, names TEXT NOT NULL, status TEXT NOT NULL, evidence TEXT NOT NULL)")
        conn.execute("DELETE FROM signature_matches")
        for address, proposals in sorted(grouped.items()):
            candidates = tuple(proposals)
            names = tuple(sorted({candidate.name for candidate in candidates}))
            status = _disposition(conn, address, names)
            if status == MatchStatus.NAMED:
                _name_candidate(conn, address, names[0], candidates)
            item = MatchEvidence(address, names, status, candidates)
            evidence.append(item)
            conn.execute("INSERT INTO signature_matches VALUES(?,?,?,?)",
                         (address, json.dumps(names), status.value, json.dumps(asdict(item))))
    rejected = {MatchStatus.AMBIGUOUS, MatchStatus.COLLISION, MatchStatus.DATA_CONFLICT}
    return SignatureReport(sum(len(items) for items in grouped.values()), len(grouped), len(evidence),
                           len(evidence), sum(item.status in rejected for item in evidence),
                           sum(item.status == MatchStatus.NAMED for item in evidence), disabled, tuple(evidence))
