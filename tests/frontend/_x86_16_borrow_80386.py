"""Layer: Frontend tests.

Responsibility: load and deduplicate borrowed 80386EX real-mode instruction cases.
"""

from __future__ import annotations

import gzip
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from tests.frontend._x86_16_borrow_80286 import (
    _iter_test_names_and_bytes_from_moo,
    _mnemonic_key,
    _normalized_instruction_bytes,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
BORROW_80386_ROOT = REPO_ROOT / "borrow" / "80386" / "v1_ex_real_mode"


@dataclass(frozen=True, slots=True)
class Borrow80386Case:
    """One deduplicated hardware-captured 80386 real-mode instruction case."""

    opcode_key: str
    mnemonic_key: str
    name: str
    instruction_bytes: bytes
    source_path: Path


@dataclass(frozen=True, slots=True)
class Borrow80386Corpus:
    """Counts and cases retained from the complete 80386 real-mode corpus."""

    cases: tuple[Borrow80386Case, ...]
    total_cases: int
    filtered_cases: int
    deduped_cases: int
    skipped_bad_cases: int
    skipped_lock_cases: int


@lru_cache(maxsize=1)
def load_borrow_80386_lifter_corpus() -> Borrow80386Corpus:
    """Load all normal non-LOCK cases and deduplicate identical instruction bytes."""
    cases: list[Borrow80386Case] = []
    seen_instruction_bytes: set[bytes] = set()
    total_cases = 0
    filtered_cases = 0
    skipped_bad_cases = 0
    skipped_lock_cases = 0

    for source_path in sorted(BORROW_80386_ROOT.glob("*.MOO.gz")):
        opcode_key = source_path.name.removesuffix(".MOO.gz")
        for name, raw_instruction_bytes in _iter_test_names_and_bytes_from_moo(gzip.decompress(source_path.read_bytes())):
            total_cases += 1
            if name.startswith("(bad)"):
                skipped_bad_cases += 1
                continue
            mnemonic_key = _mnemonic_key(name)
            if " lock " in f" {name.lower()} ":
                skipped_lock_cases += 1
                continue
            instruction_bytes = _normalized_instruction_bytes(raw_instruction_bytes)
            if not instruction_bytes:
                continue
            filtered_cases += 1
            if instruction_bytes in seen_instruction_bytes:
                continue
            seen_instruction_bytes.add(instruction_bytes)
            cases.append(
                Borrow80386Case(
                    opcode_key=opcode_key,
                    mnemonic_key=mnemonic_key,
                    name=name,
                    instruction_bytes=instruction_bytes,
                    source_path=source_path,
                )
            )

    return Borrow80386Corpus(
        cases=tuple(cases),
        total_cases=total_cases,
        filtered_cases=filtered_cases,
        deduped_cases=len(cases),
        skipped_bad_cases=skipped_bad_cases,
        skipped_lock_cases=skipped_lock_cases,
    )


def load_borrow_80386_lifter_cases(limit: int | None = None) -> tuple[Borrow80386Case, ...]:
    """Return all cases or a deterministic coverage-first corpus sample.

    A finite ``limit`` is a minimum budget: the sample always retains at least
    one case for every hardware source file and mnemonic family, then fills any
    remaining budget with evenly spaced corpus cases.
    """
    cases = load_borrow_80386_lifter_corpus().cases
    if limit is None or limit >= len(cases):
        return cases

    required_indices: set[int] = set()
    seen_sources: set[Path] = set()
    seen_mnemonics: set[str] = set()
    for index, case in enumerate(cases):
        if case.source_path not in seen_sources or case.mnemonic_key not in seen_mnemonics:
            required_indices.add(index)
            seen_sources.add(case.source_path)
            seen_mnemonics.add(case.mnemonic_key)

    target = min(len(cases), max(limit, len(required_indices)))
    if len(required_indices) < target:
        remaining_indices = tuple(index for index in range(len(cases)) if index not in required_indices)
        fill_count = target - len(required_indices)
        step = len(remaining_indices) / fill_count
        required_indices.update(remaining_indices[int(index * step)] for index in range(fill_count))
    return tuple(cases[index] for index in sorted(required_indices))
