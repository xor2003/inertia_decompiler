"""Admission contracts for whole-callee semantic equality evidence.

Layer: dosunit callee proof accounting.
Responsibility: prevent an entry-block proof or symbol alias from certifying
unproved later callee effects; identities bind exact body content and SSA scope.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class CalleeIdentity:
    """Exact binary body, entry and modeled SSA projection for a cache target."""

    entry: int
    body_hash: str
    body_size: int
    semantic_ssa_id: str


def _integer(value: object) -> int | None:
    """Parse an integer field at the legacy SSA JSON boundary without guessing."""
    if type(value) is int:
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            return None
    return None


def callee_identity(brief: dict[str, Any]) -> CalleeIdentity | None:
    """Require full binary-content provenance before consulting a callee cache."""
    location = brief.get('entry')
    entry = _integer(location.get('linear')) if isinstance(location, dict) else None
    size = _integer(brief.get('function_machine_code_size'))
    digest, semantic = brief.get('function_machine_code_sha256'), brief.get('semantic_ssa_id')
    if entry is None or size is None or size <= 0:
        return None
    if not isinstance(digest, str) or not digest or not isinstance(semantic, str) or not semantic:
        return None
    return CalleeIdentity(entry, digest, size, semantic)


def complete_leaf_block(function: dict[str, Any]) -> bool:
    """Admit a block proof as a whole leaf only with complete near/far return IR.

    The entry must cover exactly the declared binary body, end in a VEX return,
    and have no alternative fault/branch transfer. Otherwise the proof remains
    block-scoped until a closed whole-region proof is available.
    """
    source, part = function.get('source'), function.get('part')
    if not isinstance(source, dict) or source.get('jumpkind') != 'Ijk_Ret':
        return False
    if not isinstance(part, dict) or _integer(part.get('entry_delta')) != 0:
        return False
    transfer = source.get('transfer')
    if function.get('trap_exits') or (isinstance(transfer, dict) and transfer.get('kind') == 'direct_successors'):
        return False
    size = _integer(source.get('function_machine_code_size'))
    return (size is not None and size > 0 and _integer(source.get('machine_code_size')) == size
            and bool(source.get('function_machine_code_sha256'))
            and source.get('machine_code_sha256') == source.get('function_machine_code_sha256'))


def leaf_proof_covers_callee_state(
    oracle: dict[str, Any], candidate: dict[str, Any], registers: Iterable[str],
) -> bool:
    """Require a complete leaf and a proof covering every callee state component.

    Exact body equality establishes the instruction relation for arbitrary
    equal inputs. Different bodies require every modeled register projection;
    an AX-only solver result cannot certify a later caller's live carry flag.
    Full memory effects are already mandatory in the underlying comparison.
    """
    if not complete_leaf_block(oracle) or not complete_leaf_block(candidate):
        return False
    if oracle['source']['function_machine_code_sha256'] == candidate['source']['function_machine_code_sha256']:
        return True
    required = set(registers)
    return required.issubset(oracle.get('outputs', {})) and required.issubset(candidate.get('outputs', {}))
