# cython: language_level=3, infer_types=True
"""Match condition substitutions without changing guarded effects.

Layer: Tail Validation.
Responsibility: consume exact proven condition pairs and require identical
control kinds and body payloads. Fingerprints are owned validation records,
not rendered C. Unknown forms or ambiguous substitutions are refused.

Package ownership contract (canonical inertia/validation package):
Layer: Validation.
Owns canonical equivalence checking and validation diagnostics.
Do not mutate IR, rewrite emitted C, recover semantics, or accept source/COD-backed proof.
"""

from __future__ import annotations
import typing
import cython

from collections import Counter
import operator

_GUARD_PREFIXES: tuple[str, ...] = ("if:", "ifbreak:", "while:", "dowhile:", "for:", "loop:")
_LOOP_BODY_PREFIXES: tuple[str, ...] = ("loop-body-calls:", "loop-body-writes:")


@cython.ccall
def _replace_control_condition(
    token: object, pairs: object,
) -> object:
    """Return an exact substitution and its plain-guard owner, or refuse."""
    after: object
    before: object
    prefix: object
    matches: set[tuple[str, str | None]] = set()
    for before, after in pairs:
        for prefix in _GUARD_PREFIXES:
            if operator.eq(token, prefix + before):
                matches.add((prefix + after, before))
        for prefix in _LOOP_BODY_PREFIXES:
            head = prefix + before + ":"
            if token.startswith(head) and len(token) > len(head):
                # Preserve the entire ordered payload, including storage widths.
                matches.add((prefix + after + ":" + token[len(head):], None))
    return next(iter(matches)) if len(matches) == 1 else None


def control_condition_delta_matches_8616(
    removed: object,
    added: object,
    pairs: object,
) -> cython.bint:
    """Require a bijection of guards and unchanged condition-owned effects.

    Each proven condition replacement needs one plain guard. Body records may
    accompany it, but cannot substitute for that guard or change their payload.
    Control kinds, multiplicities, call ordering, and writes remain exact.
    """
    guard: object
    replacement: object
    token: object
    if not pairs or operator.ne(len(removed), len(added)):
        return False
    replacements: list[str] = []
    guards: list[str] = []
    for token in removed:
        replacement = _replace_control_condition(token, pairs)
        if replacement is None:
            return False
        transformed, guard = replacement
        replacements.append(transformed)
        if guard is not None:
            guards.append(guard)
    return (
        operator.eq(Counter(guards), Counter(before for before, _after in iter(pairs)))
        and operator.eq(Counter(replacements), Counter(added))
    )
