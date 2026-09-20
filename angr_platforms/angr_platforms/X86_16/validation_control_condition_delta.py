"""Match condition substitutions without changing guarded effects.

Layer: Tail Validation.
Responsibility: consume exact proven condition pairs and require identical
control kinds and body payloads. Fingerprints are owned validation records,
not rendered C. Unknown forms or ambiguous substitutions are refused.
"""

from __future__ import annotations

from collections import Counter

_GUARD_PREFIXES: tuple[str, ...] = ("if:", "ifbreak:", "while:", "dowhile:", "for:", "loop:")
_LOOP_BODY_PREFIXES: tuple[str, ...] = ("loop-body-calls:", "loop-body-writes:")


def _replace_control_condition(
    token: str, pairs: tuple[tuple[str, str], ...],
) -> tuple[str, str | None] | None:
    """Return an exact substitution and its plain-guard owner, or refuse."""
    matches: set[tuple[str, str | None]] = set()
    for before, after in pairs:
        for prefix in _GUARD_PREFIXES:
            if token == prefix + before:
                matches.add((prefix + after, before))
        for prefix in _LOOP_BODY_PREFIXES:
            head = prefix + before + ":"
            if token.startswith(head) and len(token) > len(head):
                # Preserve the entire ordered payload, including storage widths.
                matches.add((prefix + after + ":" + token[len(head):], None))
    return next(iter(matches)) if len(matches) == 1 else None


def control_condition_delta_matches_8616(
    removed: tuple[str, ...],
    added: tuple[str, ...],
    pairs: tuple[tuple[str, str], ...],
) -> bool:
    """Require a bijection of guards and unchanged condition-owned effects.

    Each proven condition replacement needs one plain guard. Body records may
    accompany it, but cannot substitute for that guard or change their payload.
    Control kinds, multiplicities, call ordering, and writes remain exact.
    """
    if not pairs or len(removed) != len(added):
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
        Counter(guards) == Counter(before for before, _after in pairs)
        and Counter(replacements) == Counter(added)
    )
