"""Immutable static dispatch entries and their direct lookup.

Layer: IR.
Responsibility: provide a tuple-based dispatch contract with no mutable backing
container or derived cache. Owners retain the sole authoritative entry tuple.
This freezes entry membership, not the objects stored as keys or handlers;
owners must authenticate their supported key and callable identities separately.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting work here
"""

from __future__ import annotations

type FrozenDispatch[K, V] = tuple[tuple[K, V], ...]
"""An authoritative ordered tuple of immutable key-handler entry pairs."""


def frozen_dispatch_lookup[K, V](
    registry: FrozenDispatch[K, V] | dict[K, V], key: K,
) -> V | None:
    """Return the exact first matching handler, or None for an absent key.

    Owned immutable registries require built-in tuples at both levels. An
    exact dict supports foreign replacement instrumentation on the ordinary
    route only: lookup compatibility does not grant immutable admission, and
    consumers must revoke fused authority when registry identity changes.
    Malformed representations raise TypeError. Key equality follows the owner's
    key semantics; this helper does not authenticate arbitrary key objects or
    freeze handler internals.
    Every call reads the authoritative entries directly, without a cache.
    """
    if type(registry) is dict:
        return registry.get(key)
    if type(registry) is not tuple:
        raise TypeError("dispatch registry must be an exact tuple or replacement dict")
    for entry in registry:
        if type(entry) is not tuple or len(entry) != 2:
            raise TypeError("dispatch entry must be an exact two-item tuple")
        candidate, handler = entry
        if candidate == key:
            return handler
    return None
