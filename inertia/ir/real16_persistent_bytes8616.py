"""Mutable facade over an immutable ``immutables.Map`` root for path memory.

Layer: IR (invocation/control proof).
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting work here.

Responsibility: give ``PathMemory8616.known`` a mutable surface that can
share an immutable backing root across ``copy()`` snapshots at O(1), while
every mutating call swaps only this facade's root pointer — a write on one
overlay can never reach a sibling that borrowed the same root, so the
public-mutation isolation the previous full ``dict`` clone provided is
preserved exactly. Iteration, membership, length, and equality behave like
the plain ``dict`` they replace; the ``unknown`` byte set deliberately
stays an ordinary ``set`` (only the known map is large in practice).

The facade additionally maintains a constant-time conservative address
envelope (see ``PersistentBytes8616.address_envelope_8616``) so overlap
queries never need an O(|known|) key scan on the canonical representation.
The envelope is a data-structure invariant kept exact at owned write
boundaries — never a cached proof of anything about the bytes themselves.
"""

from __future__ import annotations

from collections.abc import ItemsView, Iterator, KeysView, Mapping, MutableMapping, ValuesView
from typing import cast

from immutables import Map as _ImmutableMap

#: Sentinel for cross-type mapping equality — a missing key must never
#: compare equal to a stored value, even a malformed ``None``.
_MISSING_8616: object = object()


class PersistentBytes8616(MutableMapping[int, int]):
    """Mutable byte map whose storage is an immutable ``Map`` root.

    ``share_8616`` produces an independent facade over the same root in
    O(1); each mutating call replaces only this facade's root, so logical
    copies stay isolated without copying any entries. Convenience mutators
    not listed here (``pop``, ``update``, ``setdefault``, ``popitem``,
    ``get``) come from the ``MutableMapping`` mixins and operate on the
    same typed core operations.

    ``_bounds_root``/``_bounds_low``/``_bounds_high`` carry the maintained
    address envelope: ``_bounds_root`` is the exact immutable root identity
    the endpoints were computed against, and the endpoints cover every
    exact-``int`` key of that root. The triple is trustworthy only when it
    was anchored on an observably empty root at an owned boundary
    (construction, ``clear``, deletion to empty, or an integer write onto
    an empty root) — any root whose contents were never enumerated here
    reports ``None`` instead of trusting unverified endpoints. A write of
    a non-exact-``int`` key disables the envelope; deletion keeps loose
    endpoints. This metadata is a private structural invariant: it is
    bound to the root identity and never re-verified against root
    contents, so it is conservative evidence only — writes to the private
    fields are outside the trust boundary, exactly as ``_root`` swaps are.
    """

    __slots__ = ("_bounds_high", "_bounds_low", "_bounds_root", "_root")

    def __init__(
        self,
        root: _ImmutableMap | Mapping[int, int] | None = None,
    ) -> None:
        """Bind the facade to ``root``; foreign mappings are detached.

        The envelope anchors only when the bound root is observably empty:
        ``__init__`` performs no extra bounds scan, so a nonempty supplied
        root — foreign or native — leaves the envelope unknown rather
        than paying an uncharged scan.
        """
        # An external Mapping is folded into a fresh immutable root, so
        # the caller can never mutate this facade through its own dict.
        self._root: _ImmutableMap[int, int] = (
            _ImmutableMap()
            if root is None
            else root if type(root) is _ImmutableMap else _ImmutableMap(root)
        )
        self._bounds_root: _ImmutableMap[int, int] | None = (
            self._root if len(self._root) == 0 else None
        )
        self._bounds_low: int | None = None
        self._bounds_high: int | None = None

    def __getitem__(self, key: int) -> int:
        """Return the byte value stored at ``key``."""
        return cast(int, self._root[key])

    def __setitem__(self, key: int, value: int) -> None:
        """Store ``value`` at ``key``, replacing only this facade's root.

        Envelope maintenance is folded into the per-key write the mapping
        already performs: an exact-``int`` key extends the tracked
        endpoints, a non-exact-``int`` key (including ``bool``) disables
        the envelope while the store itself keeps ordinary ``dict``
        behavior. When the current root is untracked but observably empty,
        one integer store re-anchors the envelope on that single key. A
        failed store raises before any metadata or root changes.
        """
        new_root = self._root.set(key, value)
        if self._bounds_root is self._root:
            if type(key) is int:
                low = self._bounds_low
                self._bounds_low = key if low is None else min(low, key)
                high = self._bounds_high
                self._bounds_high = key + 1 if high is None else max(high, key + 1)
                self._bounds_root = new_root
            else:
                self._bounds_root = None
                self._bounds_low = None
                self._bounds_high = None
        elif len(self._root) == 0 and type(key) is int:
            # The pre-store root was observably empty, so this key is the
            # only exact-int key the new root can hold.
            self._bounds_low = key
            self._bounds_high = key + 1
            self._bounds_root = new_root
        self._root = new_root

    def __delitem__(self, key: int) -> None:
        """Drop ``key``; ``KeyError`` on absence matches ``dict``.

        Deletion keeps the tracked endpoints loose — a removed endpoint
        address simply widens the reported interval beyond the live keys,
        which stays conservative — and re-anchors the metadata to the new
        root identity. Deleting the last key of an untracked root leaves
        an observably empty root, so the envelope re-anchors empty. A
        failed delete raises before any metadata or root changes.
        """
        new_root = self._root.delete(key)
        if self._bounds_root is self._root:
            self._bounds_root = new_root
        elif len(new_root) == 0:
            self._bounds_root = new_root
            self._bounds_low = None
            self._bounds_high = None
        self._root = new_root

    def __iter__(self) -> Iterator[int]:
        """Iterate stored byte addresses via the root's native iterator."""
        return iter(self._root)

    def __len__(self) -> int:
        """Return the number of stored bytes."""
        return len(self._root)

    def __contains__(self, key: object) -> bool:
        """Return whether ``key`` holds a stored byte."""
        return key in self._root

    def items(self) -> ItemsView[int, int]:
        """Return a live ``(key, value)`` view bound to this facade.

        The view re-reads the facade's current root at iteration, so a
        retained view observes later writes exactly like a ``dict`` view.
        """
        return _LiveItemsView8616(self)

    def keys(self) -> KeysView[int]:
        """Return a live key view bound to this facade.

        ``KeysView`` already iterates the facade itself, so the view is
        live and native without any subclass.
        """
        return KeysView(self)

    def values(self) -> ValuesView[int]:
        """Return a live value view bound to this facade."""
        return _LiveValuesView8616(self)

    def clear(self) -> None:
        """Drop every stored byte in O(1) by replacing the root.

        The fresh root is observably empty, so the envelope re-anchors
        and the next exact-``int`` write resumes tracking.
        """
        self._root = _ImmutableMap()
        self._bounds_root = self._root
        self._bounds_low = None
        self._bounds_high = None

    def address_envelope_8616(self) -> tuple[int, int] | None:
        """Return a conservative half-open ``(low, high)`` covering keys.

        When the metadata is anchored to the CURRENT root identity and at
        least one exact-``int`` key was stored through a tracked path, the
        interval contains every exact-``int`` key of this map; deletion
        may leave it strictly wider than the live minimum/maximum. The
        answer is ``None`` whenever the bound root's contents were never
        enumerated at an owned boundary — nonempty foreign or native-root
        construction, an externally swapped ``_root``, any non-exact-``int``
        key stored — or while no exact-``int`` key has been tracked yet;
        callers distinguish an empty map through ``len`` separately.

        This is O(1) structural metadata, not an authenticated proof: the
        endpoints are bound to root identity and never re-verified against
        the map, so private-field forgery is outside the trust boundary
        and consumers may use the interval only as conservative evidence,
        never as admission.
        """
        if (
            self._bounds_root is self._root
            and self._bounds_low is not None
            and self._bounds_high is not None
        ):
            return (self._bounds_low, self._bounds_high)
        return None

    def share_8616(self) -> PersistentBytes8616:
        """Return an independent facade over the identical root, O(1).

        Envelope metadata is copied, not recomputed: because the clone
        borrows the identical root object, the same anchored-or-not
        verdict transfers exactly, and later writes on either facade
        rebind only that facade's metadata and root.
        """
        clone = PersistentBytes8616(self._root)
        clone._bounds_root = self._bounds_root
        clone._bounds_low = self._bounds_low
        clone._bounds_high = self._bounds_high
        return clone

    def adopt_8616(self, other: Mapping[int, int]) -> None:
        """Point this facade at ``other``'s root (in-place ``assign``).

        Adopting a canonical facade adopts its envelope metadata verbatim —
        the borrowed root is the identical object the source endpoints
        describe, so the anchored verdict transfers with it. Folding a
        foreign mapping performs the existing conversion without an extra
        bounds scan: an empty result
        re-anchors empty, anything else reports unknown bounds.
        """
        if type(other) is PersistentBytes8616:
            self._root = other._root
            self._bounds_root = other._bounds_root
            self._bounds_low = other._bounds_low
            self._bounds_high = other._bounds_high
            return
        self._root = _ImmutableMap(other)
        self._bounds_root = self._root if len(self._root) == 0 else None
        self._bounds_low = None
        self._bounds_high = None

    def __eq__(self, other: object) -> bool:
        """Compare stored bytes; content equality with any Mapping.

        Identical immutable roots are trivially equal; foreign mappings
        compare per key with a missing-value sentinel so a stored
        ``None``-shaped value can never fake presence.
        """
        if type(other) is PersistentBytes8616:
            return self._root is other._root or self._root == other._root
        if type(other) is _ImmutableMap:
            return cast(bool, self._root == other)
        if isinstance(other, Mapping):
            if len(self._root) != len(other):
                return False
            return all(
                self._root.get(key, _MISSING_8616) == value
                for key, value in other.items()
            )
        return NotImplemented

    __hash__ = None  # type: ignore[assignment]

    def __repr__(self) -> str:
        """Render like the equivalent ``dict`` for diagnostics."""
        return repr(dict(self._root.items()))


class _LiveItemsView8616(ItemsView[int, int]):
    """``ItemsView`` that iterates the facade's CURRENT root each time.

    A retained view must observe writes made after the view was taken —
    iterating the facade's live root preserves ``dict``-view semantics
    while keeping native per-scan cost (no per-element ``__getitem__``).
    """

    __slots__ = ("_owner",)

    def __init__(self, owner: PersistentBytes8616) -> None:
        """Bind the view to ``owner``'s facade, not to any root."""
        super().__init__(owner)
        self._owner = owner

    def __iter__(self) -> Iterator[tuple[int, int]]:
        """Iterate pairs of the owner's current root."""
        return iter(self._owner._root.items())


class _LiveValuesView8616(ValuesView[int]):
    """``ValuesView`` that iterates the facade's CURRENT root each time."""

    __slots__ = ("_owner",)

    def __init__(self, owner: PersistentBytes8616) -> None:
        """Bind the view to ``owner``'s facade, not to any root."""
        super().__init__(owner)
        self._owner = owner

    def __iter__(self) -> Iterator[int]:
        """Iterate values of the owner's current root."""
        return iter(self._owner._root.values())


def canonical_known_root_8616(candidate: object) -> bool:
    """Return whether ``candidate`` is a canonical facade on a native root.

    Strict admission predicate for fused-eligibility guards: only the
    exact ``PersistentBytes8616`` facade backed by a genuine immutable
    ``immutables.Map`` qualifies — arbitrary ``Mapping`` lookalikes and
    swapped internals refuse.
    """
    return (
        type(candidate) is PersistentBytes8616
        and type(candidate._root) is _ImmutableMap
    )


def persistent_bytes_producers_8616() -> tuple[object, ...]:
    """Every helper-owned identity fused walks must authenticate.

    Single authoritative inventory so parent binding code consumes one
    tuple instead of duplicating private method lists: the native root
    type, the canonical admission predicate, every facade boundary
    method, and the live-view ``__iter__``/``__init__`` producers.
    """
    return (
        _ImmutableMap,
        canonical_known_root_8616,
        persistent_bytes_producers_8616,
        PersistentBytes8616,
        PersistentBytes8616.__init__,
        PersistentBytes8616.share_8616,
        PersistentBytes8616.adopt_8616,
        PersistentBytes8616.__getitem__,
        PersistentBytes8616.__setitem__,
        PersistentBytes8616.__delitem__,
        PersistentBytes8616.__iter__,
        PersistentBytes8616.__len__,
        PersistentBytes8616.__contains__,
        PersistentBytes8616.items,
        PersistentBytes8616.keys,
        PersistentBytes8616.values,
        PersistentBytes8616.clear,
        # Inherited MutableMapping mixins — real byte operations call
        # these, so their bound identities must invalidate pure transfer
        # when replaced just like the overridden core methods.
        PersistentBytes8616.get,
        PersistentBytes8616.pop,
        PersistentBytes8616.update,
        PersistentBytes8616.setdefault,
        PersistentBytes8616.popitem,
        PersistentBytes8616.address_envelope_8616,
        PersistentBytes8616.__eq__,
        _LiveItemsView8616.__init__,
        _LiveItemsView8616.__iter__,
        _LiveValuesView8616.__init__,
        _LiveValuesView8616.__iter__,
    )
