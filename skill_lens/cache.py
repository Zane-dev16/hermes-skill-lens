"""Fast-path cache — <200 ms answers keyed by canonical bundle hash.

Key recipe (PLAN Phase 1): SHA-256 over the CANONICAL ENVELOPE of the
SkillIR (:meth:`skill_lens.ir.SkillIR.canonical_dict` serialized with
:func:`skill_lens.canonical.canonical_dumps`). Any byte of deterministic
IR change ⇒ new key ⇒ old entries simply stop being hit (invalidation by
hash identity); nothing time- or path-dependent enters the key beyond what
the IR itself already records as display labels.

Stores the rendered fast-path one-liner fields + verdict + grade/score,
plus the rendered chat-compact text and canonical ``report/1`` JSON text so
``/lens scan`` (with or without ``--json``) and ``/lens report`` can answer
inline without rescanning. Thread safety: one :class:`threading.Lock`
around an OrderedDict with FIFO eviction at a bounded entry count (the
cache is a hot-path convenience, not a database).

Wall-clock note: ``cached_at`` uses ``time.monotonic`` purely to render the
§11.4 format-A "cached Ns ago" status fragment. It NEVER enters cache keys,
envelopes, or any deterministic artifact — status lines are exempt from the
report laws (§12.6).
"""

from __future__ import annotations

import hashlib
import threading
import time
from collections import OrderedDict
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from .canonical import canonical_dumps

#: Default FIFO bound. Bundles are small; 128 entries covers realistic
#: skill-tree churn while keeping memory trivial.
DEFAULT_MAX_ENTRIES = 128


@dataclass(frozen=True)
class CacheEntry:
    """One cached fast-path answer."""

    bundle_hash: str  # sha256:<hex> over the canonical IR envelope
    name: str
    grade: str
    value: int
    verdict: str
    counts: str  # §11.4 count fragment, pre-rendered
    cached_at: float  # time.monotonic() at put-time; DISPLAY ONLY
    one_liner_fields: tuple[str, ...] = ()
    compact_text: str | None = None
    envelope_json: str | None = None
    extra: Mapping[str, Any] = field(default_factory=dict)

    def age_seconds(self, *, now: float | None = None) -> int:
        """Whole seconds since insertion (never negative; display only)."""
        reference = time.monotonic() if now is None else now
        return max(0, int(reference - self.cached_at))


def key_for_ir(ir: Any) -> str:
    """Canonical cache key: sha256 over the IR's canonical envelope bytes."""
    payload = canonical_dumps(ir.canonical_dict()).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def hash8(bundle_hash: str) -> str:
    """8-hex display shard used by one-liners and overflow filenames."""
    if bundle_hash.startswith("sha256:") and len(bundle_hash) > len("sha256:"):
        return bundle_hash[len("sha256:") :][:8]
    return bundle_hash[:8] if bundle_hash else "unhashed"


class FastPathCache:
    """Thread-safe, bounded, hash-keyed memo for fast-path answers."""

    def __init__(self, max_entries: int = DEFAULT_MAX_ENTRIES) -> None:
        if max_entries < 1:
            raise ValueError("max_entries must be >= 1")
        self._max_entries = max_entries
        self._lock = threading.Lock()
        self._entries: OrderedDict[str, CacheEntry] = OrderedDict()
        self._hits = 0
        self._misses = 0

    # -- core operations -------------------------------------------------------

    def get(self, bundle_hash: str) -> CacheEntry | None:
        """Return the live entry for *bundle_hash*, else None (O(1))."""
        with self._lock:
            entry = self._entries.get(bundle_hash)
            if entry is not None:
                self._hits += 1
            else:
                self._misses += 1
            return entry

    def peek(self, bundle_hash: str) -> CacheEntry | None:
        """Like :meth:`get` but does not touch hit/miss counters."""
        with self._lock:
            return self._entries.get(bundle_hash)

    def put(self, entry: CacheEntry) -> None:
        """Insert/replace an entry; evicts oldest when over capacity."""
        with self._lock:
            self._entries.pop(entry.bundle_hash, None)
            self._entries[entry.bundle_hash] = entry
            while len(self._entries) > self._max_entries:
                self._entries.popitem(last=False)

    def invalidate(self, bundle_hash: str) -> bool:
        """Drop one key explicitly; True when something was dropped."""
        with self._lock:
            return self._entries.pop(bundle_hash, None) is not None

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()

    # -- lookup helpers ----------------------------------------------------------

    def latest_by_name(self, name: str) -> CacheEntry | None:
        """Newest entry whose bundle name matches (for /lens report pulls)."""
        with self._lock:
            matches = [e for e in self._entries.values() if e.name == name]
        return matches[-1] if matches else None

    # -- introspection -------------------------------------------------------------

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    def stats(self) -> dict[str, int]:
        with self._lock:
            return {
                "entries": len(self._entries),
                "hits": self._hits,
                "misses": self._misses,
                "max_entries": self._max_entries,
            }


__all__ = [
    "DEFAULT_MAX_ENTRIES",
    "CacheEntry",
    "FastPathCache",
    "hash8",
    "key_for_ir",
]
