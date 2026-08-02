"""
Payload-quality filters shared by every reservoir extraction script.

Kept deliberately tiny and dependency-free so it's trivial to unit test
and to reason about independently of pcap/CSV parsing concerns.
"""

from __future__ import annotations

import hashlib

# Bytes considered "printable" for the ASCII-ratio gate: standard printable
# range plus tab/newline/carriage-return, since protocol text (HTTP headers,
# FTP/SSH banners, shell I/O) legitimately contains those.
_PRINTABLE = frozenset([9, 10, 13]) | frozenset(range(32, 127))


def printable_ratio(data: bytes) -> float:
    """Fraction of bytes in `data` that are printable ASCII (or tab/CR/LF)."""
    if not data:
        return 0.0
    printable = sum(1 for b in data if b in _PRINTABLE)
    return printable / len(data)


def is_printable_enough(data: bytes, min_ratio: float = 0.30) -> bool:
    return printable_ratio(data) >= min_ratio


def payload_digest(data: bytes) -> str:
    """Stable hash used for dedup, cheaper to keep in a set than raw bytes."""
    return hashlib.blake2b(data, digest_size=16).hexdigest()


class DedupSet:
    """Thin wrapper around a set of digests, so extraction scripts don't
    need to import hashlib directly and the dedup strategy stays in one place."""

    __slots__ = ("_seen",)

    def __init__(self) -> None:
        self._seen: set[str] = set()

    def seen_before(self, data: bytes) -> bool:
        digest = payload_digest(data)
        if digest in self._seen:
            return True
        self._seen.add(digest)
        return False

    def __len__(self) -> int:
        return len(self._seen)
