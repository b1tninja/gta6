from __future__ import annotations

import struct
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class TocHeadFields:
    """First 16 bytes at TOC+0 — cleartext, varies per archive."""

    dword0: int
    dword1: int
    dword2: int
    dword3: int

    @property
    def entry0_hint(self) -> int:
        """Low byte often matches `entry_count - 1` or root child count."""
        return self.dword0 & 0xFF

    @property
    def shared_magic(self) -> bool:
        """`3e5772da` / `5427a9c0` patterns in dword2 across builds."""
        return self.dword2 not in (0, 0xFFFFFFFF)


def parse_toc_head(toc: bytes) -> TocHeadFields:
    d0, d1, d2, d3 = struct.unpack_from("<4I", toc, 0)
    return TocHeadFields(d0, d1, d2, d3)