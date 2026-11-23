from __future__ import annotations

import binascii
import os
import re
from pathlib import Path


def load_aes_key() -> bytes | None:
    """Load a 32-byte AES key from env (hex or binary file)."""
    hex_raw = os.environ.get("GTA6_AES_KEY_HEX", "").strip()
    if hex_raw:
        key = binascii.unhexlify(hex_raw.replace(" ", ""))
        if len(key) != 32:
            msg = f"GTA6_AES_KEY_HEX must decode to 32 bytes, got {len(key)}"
            raise ValueError(msg)
        return key

    key_path = os.environ.get("GTA6_AES_KEY_FILE", "").strip()
    if key_path:
        data = Path(key_path).expanduser().read_bytes()
        if len(data) == 32:
            return data
        msg = f"{key_path}: expected 32 raw key bytes, got {len(data)}"
        raise ValueError(msg)

    return None


def scan_exe_for_key_candidates(exe: Path, *, limit: int = 2000) -> list[bytes]:
    """
    Heuristic: collect 32-byte windows with high entropy from the game executable.

    Useful once `game_scarlett_master.exe` is available; callers can trial-decrypt.
    """
    data = exe.read_bytes()
    candidates: list[bytes] = []
    seen: set[bytes] = set()
    for offset in range(0, len(data) - 32, 4):
        window = data[offset : offset + 32]
        if window in seen:
            continue
        unique = len(set(window))
        if unique < 26:
            continue
        if not re.search(rb"[\x20-\x7e]{4}", window):
            continue
        seen.add(window)
        candidates.append(window)
        if len(candidates) >= limit:
            break
    return candidates