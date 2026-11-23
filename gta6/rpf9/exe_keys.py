"""Recover the RPF9 TOC key from the leaked game executable.

Every RPF9 TOC in this build carries a 48-byte global template at offsets
16..63 (see ``gta6.rpf9.template`` and the xor-structure note): three
*identical* 16-byte blocks, the same in every archive.  Under ECB, a repeated
ciphertext block means a repeated plaintext block, so that region is the
ciphertext of a constant block -- most plausibly a run of zeros.

That makes it a known-plaintext pair, which turns key search into a single
AES block test: a candidate key is right iff ``AES_k(0^16)`` equals the
stored template block.  No scoring heuristics, no false positives.

``KeyOracle`` tests candidates against one archive; ``recover_key`` sweeps a
large executable for the candidate that passes.
"""

from __future__ import annotations

import hashlib
import sys
from collections.abc import Iterator
from dataclasses import dataclass, replace
from pathlib import Path

from gta6.rpf9.template import CLEARTEXT_TEMPLATE_END

TEMPLATE_OFFSET = 16
TEMPLATE_SIZE = CLEARTEXT_TEMPLATE_END - TEMPLATE_OFFSET
KEY_LENGTHS = (16, 24, 32)

ZERO_BLOCK = bytes(16)
ZERO_RUN = bytes(TEMPLATE_SIZE)


def _aes_ecb(data: bytes, key: bytes, *, decrypt: bool) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    cipher = Cipher(algorithms.AES(key), modes.ECB())
    ctx = cipher.decryptor() if decrypt else cipher.encryptor()
    return ctx.update(data) + ctx.finalize()


def aes_ecb_encrypt_block(block: bytes, key: bytes) -> bytes:
    """Encrypt one 16-byte block; key length selects AES-128/192/256."""
    if len(block) != 16:
        msg = f"block must be 16 bytes, got {len(block)}"
        raise ValueError(msg)
    if len(key) not in KEY_LENGTHS:
        msg = f"AES key must be 16/24/32 bytes, got {len(key)}"
        raise ValueError(msg)
    return _aes_ecb(block, key, decrypt=False)


def ecb_decrypt(data: bytes, key: bytes) -> bytes:
    """ECB-decrypt ``data``; a trailing partial block is passed through."""
    full = len(data) - (len(data) % 16)
    if full == 0:
        return data
    return _aes_ecb(data[:full], key, decrypt=True) + data[full:]


def ctr_decrypt(data: bytes, key: bytes, nonce: bytes) -> bytes:
    """CTR-decrypt with a 16-byte initial counter block."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    ctx = Cipher(algorithms.AES(key), modes.CTR(nonce)).decryptor()
    return ctx.update(data) + ctx.finalize()


def read_toc(path: Path, base: int = 0, *, limit: int = 1 << 20) -> bytes:
    """Read the raw (still encrypted) TOC bytes of one archive base."""
    import struct

    with path.open("rb") as fh:
        fh.seek(base)
        magic, toc_size = struct.unpack("<II", fh.read(8))
        if magic != 0x52504639:
            msg = f"{path}@{base}: not an RPF9 header"
            raise ValueError(msg)
        fh.seek(base + 32)
        return fh.read(min(toc_size, limit))


def toc_template(toc: bytes) -> bytes:
    """The 48-byte global template region as stored in the file."""
    return toc[TEMPLATE_OFFSET:CLEARTEXT_TEMPLATE_END]


@dataclass(frozen=True, slots=True)
class KeyHit:
    """A candidate that reproduces the template ciphertext from a known plaintext."""

    key: bytes
    offset: int
    scheme: str

    @property
    def key_hex(self) -> str:
        return self.key.hex()


class KeyOracle:
    """Tests candidate keys against one archive's known-plaintext template pair."""

    def __init__(self, toc: bytes) -> None:
        self.stored = toc_template(toc)
        if len(self.stored) != TEMPLATE_SIZE:
            msg = f"TOC too short for a template pair ({len(self.stored)} bytes)"
            raise ValueError(msg)
        self.block = self.stored[:16]
        self.repeats = self.stored[16:32] == self.block and self.stored[32:48] == self.block

    def test(self, key: bytes) -> KeyHit | None:
        """Hit if ``key`` maps the zero block onto the stored template block (ECB)."""
        if len(key) not in KEY_LENGTHS:
            return None
        if aes_ecb_encrypt_block(ZERO_BLOCK, key) == self.block:
            return KeyHit(key=key, offset=-1, scheme="aes-ecb-zero")
        return None

    def test_ctr(self, key: bytes, nonce: bytes) -> KeyHit | None:
        """CTR variant: keystream block at ``nonce`` must equal the stored block."""
        if len(key) not in KEY_LENGTHS or len(nonce) != 16:
            return None
        if aes_ecb_encrypt_block(nonce, key) == self.block:
            return KeyHit(key=key, offset=-1, scheme="aes-ctr")
        return None


def _plausible_key(key: bytes) -> bool:
    """Reject windows that are clearly not key material (text, zero runs, code)."""
    if len(set(key)) < 12:
        return False
    if any(b == 0 for b in key):
        return False
    printable = sum(1 for b in key if 0x20 <= b <= 0x7E)
    return printable < len(key) - 2


def key_candidates_from_pe(
    path: Path,
    *,
    chunk: int = 1 << 20,
    step: int = 1,
    key_lengths: tuple[int, ...] = (32, 16),
) -> Iterator[tuple[int, bytes]]:
    """Stream (offset, bytes) windows from a large executable without loading it.

    Reads in chunks so a 120 MB exe costs a few MB of RAM.  With ``step=1``
    every byte offset is visited, which a real hunt needs: a key inside a
    struct is not guaranteed to be 4-byte aligned.
    """
    window = max(key_lengths)
    seen: set[bytes] = set()
    carry = b""
    pos = 0
    with path.open("rb") as fh:
        while True:
            raw = fh.read(chunk)
            if not raw:
                break
            buf = carry + raw
            base = pos - len(carry)
            for off in range(0, max(0, len(buf) - window + 1), step):
                for klen in key_lengths:
                    key = buf[off : off + klen]
                    if len(key) != klen or key in seen:
                        continue
                    seen.add(key)
                    yield base + off, key
            carry = buf[-(window - 1) :] if window > 1 else b""
            pos += len(raw)


def recover_key(
    exe: Path,
    toc: bytes,
    *,
    key_lengths: tuple[int, ...] = (32, 16),
    limit: int = 0,
    stop_after: int = 1,
    verbose: bool = False,
) -> list[KeyHit]:
    """Sweep ``exe`` for keys whose AES(zeros) equals the archive's template block."""
    oracle = KeyOracle(toc)
    hits: list[KeyHit] = []
    tried = 0
    for offset, key in key_candidates_from_pe(exe, key_lengths=key_lengths):
        if not _plausible_key(key):
            continue
        tried += 1
        hit = oracle.test(key)
        if hit is not None:
            hits.append(replace(hit, offset=offset))
            if verbose:
                print(f"hit @ {offset:#x} {hit.scheme} {hit.key_hex}", file=sys.stderr)
            if len(hits) >= stop_after:
                break
        if limit and tried >= limit:
            break
    if verbose:
        print(f"# tried {tried} candidates, {len(hits)} hits", file=sys.stderr)
    return hits


def derive_key_candidates(seeds: list[tuple[str, bytes]]) -> Iterator[tuple[str, bytes]]:
    """Hash-derived keys, for the per-archive-key model (key = hash of header)."""
    for label, material in seeds:
        yield f"sha256:{label}", hashlib.sha256(material).digest()
        yield f"md5x2:{label}", hashlib.md5(material).digest() * 2
        yield f"pad32:{label}", (material + bytes(32))[:32]
