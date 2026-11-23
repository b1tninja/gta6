"""RPF9 TOC decryption primitives.

Two cipher models live here:

* ``aes256_ecb_decrypt`` / ``decrypt_toc_and_names`` - the original RPF7-style
  hypothesis (plain AES-256-ECB over the whole TOC+names blob). Kept because its
  failure is the evidence against ECB (see ``toc_key``).
* ``WhitenedAesCbc`` - the cipher identified in the retail executable: a
  table-driven AES-256 with input and output whitening folded into the tables,
  run in CBC mode.

The whitened cipher takes the precomputed key-context blob (``key_ctx``) the game
derives for the archive key handles, laid out as::

    +0x0000  initial whitening keys      16 B
    +0x0010  round keys                  AES-256: 15 x 16 B
    +0x00f0  16 final whitening tables   16 x 256 B = 0x1000
    +0x10f0  IV / chaining slot          16 B   (total 0x10f4)

The blob address is build-specific and is recovered at runtime (see
``gta6.rpf9.sbox_key``); the layout offsets above are the stable part. The exact
whitening byte orderings are pinned by a dynamic trace of the AES block transform;
until then they are read from these offsets and exposed as fields.
"""

from __future__ import annotations

from dataclasses import dataclass

KEY_CTX_SIZE = 0x1100  # IV slot at +0x10f0 needs 16 B; blob rounded up from 0x10f4
INITIAL_WHITENING_OFFSET = 0x0000
ROUND_KEYS_OFFSET = 0x0010
FINAL_TABLES_OFFSET = 0x00F0
IV_SLOT_OFFSET = 0x10F0
AES256_ROUNDS = 14
BLOCK = 16

_SBOX = bytes(
    [
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
        0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
        0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
        0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
        0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
        0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
        0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
        0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
        0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,
        0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
        0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
        0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
        0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
        0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
        0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,
        0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
        0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
    ]
)

_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D]

_INV_SBOX = bytes(_SBOX.index(i) for i in range(256))


def _xtime(a: int) -> int:
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF


def _mul(a: int, b: int) -> int:
    """Multiply two bytes in GF(2^8)."""
    res = 0
    for _ in range(8):
        if b & 1:
            res ^= a
        b >>= 1
        a = _xtime(a)
    return res


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b, strict=True))


def expand_key_256(key: bytes) -> list[bytes]:
    """AES-256 key expansion -> 15 round-key blocks of 16 bytes each."""
    if len(key) != 32:
        msg = f"AES-256 key must be 32 bytes, got {len(key)}"
        raise ValueError(msg)
    nk, nr = 8, AES256_ROUNDS
    words: list[list[int]] = [list(key[4 * i : 4 * i + 4]) for i in range(nk)]
    for i in range(nk, 4 * (nr + 1)):
        temp = list(words[i - 1])
        if i % nk == 0:
            temp = temp[1:] + temp[:1]
            temp = [_SBOX[b] for b in temp]
            temp[0] ^= _RCON[i // nk - 1]
        elif i % nk == 4:
            temp = [_SBOX[b] for b in temp]
        words.append([words[i - nk][j] ^ temp[j] for j in range(4)])
    blocks: list[bytes] = []
    for r in range(nr + 1):
        blk = bytearray()
        for w in range(4):
            blk.extend(words[4 * r + w])
        blocks.append(bytes(blk))
    return blocks


def _add_round_key(s: bytearray, rk: bytes) -> None:
    for i in range(BLOCK):
        s[i] ^= rk[i]


def _sub_bytes(s: bytearray) -> None:
    for i in range(BLOCK):
        s[i] = _SBOX[s[i]]


def _shift_rows(s: bytearray) -> None:
    out = bytearray(s)
    for r in range(1, 4):
        for c in range(4):
            out[4 * c + r] = s[4 * ((c + r) % 4) + r]
    s[:] = out


def _mix_columns(s: bytearray) -> None:
    for c in range(4):
        a0, a1, a2, a3 = s[4 * c], s[4 * c + 1], s[4 * c + 2], s[4 * c + 3]
        s[4 * c] = _mul(a0, 2) ^ _mul(a1, 3) ^ a2 ^ a3
        s[4 * c + 1] = a0 ^ _mul(a1, 2) ^ _mul(a2, 3) ^ a3
        s[4 * c + 2] = a0 ^ a1 ^ _mul(a2, 2) ^ _mul(a3, 3)
        s[4 * c + 3] = _mul(a0, 3) ^ a1 ^ a2 ^ _mul(a3, 2)


def aes256_encrypt_block(block: bytes, round_keys: list[bytes]) -> bytes:
    """Encrypt one 16-byte block with a precomputed AES-256 round-key schedule."""
    if len(block) != BLOCK:
        msg = f"block must be {BLOCK} bytes, got {len(block)}"
        raise ValueError(msg)
    s = bytearray(block)
    _add_round_key(s, round_keys[0])
    for rnd in range(1, AES256_ROUNDS):
        _sub_bytes(s)
        _shift_rows(s)
        _mix_columns(s)
        _add_round_key(s, round_keys[rnd])
    _sub_bytes(s)
    _shift_rows(s)
    _add_round_key(s, round_keys[AES256_ROUNDS])
    return bytes(s)


def _inv_sub_bytes(s: bytearray) -> None:
    for i in range(BLOCK):
        s[i] = _INV_SBOX[s[i]]


def _inv_shift_rows(s: bytearray) -> None:
    out = bytearray(s)
    for r in range(1, 4):
        for c in range(4):
            out[4 * ((c + r) % 4) + r] = s[4 * c + r]
    s[:] = out


def _inv_mix_columns(s: bytearray) -> None:
    for c in range(4):
        a0, a1, a2, a3 = s[4 * c], s[4 * c + 1], s[4 * c + 2], s[4 * c + 3]
        s[4 * c] = _mul(a0, 14) ^ _mul(a1, 11) ^ _mul(a2, 13) ^ _mul(a3, 9)
        s[4 * c + 1] = _mul(a0, 9) ^ _mul(a1, 14) ^ _mul(a2, 11) ^ _mul(a3, 13)
        s[4 * c + 2] = _mul(a0, 13) ^ _mul(a1, 9) ^ _mul(a2, 14) ^ _mul(a3, 11)
        s[4 * c + 3] = _mul(a0, 11) ^ _mul(a1, 13) ^ _mul(a2, 9) ^ _mul(a3, 14)


def aes256_decrypt_block(block: bytes, round_keys: list[bytes]) -> bytes:
    """Inverse AES-256 block transform with a precomputed round-key schedule."""
    if len(block) != BLOCK:
        msg = f"block must be {BLOCK} bytes, got {len(block)}"
        raise ValueError(msg)
    s = bytearray(block)
    _add_round_key(s, round_keys[AES256_ROUNDS])
    for rnd in range(AES256_ROUNDS - 1, 0, -1):
        _inv_shift_rows(s)
        _inv_sub_bytes(s)
        _add_round_key(s, round_keys[rnd])
        _inv_mix_columns(s)
    _inv_shift_rows(s)
    _inv_sub_bytes(s)
    _add_round_key(s, round_keys[0])
    return bytes(s)


@dataclass(frozen=True, slots=True)
class WhitenedAesCbc:
    """Whitened AES-256-CBC driven by a precomputed ``key_ctx`` blob.

    Whitening is applied around a standard AES-256 core: input whitening XOR,
    inverse AES, output whitening XOR, then CBC chaining with ``iv``. The three
    whitening/IV fields are exposed so a dynamic trace of the AES block transform
    can override the defaults read from ``key_ctx``.
    """

    round_keys: tuple[bytes, ...]
    input_whitening: bytes
    output_whitening: bytes
    iv: bytes

    @classmethod
    def from_key_ctx(cls, key_ctx: bytes, *, iv: bytes | None = None) -> WhitenedAesCbc:
        if len(key_ctx) < KEY_CTX_SIZE:
            msg = f"key_ctx must be >= {KEY_CTX_SIZE} bytes, got {len(key_ctx)}"
            raise ValueError(msg)
        # AES-256 uses 15 round keys. key_ctx[0:16] is the round-0 (initial
        # whitening) key; rounds 1..14 are the 14 contiguous blocks at +0x10..+0xf0
        # (note sec 6.4: round-key region +0x10..+0xf0 = 56 words).
        rk = (key_ctx[INITIAL_WHITENING_OFFSET : INITIAL_WHITENING_OFFSET + BLOCK],) + tuple(
            key_ctx[ROUND_KEYS_OFFSET + BLOCK * (r - 1) : ROUND_KEYS_OFFSET + BLOCK * r]
            for r in range(1, AES256_ROUNDS + 1)
        )
        input_w = key_ctx[INITIAL_WHITENING_OFFSET : INITIAL_WHITENING_OFFSET + BLOCK]
        output_w = key_ctx[FINAL_TABLES_OFFSET : FINAL_TABLES_OFFSET + BLOCK]
        if iv is None:
            iv = key_ctx[IV_SLOT_OFFSET : IV_SLOT_OFFSET + BLOCK]
        if len(iv) != BLOCK:
            msg = f"IV must be {BLOCK} bytes, got {len(iv)}"
            raise ValueError(msg)
        return cls(round_keys=rk, input_whitening=input_w, output_whitening=output_w, iv=iv)

    def decrypt_block(self, block: bytes) -> bytes:
        """Raw whitened block transform (no CBC chaining): inverse-AES + output XOR."""
        return aes256_decrypt_block(_xor(block, self.output_whitening), list(self.round_keys))

    def decrypt(self, data: bytes, *, iv: bytes | None = None) -> bytes:
        """CBC-decrypt ``data``. A trailing partial block is passed through."""
        prev = iv if iv is not None else self.iv
        if len(prev) != BLOCK:
            msg = f"IV must be {BLOCK} bytes, got {len(prev)}"
            raise ValueError(msg)
        full = len(data) - (len(data) % BLOCK)
        out = bytearray()
        for off in range(0, full, BLOCK):
            block = data[off : off + BLOCK]
            dec = self.decrypt_block(block)
            plain = _xor(_xor(dec, prev), self.input_whitening)
            out += plain
            prev = block
        out += data[full:]
        return bytes(out)


def aes256_ecb_decrypt(data: bytes, key: bytes) -> bytes:
    """Decrypt in 16-byte ECB blocks; tail shorter than 16 bytes passes through."""
    if len(key) != 32:
        msg = f"AES-256 key must be 32 bytes, got {len(key)}"
        raise ValueError(msg)
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError as exc:
        msg = "Install cryptography: pip install gta6[crypto]"
        raise ImportError(msg) from exc

    cipher = Cipher(algorithms.AES(key), modes.ECB())
    decryptor = cipher.decryptor()
    full = len(data) - (len(data) % 16)
    if full == 0:
        return data
    head = decryptor.update(data[:full]) + decryptor.finalize()
    return head + data[full:]


def decrypt_toc_and_names(blob: bytes, key: bytes) -> bytes:
    """Retail RPF7 decrypts TOC+names as one run; try the same for RPF9."""
    return aes256_ecb_decrypt(blob, key)
