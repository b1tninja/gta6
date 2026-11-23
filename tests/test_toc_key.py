from __future__ import annotations

from pathlib import Path

import pytest

from gta6.rpf9 import toc_key

# No zero bytes and 24 distinct bytes, so the plausibility filter accepts it.
FAKE_KEY = bytes((i * 7 + 0x1b) % 256 for i in range(1, 33))


def _ctr_template(key: bytes, nonce: bytes) -> bytes:
    """The 48-byte keystream CTR would emit starting at ``nonce``."""
    start = int.from_bytes(nonce, "big")
    return b"".join(
        toc_key.ecb_encrypt_block((start + i).to_bytes(16, "big"), key) for i in range(3)
    )


def test_ecb_encrypt_block_roundtrips_through_ecb_decrypt() -> None:
    block = bytes(range(16))
    ct = toc_key.ecb_encrypt_block(block, FAKE_KEY)
    assert toc_key.ecb_decrypt(ct, FAKE_KEY) == block


def test_ecb_decrypt_passes_through_short_tail() -> None:
    assert toc_key.ecb_decrypt(b"\x01\x02\x03", FAKE_KEY) == b"\x01\x02\x03"


def test_key_length_is_validated() -> None:
    with pytest.raises(ValueError, match="16/24/32"):
        toc_key.ecb_encrypt_block(bytes(16), bytes(20))
    with pytest.raises(ValueError, match="16 bytes"):
        toc_key.ecb_encrypt_block(bytes(8), FAKE_KEY)


def test_template_oracle_rejects_wrong_size() -> None:
    with pytest.raises(ValueError, match="48 bytes"):
        toc_key.TemplateOracle(bytes(32))


def test_real_template_is_three_distinct_blocks() -> None:
    """The retail template is three *distinct* blocks, so ECB-of-zeros is ruled out."""
    oracle = toc_key.TemplateOracle()
    assert oracle.distinct
    assert oracle.test_ecb(FAKE_KEY) is None
    assert oracle.test_ecb(bytes.fromhex("ff" * 32)) is None


def test_ctr_hit_is_found_for_a_synthetic_template() -> None:
    nonce = bytes.fromhex("11111111222222223333333344444444")
    oracle = toc_key.TemplateOracle(_ctr_template(FAKE_KEY, nonce))
    hit = oracle.test_ctr(FAKE_KEY, nonce)
    assert hit is not None
    assert hit.scheme == "aes-ctr"
    assert hit.key_hex == FAKE_KEY.hex()
    assert oracle.test_ctr(bytes.fromhex("01" * 32), nonce) is None


def test_plausible_key_filter_rejects_text_and_zeros() -> None:
    assert not toc_key._plausible_key(b"AAAA" * 8)
    assert not toc_key._plausible_key(bytes(32))
    assert toc_key._plausible_key(FAKE_KEY)


def test_key_candidates_from_pe_respects_byte_range(tmp_path: Path) -> None:
    exe = tmp_path / "fake.exe"
    exe.write_bytes(bytes(64) + FAKE_KEY + bytes(64))
    whole = [off for off, _ in toc_key.key_candidates_from_pe(exe, key_lengths=(32,))]
    assert 64 in whole
    window = [
        off
        for off, _ in toc_key.key_candidates_from_pe(exe, start=64, end=96, key_lengths=(32,))
    ]
    assert window and all(off >= 64 for off in window)


def test_sweep_exe_finds_a_planted_key(tmp_path: Path) -> None:
    """Plant a key whose CTR keystream equals a synthetic template; sweep must find it."""
    nonce = bytes.fromhex("0a0b0c0d0e0f00010203040506070809")
    template = _ctr_template(FAKE_KEY, nonce)

    exe = tmp_path / "game.exe"
    exe.write_bytes(bytes(100) + FAKE_KEY + bytes(100))

    hits = toc_key.sweep_exe(
        exe, template=template, nonces=[("test", nonce)], key_lengths=(32,), stop_after=0
    )
    assert any(h.key == FAKE_KEY and h.offset == 100 for h in hits)
