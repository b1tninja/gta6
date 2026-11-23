from __future__ import annotations

import struct
from pathlib import Path

from gta6.rpf9 import sbox_key

# A synthetic image: one fake ".text" section and one fake ".rdata" section, laid out
# contiguously so VA<->file mapping is a constant offset. This lets us exercise the
# descriptor-getter scan and registry-signature logic without a real PE on disk.
_IMAGE_BASE = 0x140000000
_TEXT_OFF = 0x1000
_RDATA_OFF = 0x4000


class FakeView:
    """Minimal stand-in for sbox_key.PeView over an in-memory byte image."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.image_base = _IMAGE_BASE

    def _sections(self) -> list[dict]:
        return [
            {
                "name": ".text",
                "va": _IMAGE_BASE + _TEXT_OFF,
                "vsize": _RDATA_OFF - _TEXT_OFF,
                "raw": _TEXT_OFF,
                "raw_size": _RDATA_OFF - _TEXT_OFF,
            },
            {
                "name": ".rdata",
                "va": _IMAGE_BASE + _RDATA_OFF,
                "vsize": len(self.data) - _RDATA_OFF,
                "raw": _RDATA_OFF,
                "raw_size": len(self.data) - _RDATA_OFF,
            },
        ]

    def va_to_file(self, va: int) -> int | None:
        for s in self._sections():
            if s["va"] <= va < s["va"] + s["vsize"]:
                return s["raw"] + (va - s["va"])
        return None

    def file_to_va(self, off: int) -> int | None:
        for s in self._sections():
            if s["raw"] <= off < s["raw"] + s["raw_size"]:
                return s["va"] + (off - s["raw"])
        return None

    def section_by_name(self, name: str) -> dict | None:
        for s in self._sections():
            if s["name"] == name:
                return s
        return None

    def read_at_va(self, va: int, size: int) -> bytes | None:
        off = self.va_to_file(va)
        if off is None:
            return None
        return self.data[off : off + size]


def _descriptor_getter_bytes(table_va: int, code_va: int, count: int) -> bytes:
    """LEA rax,[rip+disp] ; MOV [rcx],rax ; MOV dword [rcx+8],count ; RET"""
    disp = table_va - (code_va + 7)
    return (
        b"\x48\x8d\x05"
        + struct.pack("<i", disp)
        + b"\x48\x89\x01"
        + b"\xc7\x41\x08"
        + struct.pack("<I", count)
        + b"\xc3"
    )


def _registry_entry(handle: int, flags: int, val0: int, length: int) -> bytes:
    key = (handle << 32) | (flags << 24)
    return struct.pack("<QQQ", key, val0, length)


def _build_image() -> tuple[FakeView, int, int]:
    """Build an image with a crypto registry (2 entries) and a decoy table.

    Returns (view, registry_table_va, key_ctx_blob_va).
    """
    data = bytearray(0x8000)

    # Key-context blob lives in .rdata.
    blob_va = _IMAGE_BASE + 0x5000
    blob_off = _RDATA_OFF + (blob_va - (_IMAGE_BASE + _RDATA_OFF))
    data[blob_off : blob_off + sbox_key.KEY_CTX_LEN] = bytes(
        (i * 31 + 7) % 256 for i in range(sbox_key.KEY_CTX_LEN)
    )

    # A second, distinct high-entropy key-context blob (a runtime-keyed provider).
    blob2_va = blob_va + 0x1100
    blob2_off = _RDATA_OFF + (blob2_va - (_IMAGE_BASE + _RDATA_OFF))
    data[blob2_off : blob2_off + sbox_key.KEY_CTX_LEN] = bytes(
        (i * 131 + 99) % 256 for i in range(sbox_key.KEY_CTX_LEN)
    )

    # Registry table: entry 0 is the AES-256 key ctx (handle 1, flags 2); entry 1 is a
    # runtime-keyed blob (handle 0x10000004, flags 2).
    table_va = _IMAGE_BASE + 0x6000
    table_off = _RDATA_OFF + (table_va - (_IMAGE_BASE + _RDATA_OFF))
    data[table_off : table_off + 24] = _registry_entry(1, 2, blob_va, sbox_key.KEY_CTX_LEN)
    data[table_off + 24 : table_off + 48] = _registry_entry(
        0x10000004, 2, blob2_va, sbox_key.KEY_CTX_LEN
    )

    # A descriptor getter in .text pointing at the registry table.
    code_va = _IMAGE_BASE + _TEXT_OFF + 0x40
    code_off = _TEXT_OFF + (code_va - (_IMAGE_BASE + _TEXT_OFF))
    data[code_off : code_off + 18] = _descriptor_getter_bytes(table_va, code_va, 2)

    # A decoy getter whose table is NOT a crypto registry (flags invalid, no key ctx).
    decoy_va = _IMAGE_BASE + 0x7000
    decoy_off = _RDATA_OFF + (decoy_va - (_IMAGE_BASE + _RDATA_OFF))
    data[decoy_off : decoy_off + 24] = struct.pack("<QQQ", 0xDEADBEEF, 0, 0)
    code_va2 = _IMAGE_BASE + _TEXT_OFF + 0x80
    code_off2 = _TEXT_OFF + (code_va2 - (_IMAGE_BASE + _TEXT_OFF))
    data[code_off2 : code_off2 + 18] = _descriptor_getter_bytes(decoy_va, code_va2, 1)

    return FakeView(bytes(data)), table_va, blob_va


def test_descriptor_pattern_is_keystone_assembled() -> None:
    """The descriptor pattern is assembled from mnemonics via keystone, not copied bytes.

    The assembled regex must match the canonical getter encoding, and the LEA length
    must be the real instruction length (opcode + 4-byte RIP displacement).
    """
    import re

    assert sbox_key._DESCRIPTOR_RE is not None, "keystone (disasm extra) must be installed"
    code_va = 0x1400_4040
    table_va = 0x1400_6000
    enc = _descriptor_getter_bytes(table_va, code_va, 2)
    m = re.search(sbox_key._DESCRIPTOR_RE.pattern, enc)
    assert m is not None
    disp = struct.unpack("<i", m.group(1))[0]
    assert code_va + sbox_key._LEA_LEN + disp == table_va
    assert sbox_key._LEA_LEN == 7


def test_descriptor_pattern_is_derived_not_literal() -> None:
    """The variable-field offsets are derived by diffing two keystone assemblies.

    Re-running the assembler must reproduce the exact same pattern (deterministic), and
    the fixed opcode bytes must come from keystone, not a hard-coded literal: assembling
    the individual mnemonics must yield the same fixed prefix/suffix the pattern uses.
    """
    assert sbox_key._DESCRIPTOR_RE is not None
    # Deterministic across calls.
    again, lea_again = sbox_key._assemble_descriptor_pattern()
    assert again == sbox_key._DESCRIPTOR_RE.pattern
    assert lea_again == sbox_key._LEA_LEN
    # The fixed bytes are exactly what keystone assembles for the fixed instructions.
    assert sbox_key._keystone_asm("mov qword ptr [rcx], rax") == b"\x48\x89\x01"
    assert sbox_key._keystone_asm("ret") == b"\xc3"
    # The LEA opcode prefix (before the disp32 capture) is keystone-derived.
    assert again.startswith(sbox_key._keystone_asm("lea rax, [rip + 0x0]")[:3])


def test_gen_sbox_matches_known_vectors() -> None:
    fwd = sbox_key.gen_sbox()
    assert fwd[0] == 0x63 and fwd[1] == 0x7C and fwd[2] == 0x77 and fwd[255] == 0x16
    inv = sbox_key.gen_inv_sbox(fwd)
    # inverse composed with forward is identity
    assert bytes(inv[v] for v in range(256)) == bytes(range(256)) or all(
        fwd[inv[i]] == i for i in range(256)
    )


def test_find_descriptor_getters_resolves_table_va() -> None:
    view, table_va, _blob = _build_image()
    getters = sbox_key.find_descriptor_getters(view)
    tables = {g.table_va for g in getters}
    assert table_va in tables


def test_crypto_registry_signature_distinguishes_tables() -> None:
    view, table_va, _blob = _build_image()
    good = sbox_key.parse_registry_table(view, table_va, 2)
    assert sbox_key.is_crypto_registry(good, view)
    # The decoy table (flags invalid, no key ctx) must be rejected.
    decoy = sbox_key.parse_registry_table(view, _IMAGE_BASE + 0x7000, 1)
    assert not sbox_key.is_crypto_registry(decoy, view)


def test_recover_key_ctx_blob_finds_the_crypto_blob() -> None:
    view, table_va, blob_va = _build_image()
    rec = sbox_key.recover_key_ctx_blob(view, handle=1, flags=2)
    assert rec is not None
    assert rec.blob_va == blob_va
    assert rec.length == sbox_key.KEY_CTX_LEN
    assert rec.table_va == table_va
    assert rec.handle == 1 and rec.flags == 2


def test_recover_key_ctx_blob_honours_handle_filter() -> None:
    view, _table, blob_va = _build_image()
    rec = sbox_key.recover_key_ctx_blob(view, handle=0x10000004, flags=2)
    assert rec is not None
    assert rec.blob_va == blob_va + 0x1100
    # A handle that is not present returns None.
    assert sbox_key.recover_key_ctx_blob(view, handle=0x99, flags=2) is None


def test_recover_key_ctx_report_reports_ok(tmp_path: Path) -> None:
    # recover_key_ctx_report needs a real PE via PeView, so exercise the pure path here
    # through the FakeView helpers instead; assert the report shape via the module API.
    view, _table, blob_va = _build_image()
    rec = sbox_key.recover_key_ctx_blob(view)
    assert rec is not None
    d = rec.as_dict()
    assert d["blob_va"] == hex(blob_va)
    assert d["length"] == hex(sbox_key.KEY_CTX_LEN)


def test_recover_key_ctx_blob_derives_without_static_handle() -> None:
    """Discovery needs no static handle/flags: it picks the largest high-entropy blob.

    The key-context length is derived from the data, so a blob whose length differs from
    the documented KEY_CTX_LEN is still found (as long as it is the largest high-entropy
    entry). This proves discovery does not match against a hard-coded length.
    """
    data = bytearray(0x9000)
    # A key-context blob of a NON-standard length, high entropy.
    custom_len = 0x900
    blob_va = _IMAGE_BASE + 0x5000
    blob_off = _RDATA_OFF + (blob_va - (_IMAGE_BASE + _RDATA_OFF))
    data[blob_off : blob_off + custom_len] = bytes((i * 31 + 7) % 256 for i in range(custom_len))
    # A small low-entropy IV slot (should never be chosen).
    iv_va = _IMAGE_BASE + 0x6800
    iv_off = _RDATA_OFF + (iv_va - (_IMAGE_BASE + _RDATA_OFF))
    data[iv_off : iv_off + 0x20] = b"\x00" * 0x20

    table_va = _IMAGE_BASE + 0x6000
    table_off = _RDATA_OFF + (table_va - (_IMAGE_BASE + _RDATA_OFF))
    data[table_off : table_off + 24] = _registry_entry(7, 2, blob_va, custom_len)
    data[table_off + 24 : table_off + 48] = _registry_entry(8, 0, iv_va, 0x20)

    code_va = _IMAGE_BASE + _TEXT_OFF + 0x40
    code_off = _TEXT_OFF + (code_va - (_IMAGE_BASE + _TEXT_OFF))
    data[code_off : code_off + 18] = _descriptor_getter_bytes(table_va, code_va, 2)

    view = FakeView(bytes(data))
    rec = sbox_key.recover_key_ctx_blob(view)  # no handle/flags
    assert rec is not None
    assert rec.blob_va == blob_va
    assert rec.length == custom_len  # derived, not KEY_CTX_LEN
    assert rec.length != sbox_key.KEY_CTX_LEN
