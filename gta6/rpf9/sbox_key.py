"""Automatic AES key recovery from the game binary, anchored on the AES S-box.

The AES S-box is constant-derived (GF(2^8) inverse + affine map), so it is trivially
locatable in the binary by its known 256 bytes. On the Scarlett build the *forward*
S-box is absent (the T-tables are pre-whitened and stored compressed), but the
*inverse* S-box is present exactly once, which makes it a clean anchor.

Two recovery strategies live here:

**A. Registry-descriptor recovery (primary, fast, no full disasm).**
The block-cipher provider registry is a static table of ``{ u64 key, u64 val0, u64 len }``
entries; the AES-256 whitened-CBC key-context blob is the high-entropy ``val0`` with the
largest ``len``. The table is reached through a tiny *descriptor getter* whose body is::

    LEA  RAX,[rip+disp32]      ; -> &table
    MOV  [RCX],RAX
    MOV  dword [RCX+8],imm32   ; -> entry count
    RET

The byte pattern for that getter is **assembled from the mnemonics with keystone** (the
optional ``disasm`` extra) and the variable disp32/imm32 field offsets are *derived* by
assembling each instruction with two different placeholder immediates and diffing the
encodings -- so no opcode byte string is copied from the game. :func:`find_descriptor_getters`
scans ``.text`` with that pattern (a byte scan, so it runs in well under a second over the
~95 MB ``.text``). :func:`recover_key_ctx_blob` parses each candidate table, keeps the one
matching the crypto-registry signature (flags packed as ``handle<<32 | flags<<24`` with
``flags in {0,2,3}``, at least one high-entropy blob entry, all ``val0`` mapped), and
returns the key-context blob -- its length is **derived from the data** (largest
high-entropy entry), not hard-coded. This recovers the blob address **from the executable**
with no committed key material or exe pointer.

**B. S-box anchor (secondary, slow).**
Locate the inverse S-box, use capstone to scan ``.text`` for RIP-relative references to
it (the AES key-schedule / table-build sites), and collect high-entropy windows near
those references as raw key candidates. This is a candidate *filter* only — the concrete
cipher is whitened AES-256-CBC (see
``docs/notes/2026-11-24-rpf9-crypto-provider-reverse.md``) and the whitening is folded
into runtime tables, so a plain AES oracle match is not proof.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass
from pathlib import Path

import pefile

from gta6.rpf9 import toc_key

# Canonical AES S-boxes, generated from GF(2^8) math (constant-derived, so they are the
# search needles). The forward S-box is absent on this build; the inverse is the anchor.
KEY_LENGTHS = toc_key.KEY_LENGTHS  # (16, 24, 32)

# The AES-256 whitened-CBC key-context blob size (round keys + final whitening tables +
# IV slot). See crypto.py / the crypto-provider note sec 6.4. This is the *expected*
# size and is used only for reporting/validation -- discovery does NOT require it: the
# key-context blob is found structurally (largest high-entropy ``val0`` in the crypto
# registry), so the length is derived from the data, not matched against this constant.
KEY_CTX_LEN = 0x10F4
REGISTRY_ENTRY_SIZE = 24
# Shannon entropy (bits/byte) above which a region is treated as key material. A real
# AES key schedule / whitening table is ~8.0; an IV slot or pointer table is far lower.
HIGH_ENTROPY_BITS = 7.5


def _shannon_entropy(buf: bytes) -> float:
    """Shannon entropy in bits/byte (0..8). Used to spot key-schedule regions."""
    if not buf:
        return 0.0
    counts = [0] * 256
    for b in buf:
        counts[b] += 1
    n = len(buf)
    import math

    return -sum((c / n) * math.log2(c / n) for c in counts if c)


def _is_high_entropy(view: PeView, va: int, length: int, *, cap: int = 0x2000) -> bool:
    """True if the region at ``va`` looks like key material (high entropy)."""
    if not va or length <= 0:
        return False
    raw = view.read_at_va(va, min(length, cap))
    if raw is None or len(raw) < min(length, 64):
        return False
    return _shannon_entropy(raw) >= HIGH_ENTROPY_BITS
# Provider-registry key packing: (handle << 32) | (flags << 24). flags==2 is the
# block-cipher family (internal alg ids 0x10..0x15); 0/3 appear on other entries.
VALID_REGISTRY_FLAGS = frozenset({0, 2, 3})

# Descriptor-getter instruction sequence, expressed ONLY as mnemonics -- no byte
# literals. The bytes are assembled with keystone (optional ``disasm`` extra) and the
# variable disp32/imm32 field offsets are derived by diffing two assemblies, so nothing
# here is a byte string copied from the game binary.
#   LEA  rax,[rip+disp32]      -> &table   (disp32 is the variable field)
#   MOV  [rcx],rax
#   MOV  dword [rcx+8],imm32   -> entry count (imm32 is the variable field)
#   RET
# Each entry is (mnemonic_template, placeholder_field_name_or_None). The template uses
# ``{PH}`` where a 4-byte immediate/displacement will be substituted with two different
# probe values to locate the variable field.
_DESCRIPTOR_INSNS: tuple[tuple[str, str | None], ...] = (
    ("lea rax, [rip + {PH}]", "disp32"),
    ("mov qword ptr [rcx], rax", None),
    ("mov dword ptr [rcx + 8], {PH}", "imm32"),
    ("ret", None),
)

# Two distinct 32-bit probe immediates used to locate a variable field by diffing.
_PROBE_A = 0x11223344
_PROBE_B = 0x55667788


def _keystone_asm(text: str) -> bytes:
    """Assemble one x86-64 instruction with keystone. Raises ImportError if absent."""
    from keystone import KS_ARCH_X86, KS_MODE_64, Ks

    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    enc, n = ks.asm(text)
    if n != 1:
        raise ValueError(f"expected one instruction, got {n}: {text!r}")
    return bytes(enc)


def _assemble_descriptor_pattern() -> tuple[bytes, int]:
    """Build the descriptor-getter byte pattern from mnemonics via keystone.

    Returns ``(pattern, lea_len)`` where ``pattern`` is a regex bytes object with the
    variable disp32/imm32 fields replaced by ``(.{4})`` capture groups, and ``lea_len``
    is the length of the LEA instruction (opcode + 4-byte RIP displacement).

    For each instruction we assemble it twice with two different probe immediates. The
    byte offset where the two encodings first differ is the start of the variable field;
    the field is 4 bytes wide (disp32 / imm32). This *derives* the field offset from the
    assembler rather than hard-coding it. The fixed prefix/suffix bytes come straight
    from keystone's encoding, so they are ISA-derived, not copied from the game.
    """
    parts: list[bytes] = []
    lea_len = 0
    for template, field in _DESCRIPTOR_INSNS:
        if field is None:
            enc = _keystone_asm(template)
            parts.append(enc)
            if template.startswith("lea"):
                lea_len = len(enc)
            continue
        enc_a = _keystone_asm(template.replace("{PH}", hex(_PROBE_A)))
        enc_b = _keystone_asm(template.replace("{PH}", hex(_PROBE_B)))
        assert len(enc_a) == len(enc_b), f"probe length differs for {template!r}"
        # The variable field is the 4 bytes that differ between the two probes.
        diff = [i for i in range(len(enc_a)) if enc_a[i] != enc_b[i]]
        assert diff, f"probes identical for {template!r}"
        start = diff[0]
        assert diff == list(range(start, start + 4)), f"non-contiguous field for {template!r}"
        parts.append(enc_a[:start])
        parts.append(b"(.{4})")
        parts.append(enc_a[start + 4 :])
        if template.startswith("lea"):
            lea_len = len(enc_a)
    return b"".join(parts), lea_len


try:
    _DESCRIPTOR_RE_BYTES, _LEA_LEN = _assemble_descriptor_pattern()
    # Group 1 = LEA disp32, group 2 = MOV imm32 (entry count).
    _DESCRIPTOR_RE: re.Pattern[bytes] | None = re.compile(_DESCRIPTOR_RE_BYTES, re.S)
except ImportError:  # keystone not installed -> discovery path unavailable.
    _DESCRIPTOR_RE = None
    _LEA_LEN = 0


def gen_sbox() -> bytes:
    """Canonical AES forward S-box, generated from GF(2^8) math and self-checked."""
    exp = [0] * 512
    log = [0] * 256
    x = 1
    for i in range(255):
        exp[i] = x
        log[x] = i
        x ^= (x << 1) ^ (0x11B if x & 0x80 else 0)
        x &= 0xFF
    for i in range(255, 512):
        exp[i] = exp[i - 255]
    sbox = []
    for a in range(256):
        inv = 0 if a == 0 else exp[255 - log[a]]
        s = inv
        for sh in (1, 2, 3, 4):
            s ^= ((inv << sh) | (inv >> (8 - sh))) & 0xFF
            s &= 0xFF
        sbox.append(s ^ 0x63)
    out = bytes(sbox)
    assert out[0] == 0x63 and out[1] == 0x7C and out[255] == 0x16, out[:4].hex()
    return out


def gen_inv_sbox(fwd: bytes | None = None) -> bytes:
    fwd = gen_sbox() if fwd is None else fwd
    inv = [0] * 256
    for i, v in enumerate(fwd):
        inv[v] = i
    return bytes(inv)


@dataclass(frozen=True, slots=True)
class SboxHit:
    """One located S-box table in the binary."""

    kind: str  # "forward" | "inverse"
    file_offset: int
    va: int

    def as_dict(self) -> dict[str, object]:
        return {"kind": self.kind, "file_offset": self.file_offset, "va": hex(self.va)}


@dataclass(frozen=True, slots=True)
class CodeRef:
    """A RIP-relative reference to an S-box from a code instruction."""

    code_va: int
    target_va: int
    mnemonic: str
    op_str: str

    def as_dict(self) -> dict[str, object]:
        return {
            "code_va": hex(self.code_va),
            "target_va": hex(self.target_va),
            "insn": f"{self.mnemonic} {self.op_str}".strip(),
        }


@dataclass(frozen=True, slots=True)
class DescriptorGetter:
    """A function returning ``{ &table, count }`` (LEA + MOV + MOV imm + RET)."""

    code_va: int
    table_va: int
    count: int

    def as_dict(self) -> dict[str, object]:
        return {
            "code_va": hex(self.code_va),
            "table_va": hex(self.table_va),
            "count": self.count,
        }


@dataclass(frozen=True, slots=True)
class RegistryEntry:
    """One 24-byte provider-registry entry ``{ key, val0, len }``."""

    key: int
    val0: int
    length: int

    @property
    def handle(self) -> int:
        return self.key >> 32

    @property
    def flags(self) -> int:
        return (self.key >> 24) & 0xFF

    def as_dict(self) -> dict[str, object]:
        return {
            "key": hex(self.key),
            "handle": hex(self.handle),
            "flags": self.flags,
            "val0": hex(self.val0),
            "len": hex(self.length),
        }


@dataclass(frozen=True, slots=True)
class RecoveredKeyCtx:
    """The recovered key-context blob: where it lives and how it was found."""

    blob_va: int
    blob_off: int  # file offset of the blob
    length: int
    table_va: int
    getter_va: int
    handle: int
    flags: int

    @property
    def blob_hex(self) -> str:
        return hex(self.blob_va)

    def as_dict(self) -> dict[str, object]:
        return {
            "blob_va": self.blob_hex,
            "blob_off": self.blob_off,
            "length": hex(self.length),
            "table_va": hex(self.table_va),
            "getter_va": hex(self.getter_va),
            "handle": hex(self.handle),
            "flags": self.flags,
        }


@dataclass(frozen=True, slots=True)
class RecoveredKey:
    key: bytes
    source: str  # how it was found
    offset: int  # file offset of the key bytes
    scheme: str  # oracle scheme that accepted it, if any

    @property
    def key_hex(self) -> str:
        return self.key.hex()

    def as_dict(self) -> dict[str, object]:
        return {
            "key_hex": self.key_hex,
            "source": self.source,
            "offset": self.offset,
            "scheme": self.scheme,
        }


class PeView:
    """Minimal PE view: file-offset <-> VA mapping and section access."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.data = path.read_bytes()
        self.pe = pefile.PE(str(path), fast_load=True)
        self.image_base = self.pe.OPTIONAL_HEADER.ImageBase
        self._sections = [
            {
                "name": s.Name.rstrip(b"\x00").decode(errors="replace"),
                "va": self.image_base + s.VirtualAddress,
                "vsize": max(s.Misc_VirtualSize, s.SizeOfRawData),
                "raw": s.PointerToRawData,
                "raw_size": s.SizeOfRawData,
                "chars": s.Characteristics,
            }
            for s in self.pe.sections
        ]

    def file_to_va(self, off: int) -> int | None:
        for s in self._sections:
            if s["raw"] <= off < s["raw"] + s["raw_size"]:
                return s["va"] + (off - s["raw"])
        return None

    def va_to_file(self, va: int) -> int | None:
        for s in self._sections:
            if s["va"] <= va < s["va"] + s["vsize"]:
                return s["raw"] + (va - s["va"])
        return None

    def section_by_name(self, name: str) -> dict | None:
        for s in self._sections:
            if s["name"] == name:
                return s
        return None

    def read_at_va(self, va: int, size: int) -> bytes | None:
        off = self.va_to_file(va)
        if off is None:
            return None
        return self.data[off : off + size]


def find_sboxes(view: PeView) -> list[SboxHit]:
    """Locate forward and inverse AES S-boxes by their constant bytes."""
    fwd = gen_sbox()
    inv = gen_inv_sbox(fwd)
    hits: list[SboxHit] = []
    for kind, tbl in (("forward", fwd), ("inverse", inv)):
        start = 0
        while True:
            i = view.data.find(tbl, start)
            if i < 0:
                break
            va = view.file_to_va(i)
            if va is not None:
                hits.append(SboxHit(kind=kind, file_offset=i, va=va))
            start = i + 1
    return hits


def _is_rip_relative_ref(insn, target_va: int) -> bool:
    """True if insn uses RIP-relative addressing resolving to target_va."""
    # capstone x86: an operand with base == RIP and a disp encodes the resolved address
    # in insn.reg_name / the operand's disp. We recompute from the instruction length.
    if insn.reg_name is None:
        return False
    for op in insn.operands:
        if op.type == 3:  # X86_OP_MEM
            base = insn.reg_name(op.mem.base)
            if base in ("rip", "eip"):
                resolved = insn.address + insn.size + op.mem.disp
                if resolved == target_va:
                    return True
    return False


def find_code_refs(view: PeView, target_va: int, *, text_only: bool = True) -> list[CodeRef]:
    """Disassemble .text and return RIP-relative references to ``target_va``."""
    from capstone import CS_ARCH_X86, CS_MODE_64, Cs

    text = view.section_by_name(".text") if text_only else None
    if text is None:
        return []
    code = view.data[text["raw"] : text["raw"] + text["raw_size"]]
    base_va = text["va"]
    chunk = 4 << 20  # 4 MiB per disasm call; .text is ~95 MB
    refs: list[CodeRef] = []
    pos = 0
    n = len(code)
    while pos < n:
        end = min(pos + chunk, n)
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = True
        consumed = 0
        for insn in md.disasm(code[pos:end], base_va + pos):
            consumed = (insn.address - base_va) + insn.size - pos
            if _is_rip_relative_ref(insn, target_va):
                refs.append(
                    CodeRef(
                        code_va=insn.address,
                        target_va=target_va,
                        mnemonic=insn.mnemonic,
                        op_str=insn.op_str,
                    )
                )
        if consumed <= 0:
            consumed = end - pos  # nothing decoded; skip the whole chunk
        pos += consumed
    return refs


def _plausible_key(key: bytes) -> bool:
    return toc_key._plausible_key(key)


def key_candidates_near_refs(
    view: PeView,
    refs: list[CodeRef],
    *,
    key_lengths: tuple[int, ...] = KEY_LENGTHS,
    window: int = 0x400,
) -> list[tuple[int, bytes]]:
    """Collect plausible key windows from data referenced near the S-box code refs.

    For each code reference, scan the referenced data region (and a window after it)
    for high-entropy 16/24/32-byte windows. These are candidate AES keys / key-schedule
    inputs.
    """
    seen: set[bytes] = set()
    out: list[tuple[int, bytes]] = []
    for ref in refs:
        base_off = view.va_to_file(ref.target_va)
        if base_off is None:
            continue
        region = view.data[base_off : base_off + window]
        for klen in key_lengths:
            for off in range(0, len(region) - klen + 1, 4):
                cand = region[off : off + klen]
                if cand in seen or not _plausible_key(cand):
                    continue
                seen.add(cand)
                out.append((base_off + off, cand))
    return out


def recover_keys(
    exe: Path,
    *,
    template: bytes | None = None,
    nonces: list[tuple[str, bytes]] | None = None,
    key_lengths: tuple[int, ...] = KEY_LENGTHS,
    max_candidates: int = 200_000,
) -> dict[str, object]:
    """Recover AES key candidates from the game binary, anchored on the S-box.

    Returns a report dict with the located S-boxes, code references, and any candidate
    keys that pass the TOC template oracle.
    """
    view = PeView(exe)
    sboxes = find_sboxes(view)
    oracle = toc_key.TemplateOracle(template) if template else toc_key.TemplateOracle()
    nonces = nonces or [("zero", bytes(16))]

    report: dict[str, object] = {
        "exe": str(exe),
        "image_base": hex(view.image_base),
        "sboxes": [s.as_dict() for s in sboxes],
        "code_refs": [],
        "candidates_scanned": 0,
        "hits": [],
    }

    # Anchor on whichever S-box is present (inverse on this build).
    anchor = next((s for s in sboxes if s.kind == "inverse"), None)
    anchor = anchor or (sboxes[0] if sboxes else None)
    if anchor is None:
        report["status"] = "no_sbox"
        return report

    refs = find_code_refs(view, anchor.va)
    report["anchor"] = anchor.as_dict()
    report["code_refs"] = [r.as_dict() for r in refs]

    candidates = key_candidates_near_refs(view, refs, key_lengths=key_lengths)
    report["candidates_scanned"] = len(candidates[:max_candidates])

    hits: list[dict[str, object]] = []
    for off, key in candidates[:max_candidates]:
        hit = None
        if len(key) == 32:
            hit = oracle.test_ecb(key)
            for _name, nonce in nonces:
                hit = hit or oracle.test_ctr(key, nonce) or oracle.test_cfb(key, nonce)
        if hit is not None:
            rec = RecoveredKey(key=key, source="sbox_ref", offset=off, scheme=hit.scheme)
            hits.append(rec.as_dict())
    report["hits"] = hits
    report["status"] = "ok" if hits else "no_hits"
    return report


# --------------------------------------------------------------------------- #
# Strategy A: registry-descriptor recovery (primary)
# --------------------------------------------------------------------------- #


def find_descriptor_getters(view: PeView) -> list[DescriptorGetter]:
    """Find ``{ &table, count }`` getter functions in ``.text`` by byte pattern.

    Matches ``LEA r64,[rip+disp32] ; MOV [r64],r64 ; MOV dword [r64+8],imm32 ; RET``
    and resolves the RIP-relative displacement to the referenced table VA. This is a
    plain byte scan (no disassembler), so it is fast even on a ~95 MB ``.text``.
    """
    if _DESCRIPTOR_RE is None:
        return []
    text = view.section_by_name(".text")
    if text is None:
        return []
    code = view.data[text["raw"] : text["raw"] + text["raw_size"]]
    base_va = text["va"]
    out: list[DescriptorGetter] = []
    for m in _DESCRIPTOR_RE.finditer(code):
        disp = struct.unpack("<i", m.group(1))[0]
        count = struct.unpack("<I", m.group(2))[0]
        va = base_va + m.start()
        table_va = va + _LEA_LEN + disp
        out.append(DescriptorGetter(code_va=va, table_va=table_va, count=count))
    return out


def parse_registry_table(view: PeView, table_va: int, count: int) -> list[RegistryEntry]:
    """Parse ``count`` 24-byte ``{ u64 key, u64 val0, u64 len }`` entries at ``table_va``.

    Returns an empty list if the table is not fully mapped in the image.
    """
    if count <= 0:
        return []
    raw = view.read_at_va(table_va, count * REGISTRY_ENTRY_SIZE)
    if raw is None or len(raw) < count * REGISTRY_ENTRY_SIZE:
        return []
    out: list[RegistryEntry] = []
    for i in range(count):
        key, val0, length = struct.unpack_from("<QQQ", raw, i * REGISTRY_ENTRY_SIZE)
        out.append(RegistryEntry(key=key, val0=val0, length=length))
    return out


def is_crypto_registry(entries: list[RegistryEntry], view: PeView) -> bool:
    """True if ``entries`` look like the block-cipher provider registry.

    Signature (all structural, no hard-coded addresses or lengths): every key packs
    flags in ``{0,2,3}`` (the ``handle<<32 | flags<<24`` scheme), at least one entry's
    ``val0`` is a high-entropy key-context blob, and every non-null ``val0`` resolves to
    a mapped VA in the image.
    """
    if not entries:
        return False
    if not all(e.flags in VALID_REGISTRY_FLAGS for e in entries):
        return False
    if not any(_is_high_entropy(view, e.val0, e.length) for e in entries):
        return False
    return all(view.va_to_file(e.val0) is not None for e in entries if e.val0)


def recover_key_ctx_blob(
    view: PeView,
    *,
    handle: int | None = None,
    flags: int | None = None,
) -> RecoveredKeyCtx | None:
    """Recover the AES key-context blob address from the executable.

    Scans for descriptor getters (keystone-assembled pattern), keeps the table matching
    the crypto-registry signature, and returns the key-context blob: the **largest
    high-entropy** ``val0`` in that table (its length is derived from the data, not
    matched to a constant). ``handle`` / ``flags`` are *optional* filters — when given,
    the entry must also match them (e.g. ``handle=1, flags=2`` pins the static archive
    key); when omitted, the first largest high-entropy blob is returned. Returns ``None``
    if no registry table or matching entry is found, or if keystone is unavailable.
    """
    if _DESCRIPTOR_RE is None:
        return None
    for getter in find_descriptor_getters(view):
        entries = parse_registry_table(view, getter.table_va, getter.count)
        if not is_crypto_registry(entries, view):
            continue
        # Candidate key-context blobs: high-entropy val0, mapped, matching optional
        # filters. Pick the largest (the key schedule dominates the small IV/nonce slots).
        candidates = [
            e
            for e in entries
            if _is_high_entropy(view, e.val0, e.length)
            and view.va_to_file(e.val0) is not None
            and (handle is None or e.handle == handle)
            and (flags is None or e.flags == flags)
        ]
        if not candidates:
            continue
        entry = max(candidates, key=lambda e: (e.length, -entries.index(e)))
        blob_off = view.va_to_file(entry.val0)
        assert blob_off is not None
        return RecoveredKeyCtx(
            blob_va=entry.val0,
            blob_off=blob_off,
            length=entry.length,
            table_va=getter.table_va,
            getter_va=getter.code_va,
            handle=entry.handle,
            flags=entry.flags,
        )
    return None


def recover_key_ctx_report(
    exe: Path, *, handle: int | None = None, flags: int | None = None
) -> dict[str, object]:
    """Recover the key-context blob and return a JSON-friendly report.

    This is the address-recovery entry point used by the CLI: it derives the blob
    location from the executable so no key material or hard-coded exe pointer needs to
    be committed.
    """
    view = PeView(exe)
    getters = find_descriptor_getters(view)
    report: dict[str, object] = {
        "exe": str(exe),
        "image_base": hex(view.image_base),
        "descriptor_getters": [g.as_dict() for g in getters],
        "key_ctx": None,
        "status": "no_registry",
    }
    recovered = recover_key_ctx_blob(view, handle=handle, flags=flags)
    if recovered is not None:
        report["key_ctx"] = recovered.as_dict()
        report["status"] = "ok"
    return report
