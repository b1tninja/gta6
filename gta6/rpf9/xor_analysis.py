from __future__ import annotations

import struct
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from gta6.rpf9.format import HEADER_SIZE, RPF9_MAGIC


@dataclass(frozen=True, slots=True)
class Rpf9Slice:
    path: Path
    base_offset: int
    header: bytes
    toc_names: bytes
    encryption: int

    @property
    def label(self) -> str:
        return f"{self.path.name}@{self.base_offset}"


def load_slices(path: Path, *, max_slices: int = 4, toc_cap: int = 4096) -> list[Rpf9Slice]:
    """Read only headers + TOC/names blobs (never the full archive)."""
    needle = struct.pack("<I", RPF9_MAGIC)
    out: list[Rpf9Slice] = []
    with path.open("rb") as fh:
        window = fh.read(512 * 1024)
        pos = 0
        while len(out) < max_slices:
            i = window.find(needle, pos)
            if i < 0:
                break
            fh.seek(i)
            header = fh.read(HEADER_SIZE)
            if len(header) < HEADER_SIZE:
                break
            fields = struct.unpack("<8I", header)
            if fields[0] != RPF9_MAGIC:
                pos = i + 4
                continue
            toc_size = fields[1]
            names_size = fields[2]
            blob_len = min(toc_size + names_size, toc_cap)
            fh.seek(i + HEADER_SIZE)
            toc_names = fh.read(blob_len)
            out.append(
                Rpf9Slice(
                    path=path,
                    base_offset=i,
                    header=header,
                    toc_names=toc_names,
                    encryption=fields[3],
                )
            )
            pos = i + 4
    return out


def xor_bytes(a: bytes, b: bytes) -> bytes:
    n = min(len(a), len(b))
    return bytes(x ^ y for x, y in zip(a[:n], b[:n], strict=False))


def repeat_xor(data: bytes, key: bytes) -> bytes:
    if not key:
        return data
    out = bytearray(len(data))
    for i, b in enumerate(data):
        out[i] = b ^ key[i % len(key)]
    return bytes(out)


def leading_equal(a: bytes, b: bytes) -> int:
    for n, (x, y) in enumerate(zip(a, b, strict=False)):
        if x != y:
            return n
    return min(len(a), len(b))


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    import math

    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def scan_plaintext_markers(data: bytes) -> dict[str, int | bool | float]:
    if not data:
        return {"entropy": 0.0, "printable_ratio": 0.0}
    dir_count = sum(
        1 for i in range(max(0, len(data) - 3)) if data[i : i + 4] == b"\x00\xff\xff\x7f"
    )
    return {
        "dir_marker_count": dir_count,
        "slash_count": data.count(ord("/")),
        "dot_count": data.count(ord(".")),
        "null_count": data.count(0),
        "printable_ratio": round(
            sum(1 for b in data if b == 0 or 0x20 <= b <= 0x7E) / len(data),
            4,
        ),
        "entropy": round(entropy(data), 3),
    }


def header_field_analysis(slices: list[Rpf9Slice]) -> dict[str, object]:
    """Compare cleartext header dwords across archives."""
    rows: list[dict[str, object]] = []
    for s in slices:
        fields = struct.unpack("<8I", s.header)
        rows.append(
            {
                "label": s.label,
                "encryption": s.encryption,
                "fields_hex": [f"{f:#x}" for f in fields],
                "toc_names_len": len(s.toc_names),
            }
        )

    # Constant columns (same value in every slice)
    if not slices:
        return {"rows": rows, "constant_indices": []}
    field_lists = [struct.unpack("<8I", s.header) for s in slices]
    constant = []
    for idx in range(8):
        vals = {f[idx] for f in field_lists}
        if len(vals) == 1:
            constant.append({"index": idx, "value": f"{field_lists[0][idx]:#x}"})
    return {"rows": rows, "constant_field_indices": constant}


def pairwise_xor_report(a: Rpf9Slice, b: Rpf9Slice) -> dict[str, object]:
    x_hdr = xor_bytes(a.header, b.header)
    x_toc = xor_bytes(a.toc_names, b.toc_names)
    # If same keystream, XOR of ciphertexts = XOR of plaintexts
    eq_hdr = leading_equal(a.header, b.header)
    eq_toc = leading_equal(a.toc_names, b.toc_names)
    return {
        "a": a.label,
        "b": b.label,
        "header_identical_prefix": eq_hdr,
        "toc_identical_prefix": eq_toc,
        "header_xor_entropy": round(entropy(x_hdr), 3),
        "toc_xor_entropy": round(entropy(x_toc), 3),
        "toc_xor_markers": scan_plaintext_markers(x_toc[: min(2048, len(x_toc))]),
        "toc_xor_first64_hex": x_toc[:64].hex(),
        # Repeating 16/32-byte key hypothesis: low entropy in xor stream suggests reused key
        "toc_xor_block16_repeat_score": _block_repeat_score(x_toc, 16),
        "toc_xor_block32_repeat_score": _block_repeat_score(x_toc, 32),
    }


def _block_repeat_score(data: bytes, block: int) -> float:
    if len(data) < block * 2:
        return 0.0
    blocks = [data[i : i + block] for i in range(0, len(data) - block + 1, block)]
    if len(blocks) < 2:
        return 0.0
    c = Counter(blocks)
    most = c.most_common(1)[0][1]
    return round(most / len(blocks), 4)


def repeated_ciphertext_blocks(slices: list[Rpf9Slice], block: int = 16) -> list[dict[str, object]]:
    """Find identical ciphertext blocks shared across TOC regions."""
    hits: dict[bytes, list[str]] = {}
    for s in slices:
        data = s.toc_names
        for i in range(0, len(data) - block + 1, block):
            blk = data[i : i + block]
            hits.setdefault(blk, []).append(f"{s.label}:{i}")
    common = [
        {"block_hex": k.hex(), "count": len(v), "sites": v[:8]}
        for k, v in hits.items()
        if len(v) >= 2 and any(b != 0 for b in k)
    ]
    common.sort(key=lambda x: -x["count"])
    return common[:25]


def global_toc_constants(paths: list[Path]) -> dict[str, object]:
    """Locate cleartext or identical ciphertext spans in TOC blobs."""
    blobs: list[tuple[str, bytes]] = []
    for p in paths:
        for sl in load_slices(p):
            blobs.append((sl.label, sl.toc_names[:512]))

    if not blobs:
        return {"labels": [], "constant_ranges": []}

    ref_name, ref = blobs[0]
    length = min(len(b) for _, b in blobs)
    constant_spans: list[dict[str, int | str]] = []
    i = 0
    while i < length:
        if all(b[i] == ref[i] for _, b in blobs):
            start = i
            while i < length and all(b[i] == ref[i] for _, b in blobs):
                i += 1
            chunk = ref[start:i]
            constant_spans.append(
                {
                    "start": start,
                    "end": i,
                    "length": i - start,
                    "hex": chunk[:64].hex(),
                    "all_zero": chunk == b"\x00" * len(chunk),
                }
            )
        else:
            i += 1

    first_diff = []
    for name, blob in blobs[1:]:
        for j in range(length):
            if blob[j] != ref[j]:
                first_diff.append({"a": ref_name, "b": name, "offset": j})
                break

    return {
        "reference": ref_name,
        "archive_count": len(blobs),
        "constant_spans": constant_spans,
        "first_differing_offset": first_diff,
    }


def analyze(paths: list[Path]) -> dict[str, object]:
    all_slices: list[Rpf9Slice] = []
    for p in paths:
        all_slices.extend(load_slices(p))

    pairs: list[dict[str, object]] = []
    for i, a in enumerate(all_slices):
        for b in all_slices[i + 1 :]:
            if len(a.toc_names) >= 64 and len(b.toc_names) >= 64:
                pairs.append(pairwise_xor_report(a, b))

    # XOR ciphertext with repeated constant header suffix (platform tag region is cleartext
    # in our model - but bytes 16-31 vary; only 24-31 constant). Test XOR toc with bytes 24-31.
    keystream_tests: list[dict[str, object]] = []
    const_suffix = struct.pack("<II", 293376, 336)
    for s in all_slices[:20]:
        trial = repeat_xor(s.toc_names[:512], const_suffix)
        keystream_tests.append(
            {
                "label": s.label,
                "trial_key": "platform_tag_dwords",
                "markers": scan_plaintext_markers(trial),
            }
        )

    return {
        "slice_count": len(all_slices),
        "global_toc_constants": global_toc_constants(paths),
        "header_analysis": header_field_analysis(all_slices),
        "pairwise_xor": pairs,
        "repeated_ciphertext_16": repeated_ciphertext_blocks(all_slices, 16),
        "repeated_ciphertext_32": repeated_ciphertext_blocks(all_slices, 32),
        "naive_keystream_trials": keystream_tests,
    }