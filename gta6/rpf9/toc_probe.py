from __future__ import annotations

import struct
from pathlib import Path

from gta6.rpf9.entries import DIR_MARKER, parse_entry
from gta6.rpf9.format import HEADER_SIZE, RPF9_MAGIC
from gta6.rpf9.head import parse_toc_head

# Structural offsets of the known-plaintext region (bytes are build-specific and
# not committed; see gta6.rpf9.toc_key).
TEMPLATE_OFFSET = 16
CLEARTEXT_TEMPLATE_END = 64


def split_toc_blob(toc: bytes) -> dict[str, bytes]:
    """Separate variable head, template region, and encrypted tail."""
    head = toc[:TEMPLATE_OFFSET]
    template = (
        toc[TEMPLATE_OFFSET:CLEARTEXT_TEMPLATE_END]
        if len(toc) >= CLEARTEXT_TEMPLATE_END
        else b""
    )
    tail = toc[CLEARTEXT_TEMPLATE_END:] if len(toc) > CLEARTEXT_TEMPLATE_END else b""
    return {"head": head, "template": template, "tail": tail}


def read_toc(path: Path, base: int = 0) -> bytes:
    with path.open("rb") as fh:
        fh.seek(base)
        hdr = fh.read(HEADER_SIZE)
        if len(hdr) < HEADER_SIZE:
            return b""
        fields = struct.unpack("<8I", hdr)
        if fields[0] != RPF9_MAGIC:
            return b""
        toc_size = fields[1]
        fh.seek(base + HEADER_SIZE)
        return fh.read(toc_size)


def probe_archive(path: Path) -> dict[str, object]:
    toc = read_toc(path)
    parsed = []
    for i in range(min(4, len(toc) // 16)):
        e = parse_entry(i, toc, i * 16)
        parsed.append(
            {
                "index": i,
                "kind": e.kind.name,
                "name_offset": e.name_offset,
                "file_offset_blocks": e.file_offset_blocks,
                "file_size": e.file_size,
                "file_uncompressed_size": e.file_uncompressed_size,
                "encryption_type": e.encryption_type,
                "entries_index": e.entries_index,
                "entries_count": e.entries_count,
            }
        )

    d2_checks = []
    for off in (32, 48):
        if len(toc) >= off + 16:
            d1 = struct.unpack_from("<I", toc, off + 4)[0]
            d2_checks.append({"offset": off, "dword1_eq_dir": d1 == DIR_MARKER})

    with path.open("rb") as fh:
        encryption_field = struct.unpack("<8I", fh.read(HEADER_SIZE))[3]
    parts = split_toc_blob(toc)
    head_fields = parse_toc_head(toc[:16]) if len(toc) >= 16 else None
    return {
        "path": str(path),
        "toc_size": len(toc),
        "encryption_field": encryption_field,
        "head_hex": parts["head"].hex(),
        "toc_head": (
            {
                "dwords_hex": [
                    f"{head_fields.dword0:#x}",
                    f"{head_fields.dword1:#x}",
                    f"{head_fields.dword2:#x}",
                    f"{head_fields.dword3:#x}",
                ],
                "entry0_hint": head_fields.entry0_hint,
            }
            if head_fields
            else None
        ),
        "tail_length": len(parts["tail"]),
        "tail_entropy_sample_hex": parts["tail"][:32].hex(),
        "entries_first_16_bytes": parsed,
        "dir_marker_at_32_or_48": d2_checks,
    }


def probe_paths(paths: list[Path]) -> dict[str, object]:
    rows = [probe_archive(p) for p in paths if p.is_file()]
    enc_hist: dict[str, int] = {}
    for r in rows:
        k = str(r.get("encryption_field"))
        enc_hist[k] = enc_hist.get(k, 0) + 1
    return {
        "count": len(rows),
        "encryption_histogram": enc_hist,
        "archives": rows,
        "cleartext_template_end": CLEARTEXT_TEMPLATE_END,
    }