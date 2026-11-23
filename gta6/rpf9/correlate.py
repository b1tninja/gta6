from __future__ import annotations

import struct
from pathlib import Path

from gta6.rpf9.format import HEADER_SIZE, RPF9_MAGIC
from gta6.rpf9.head import parse_toc_head


def correlate_archives(paths: list[Path]) -> dict[str, object]:
    rows: list[dict[str, object]] = []
    for path in paths:
        with path.open("rb") as fh:
            fh.seek(0)
            hdr = fh.read(HEADER_SIZE)
            if len(hdr) < HEADER_SIZE:
                continue
            w = struct.unpack("<8I", hdr)
            if w[0] != RPF9_MAGIC:
                continue
            fh.seek(HEADER_SIZE)
            toc_head = fh.read(16)
        th = parse_toc_head(toc_head)
        entry_count = w[1] // 16
        rows.append(
            {
                "file": path.name,
                "size": path.stat().st_size,
                "toc_bytes": w[1],
                "names_bytes": w[2],
                "encryption": w[3],
                "encryption_hex": f"{w[3]:#x}",
                "archive_id": [f"{w[4]:#x}", f"{w[5]:#x}"],
                "entry_count_guess": entry_count,
                "toc_head": [
                    f"{th.dword0:#x}",
                    f"{th.dword1:#x}",
                    f"{th.dword2:#x}",
                    f"{th.dword3:#x}",
                ],
                "dword0_low_byte": th.dword0 & 0xFF,
                "dword1_matches_enc_div16": (th.dword1 == w[3] // 16),
            }
        )

    # Group by shared toc_head dword2/dword3
    d2_groups: dict[str, list[str]] = {}
    d3_groups: dict[str, list[str]] = {}
    for r in rows:
        d2 = r["toc_head"][2]
        d3 = r["toc_head"][3]
        d2_groups.setdefault(str(d2), []).append(str(r["file"]))
        d3_groups.setdefault(str(d3), []).append(str(r["file"]))

    return {
        "count": len(rows),
        "rows": rows,
        "shared_dword2": {k: v for k, v in d2_groups.items() if len(v) > 1},
        "shared_dword3": {k: v for k, v in d3_groups.items() if len(v) > 1},
    }