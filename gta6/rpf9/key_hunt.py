from __future__ import annotations

from pathlib import Path

from gta6.rpf9.crypto import decrypt_toc_and_names
from gta6.rpf9.entries import DIR_MARKER, names_plausibility
from gta6.rpf9.keys import scan_exe_for_key_candidates
from gta6.rpf9.template import CLEARTEXT_TEMPLATE_END


def _score_toc_tail(plain_tail: bytes) -> float:
    """Best-effort: decrypted tail should contain directory markers and plausible names."""
    import struct

    if len(plain_tail) < 16:
        return 0.0
    markers = sum(
        1
        for i in range(0, len(plain_tail) - 7, 16)
        if struct.unpack_from("<I", plain_tail, i + 4)[0] == DIR_MARKER
    )
    # names often trail toc; without names blob, use marker density + low entropy runs
    marker_score = min(1.0, markers / 3.0)
    printable = sum(1 for b in plain_tail if b == 0 or 0x20 <= b <= 0x7E) / len(plain_tail)
    return 0.5 * marker_score + 0.5 * printable


def trial_keys_on_archive(
    binary: Path,
    toc_tail: bytes,
    names_blob: bytes,
    *,
    limit: int = 500,
) -> list[dict[str, object]]:
    hits: list[dict[str, object]] = []
    for idx, key in enumerate(scan_exe_for_key_candidates(binary, limit=limit)):
        dec_tail = decrypt_toc_and_names(toc_tail, key)
        dec_names = decrypt_toc_and_names(names_blob, key) if names_blob else b""
        tail_score = _score_toc_tail(dec_tail)
        name_score = names_plausibility(dec_names)
        combined = max(tail_score, name_score)
        if combined >= 0.7 or (
            b"\x00\xff\xff\x7f" in dec_tail
            and names_plausibility(dec_names) > 0.85
        ):
            hits.append(
                {
                    "key_index": idx,
                    "key_hex": key.hex(),
                    "tail_score": round(tail_score, 4),
                    "names_score": round(name_score, 4),
                }
            )
    hits.sort(key=lambda x: float(x["names_score"]) + float(x["tail_score"]), reverse=True)
    return hits[:20]


def load_toc_and_names(path: Path, base: int = 0) -> tuple[bytes, bytes]:
    import struct

    from gta6.rpf9.format import HEADER_SIZE

    with path.open("rb") as fh:
        fh.seek(base)
        hdr = fh.read(HEADER_SIZE)
        toc_size, names_size = struct.unpack_from("<II", hdr, 4)
        fh.seek(base + HEADER_SIZE)
        blob = fh.read(toc_size + names_size)
    toc = blob[:toc_size]
    names = blob[toc_size:]
    tail = toc[CLEARTEXT_TEMPLATE_END:]
    return tail, names