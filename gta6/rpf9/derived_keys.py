from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from pathlib import Path

from gta6.rpf9.crypto import aes256_ecb_decrypt, decrypt_toc_and_names
from gta6.rpf9.entries import DIR_MARKER, names_plausibility
from gta6.rpf9.format import HEADER_SIZE, RPF9_MAGIC
from gta6.rpf9.template import CLEARTEXT_TEMPLATE_END


@dataclass(frozen=True, slots=True)
class DerivedKey:
    label: str
    key: bytes


def _pad32(data: bytes) -> bytes:
    if len(data) >= 32:
        return data[:32]
    return data + b"\x00" * (32 - len(data))


def header_derived_keys(path: Path, base: int = 0) -> list[DerivedKey]:
    with path.open("rb") as fh:
        fh.seek(base)
        hdr = fh.read(HEADER_SIZE)
    if len(hdr) < HEADER_SIZE:
        return []
    fields = struct.unpack("<8I", hdr)
    if fields[0] != RPF9_MAGIC:
        return []
    magic, toc_sz, names_sz, enc, id_a, id_b, plat, flags = fields
    seed_pairs: list[tuple[str, bytes]] = [
        ("raw_ids_8", struct.pack("<II", id_a, id_b)),
        ("raw_ids_enc_16", struct.pack("<4I", id_a, id_b, enc, plat)),
        ("full_hdr_32", hdr[4:36]),
        ("filename", path.name.encode("ascii")),
        ("stem", path.stem.encode("ascii")),
        ("enc_plat", struct.pack("<III", enc, plat, flags)),
        ("toc_sizes", struct.pack("<II", toc_sz, names_sz)),
    ]
    out: list[DerivedKey] = []
    for label, seed in seed_pairs:
        out.append(DerivedKey(f"pad32:{label}", _pad32(seed)))
        out.append(DerivedKey(f"sha256:{label}", hashlib.sha256(seed).digest()))
        out.append(DerivedKey(f"md5x2:{label}", hashlib.md5(seed).digest() * 2))
    return out


def score_decryption(toc_tail: bytes, names: bytes) -> float:
    import struct as st

    if not toc_tail and not names:
        return 0.0
    markers = 0
    for i in range(0, max(0, len(toc_tail) - 7), 16):
        if st.unpack_from("<I", toc_tail, i + 4)[0] == DIR_MARKER:
            markers += 1
    name_score = names_plausibility(names)
    tail_print = 0.0
    if toc_tail:
        tail_print = sum(1 for b in toc_tail if b == 0 or 0x20 <= b <= 0x7E) / len(toc_tail)
    return name_score * 0.7 + min(1.0, markers / 2) * 0.2 + tail_print * 0.1


def try_derived_keys(
    archive: Path,
    *,
    base: int = 0,
) -> list[dict[str, object]]:
    keys = header_derived_keys(archive, base)
    with archive.open("rb") as fh:
        fh.seek(base)
        fields = struct.unpack("<8I", fh.read(HEADER_SIZE))
        toc_size, names_size = fields[1], fields[2]
        fh.seek(base + HEADER_SIZE)
        blob = fh.read(toc_size + names_size)
    toc = blob[:toc_size]
    names = blob[toc_size:]
    tail = toc[CLEARTEXT_TEMPLATE_END:]

    hits: list[dict[str, object]] = []
    for dk in keys:
        try:
            dec_tail = aes256_ecb_decrypt(tail, dk.key)
            dec_names = aes256_ecb_decrypt(names, dk.key) if names else b""
        except Exception:
            continue
        score = score_decryption(dec_tail, dec_names)
        if score >= 0.75 or (
            b"\x00\xff\xff\x7f" in dec_tail and names_plausibility(dec_names) > 0.6
        ):
            hits.append({"label": dk.label, "score": round(score, 4), "key_hex": dk.key.hex()})
        # whole-blob decrypt (legacy rpf7 style)
        try:
            whole = decrypt_toc_and_names(blob, dk.key)
            whole_tail = whole[CLEARTEXT_TEMPLATE_END:toc_size]
            whole_names = whole[toc_size:]
            wscore = score_decryption(whole_tail, whole_names)
            if wscore > score:
                hits.append(
                    {
                        "label": f"whole:{dk.label}",
                        "score": round(wscore, 4),
                        "key_hex": dk.key.hex(),
                    }
                )
        except Exception:
            pass

    hits.sort(key=lambda x: float(x["score"]), reverse=True)
    # always return top trials for debugging
    trials: list[dict[str, object]] = []
    for dk in keys[:6]:
        dec_names = aes256_ecb_decrypt(names, dk.key) if names else b""
        trials.append(
            {
                "label": dk.label,
                "names_score": round(names_plausibility(dec_names), 4),
            }
        )
    return {"hits": hits[:10], "top_trials": trials, "tried": len(keys)}