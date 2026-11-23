"""Recover the RPF9 TOC key from the leaked game executable.

What the layout actually is (measured across the Xbox install, 2026-11-21):

* The 32-byte file header is cleartext.
* The **data region is cleartext**: zlib streams sit at block-aligned offsets
  and inflate, and page padding is stored as literal zeros.
* Only the ``TOC + names`` blob is encrypted.
* ``TOC[16:64]`` is a 48-byte region identical in *every* archive, made of three
  **different** 16-byte blocks.

That last point is the key-recovery lever. A block cipher in ECB maps equal
plaintext blocks to equal ciphertext blocks, so three distinct ciphertext
blocks cannot be the ECB encryption of a zero run. They are either cleartext
metadata or the output of a mode whose block-to-block mapping is not constant
(CTR/CFB/CBC). Either way they are a *known* 48-byte string that is the same for
every archive, which makes them a searchable fingerprint:

* if the key is **global**, the exe contains a key whose CTR/CFB keystream at
  some nonce produces exactly those bytes;
* if the key is **per-archive**, the exe contains the derivation and the
  constants themselves.

``sweep_exe`` searches the executable for any 16/24/32-byte window that is a
plausible key and tests it against the fingerprint under each mode.

The template *bytes* are build-specific and are not committed here: pass them to
``TemplateOracle`` (or ``sweep_*``) when you have a survey. For "is this a valid
archive" prefer the structural checks in :mod:`gta6.rpf9.validate`, which do not
depend on any particular byte values.
"""

from __future__ import annotations

import hashlib
import sys
from collections.abc import Iterator
from dataclasses import dataclass, replace
from pathlib import Path

KEY_LENGTHS = (16, 24, 32)

# The known-plaintext region of the TOC blob: a fixed 48-byte window at a constant
# offset. Its *bytes* are build-specific and are NOT committed here -- supply them
# to TemplateOracle (see the module docstring). These are the structural offsets.
TEMPLATE_OFFSET = 16
CLEARTEXT_TEMPLATE_END = 64
TEMPLATE_SIZE = CLEARTEXT_TEMPLATE_END - TEMPLATE_OFFSET
ZERO_BLOCK = bytes(16)


def _cipher(key: bytes, mode):  # noqa: ANN202 - cryptography types are not stubbed here
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

    return Cipher(algorithms.AES(key), mode)


def ecb_encrypt_block(block: bytes, key: bytes) -> bytes:
    """Encrypt one 16-byte block; key length selects AES-128/192/256."""
    if len(block) != 16:
        msg = f"block must be 16 bytes, got {len(block)}"
        raise ValueError(msg)
    if len(key) not in KEY_LENGTHS:
        msg = f"AES key must be 16/24/32 bytes, got {len(key)}"
        raise ValueError(msg)
    from cryptography.hazmat.primitives.ciphers import modes

    ctx = _cipher(key, modes.ECB()).encryptor()
    return ctx.update(block) + ctx.finalize()


def ecb_decrypt(data: bytes, key: bytes) -> bytes:
    """ECB-decrypt ``data``; a trailing partial block is passed through."""
    from cryptography.hazmat.primitives.ciphers import modes

    full = len(data) - (len(data) % 16)
    if full == 0:
        return data
    ctx = _cipher(key, modes.ECB()).decryptor()
    return ctx.update(data[:full]) + ctx.finalize() + data[full:]


def ctr_decrypt(data: bytes, key: bytes, nonce: bytes) -> bytes:
    """CTR-decrypt with a 16-byte initial counter block."""
    from cryptography.hazmat.primitives.ciphers import modes

    ctx = _cipher(key, modes.CTR(nonce)).decryptor()
    return ctx.update(data) + ctx.finalize()


def cfb_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    """CFB-128-decrypt with a 16-byte IV."""
    from cryptography.hazmat.primitives.ciphers import modes

    ctx = _cipher(key, modes.CFB(iv)).decryptor()
    return ctx.update(data) + ctx.finalize()


def read_toc_blob(path: Path, base: int = 0, *, limit: int = 1 << 20) -> bytes:
    """Read the raw (encrypted) TOC+names blob of one archive base."""
    import struct

    with path.open("rb") as fh:
        fh.seek(base)
        magic, toc_size, names_size = struct.unpack("<III", fh.read(12))
        if magic != 0x52504639:
            msg = f"{path}@{base}: not an RPF9 header"
            raise ValueError(msg)
        fh.seek(base + 32)
        return fh.read(min(toc_size + names_size, limit))


def toc_template(toc: bytes) -> bytes:
    """The 48-byte global region as stored in the file."""
    return toc[TEMPLATE_OFFSET:CLEARTEXT_TEMPLATE_END]


@dataclass(frozen=True, slots=True)
class KeyHit:
    """A candidate key that reproduces the global template under some mode/nonce."""

    key: bytes
    offset: int
    scheme: str
    nonce: bytes | None = None

    @property
    def key_hex(self) -> str:
        return self.key.hex()

    def as_dict(self) -> dict[str, object]:
        return {
            "key_hex": self.key_hex,
            "exe_offset": self.offset,
            "key_len": len(self.key),
            "scheme": self.scheme,
            "nonce_hex": self.nonce.hex() if self.nonce else None,
        }


class TemplateOracle:
    """Tests candidate keys against the 48-byte region shared by every archive."""

    def __init__(self, template: bytes) -> None:
        if len(template) != TEMPLATE_SIZE:
            msg = f"template must be {TEMPLATE_SIZE} bytes, got {len(template)}"
            raise ValueError(msg)
        self.template = template
        self.blocks = [template[i : i + 16] for i in range(0, TEMPLATE_SIZE, 16)]
        self.distinct = len(set(self.blocks)) == 3

    def test_ecb(self, key: bytes) -> KeyHit | None:
        """ECB of a zero run gives three *equal* blocks, so this can never match the
        global template. Kept because it is the model the old extractor assumed,
        and its failure is the evidence against it."""
        if len(key) not in KEY_LENGTHS:
            return None
        if ecb_encrypt_block(ZERO_BLOCK, key) == self.blocks[0]:
            return KeyHit(key=key, offset=-1, scheme="aes-ecb-zero")
        return None

    def test_ctr(self, key: bytes, nonce: bytes) -> KeyHit | None:
        """CTR: the keystream starting at ``nonce`` must equal the template."""
        if len(key) not in KEY_LENGTHS or len(nonce) != 16:
            return None
        if ecb_encrypt_block(nonce, key) != self.blocks[0]:
            return None
        if ctr_decrypt(self.template, key, nonce) == bytes(TEMPLATE_SIZE):
            return KeyHit(key=key, offset=-1, scheme="aes-ctr", nonce=nonce)
        return None

    def test_cfb(self, key: bytes, iv: bytes) -> KeyHit | None:
        """CFB-128: same test shape as CTR, different chaining."""
        if len(key) not in KEY_LENGTHS or len(iv) != 16:
            return None
        if ecb_encrypt_block(iv, key) != self.blocks[0]:
            return None
        if cfb_decrypt(self.template, key, iv) == bytes(TEMPLATE_SIZE):
            return KeyHit(key=key, offset=-1, scheme="aes-cfb", nonce=iv)
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
    start: int = 0,
    end: int | None = None,
    chunk: int = 1 << 20,
    step: int = 1,
    key_lengths: tuple[int, ...] = KEY_LENGTHS,
    filter_plausible: bool = True,
) -> Iterator[tuple[int, bytes]]:
    """Stream (offset, bytes) windows from a large executable without loading it.

    Reads in chunks so a 120 MB exe costs a few MB of RAM. With ``step=1`` every
    byte offset is visited, which a real hunt needs: a key inside a struct is
    not guaranteed to be aligned.
    """
    window = max(key_lengths)
    stop = path.stat().st_size if end is None else min(end, path.stat().st_size)
    seen: set[bytes] = set()
    carry = b""
    pos = start
    with path.open("rb") as fh:
        fh.seek(start)
        while pos < stop:
            raw = fh.read(min(chunk, stop - pos))
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
                    if filter_plausible and not _plausible_key(key):
                        continue
                    yield base + off, key
            carry = buf[-(window - 1) :] if window > 1 else b""
            pos += len(raw)


def sweep_exe(
    exe: Path,
    *,
    template: bytes,
    nonces: list[tuple[str, bytes]] | None = None,
    key_lengths: tuple[int, ...] = (32, 24, 16),
    start: int = 0,
    end: int | None = None,
    stop_after: int = 8,
    progress_every: int = 0,
    verbose: bool = False,
) -> list[KeyHit]:
    """Search ``exe`` for a key that turns a known plaintext into the template.

    Tries ECB-of-zeros (the old hypothesis) and CTR/CFB at each supplied nonce.
    Returns every hit; an empty list means the key is not a raw constant in the
    exe and the derivation has to be found instead.
    """
    oracle = TemplateOracle(template)
    nonces = nonces if nonces is not None else [("zero", bytes(16))]
    hits: list[KeyHit] = []
    tried = 0
    for offset, key in key_candidates_from_pe(
        exe, start=start, end=end, key_lengths=key_lengths
    ):
        tried += 1
        hit = oracle.test_ecb(key)
        if hit is not None:
            hits.append(replace(hit, offset=offset))
        for label, nonce in nonces:
            for tester, scheme in ((oracle.test_ctr, "aes-ctr"), (oracle.test_cfb, "aes-cfb")):
                hit = tester(key, nonce)
                if hit is not None:
                    hits.append(replace(hit, offset=offset, scheme=f"{scheme}:{label}"))
        if progress_every and tried % progress_every == 0 and verbose:
            print(f"  {offset:#x} {tried:,} tried, {len(hits)} hits", file=sys.stderr)
        if stop_after and len(hits) >= stop_after:
            break
    if verbose:
        print(f"# tried {tried:,} candidates, {len(hits)} hits", file=sys.stderr)
    return hits


def scan_shard(args: tuple) -> dict[str, object]:
    """Worker entry point: sweep one byte range of the exe. Picklable for ProcessPool."""
    exe, start, end, template, nonces, key_lengths = args
    hits, cursor = sweep_range(
        Path(exe),
        start=start,
        end=end,
        template=template,
        nonces=nonces,
        key_lengths=key_lengths,
        stop_after=0,
    )
    return {"start": start, "end": end, "cursor": cursor, "hits": [h.as_dict() for h in hits]}


def sweep_range(
    exe: Path,
    *,
    start: int,
    end: int,
    template: bytes,
    nonces: list[tuple[str, bytes]] | None = None,
    key_lengths: tuple[int, ...] = (32, 24, 16),
    stop_after: int = 0,
) -> tuple[list[KeyHit], int]:
    """Sweep one byte range. Returns (hits, next_offset) so a caller can resume."""
    oracle = TemplateOracle(template)
    nonces = nonces if nonces is not None else [("zero", bytes(16))]
    hits: list[KeyHit] = []
    last = start
    for offset, key in key_candidates_from_pe(
        exe, start=start, end=end, key_lengths=key_lengths
    ):
        last = offset
        hit = oracle.test_ecb(key)
        if hit is not None:
            hits.append(replace(hit, offset=offset))
        for label, nonce in nonces:
            for tester, scheme in ((oracle.test_ctr, "aes-ctr"), (oracle.test_cfb, "aes-cfb")):
                hit = tester(key, nonce)
                if hit is not None:
                    hits.append(replace(hit, offset=offset, scheme=f"{scheme}:{label}"))
        if stop_after and len(hits) >= stop_after:
            break
    return hits, last + 1


def sweep_file(
    exe: Path,
    *,
    template: bytes,
    nonces: list[tuple[str, bytes]] | None = None,
    key_lengths: tuple[int, ...] = (32, 24, 16),
    workers: int = 1,
    shard: int = 8 << 20,
    stop_after: int = 0,
    progress_every: int = 0,
    verbose: bool = False,
) -> list[KeyHit]:
    """Sweep a whole executable, optionally across processes.

    The sweep is ~12 M candidate windows for a 120 MB exe, so ``workers`` splits
    it into byte-range shards. Shards tile the file exactly, so results are the
    same as a single sequential pass.
    """
    size = exe.stat().st_size
    bounds = list(range(0, size, shard)) + [size]
    jobs = [
        (str(exe), bounds[i], bounds[i + 1], template, nonces, key_lengths)
        for i in range(len(bounds) - 1)
    ]
    hits: list[KeyHit] = []
    if workers > 1:
        from concurrent.futures import ProcessPoolExecutor

        with ProcessPoolExecutor(max_workers=workers) as pool:
            for i, res in enumerate(pool.map(scan_shard, jobs), start=1):
                hits.extend(KeyHit(**_rehydrate(h)) for h in res["hits"])  # type: ignore[arg-type]
                if verbose:
                    print(
                        f"  shard {i}/{len(jobs)} done ({res['start']:#x}-{res['end']:#x}), "
                        f"{len(hits)} hits so far",
                        file=sys.stderr,
                    )
                if stop_after and len(hits) >= stop_after:
                    break
    else:
        for i, job in enumerate(jobs, start=1):
            shard_hits, _cursor = sweep_range(
                exe,
                start=job[1],
                end=job[2],
                template=template,
                nonces=nonces,
                key_lengths=key_lengths,
                stop_after=stop_after,
            )
            hits.extend(shard_hits)
            if verbose:
                print(f"  shard {i}/{len(jobs)} done, {len(hits)} hits so far", file=sys.stderr)
            if stop_after and len(hits) >= stop_after:
                break
    del progress_every
    return hits


def _rehydrate(d: dict[str, object]) -> dict[str, object]:
    key_hex = d["key_hex"]
    assert isinstance(key_hex, str)
    nonce_hex = d.get("nonce_hex")
    return {
        "key": bytes.fromhex(key_hex),
        "offset": int(d["exe_offset"]),  # type: ignore[arg-type]
        "scheme": str(d["scheme"]),
        "nonce": bytes.fromhex(nonce_hex) if isinstance(nonce_hex, str) else None,
    }


def standard_nonces(header: bytes, archive_path: Path | None = None) -> list[tuple[str, bytes]]:
    """Nonce candidates from an archive header and its name, for the per-archive model."""
    import struct

    out: list[tuple[str, bytes]] = [("zero", bytes(16))]
    if len(header) >= 32:
        fields = struct.unpack("<8I", header)
        id_bytes = struct.pack("<II", fields[4], fields[5])
        out.append(("ids", id_bytes + bytes(8)))
        out.append(("ids_tail", bytes(8) + id_bytes))
        out.append(("hdr4_20", header[4:20]))
        out.append(("hdr16_32", header[16:32]))
    if archive_path is not None:
        stem = archive_path.stem.encode("ascii")
        out.append(("stem_pad", (stem + bytes(16))[:16]))
        out.append(("stem_md5", hashlib.md5(stem).digest()))
    return out
