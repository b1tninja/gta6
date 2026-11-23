from __future__ import annotations

import zlib
from dataclasses import dataclass, field
from pathlib import Path

from gta6.rpf9.crypto import decrypt_toc_and_names
from gta6.rpf9.entries import EntryKind, names_plausibility, parse_entry, read_name
from gta6.rpf9.format import (
    BLOCK_SIZE,
    ENTRY_SIZE,
    Rpf9Header,
    find_rpf9_bases,
    parse_header,
)
from gta6.rpf9.keys import load_aes_key

DEFAULT_NAME_PLAUSIBILITY = 0.85


@dataclass
class Rpf9Archive:
    header: Rpf9Header
    toc_plain: bytes | None = None
    names_plain: bytes | None = None
    decryption: str = "unknown"
    entries: list = field(default_factory=list)

    @classmethod
    def open(cls, path: Path, *, base_offset: int | None = None) -> Rpf9Archive:
        path = path.resolve()
        with path.open("rb") as fh:
            probe = fh.read(min(path.stat().st_size, 4 * 1024 * 1024))
        bases = find_rpf9_bases(probe)
        if not bases:
            msg = f"{path}: no RPF9 header found"
            raise ValueError(msg)
        chosen = base_offset if base_offset is not None else bases[0]
        header = parse_header(path, chosen)
        arc = cls(header=header)
        arc._load_tables()
        return arc

    def _load_tables(self) -> None:
        start = self.header.toc_offset
        end = self.header.data_offset
        with self.header.path.open("rb") as fh:
            fh.seek(start)
            encrypted = fh.read(end - start)
        if not self.header.is_encrypted_toc():
            self.toc_plain = encrypted[: self.header.toc_byte_size]
            self.names_plain = encrypted[self.header.toc_byte_size :]
            self.decryption = "plaintext"
        else:
            key = load_aes_key()
            if key is None:
                self.toc_plain = encrypted[: self.header.toc_byte_size]
                self.names_plain = encrypted[self.header.toc_byte_size :]
                self.decryption = "encrypted_no_key"
                return
            plain = decrypt_toc_and_names(encrypted, key)
            self.toc_plain = plain[: self.header.toc_byte_size]
            self.names_plain = plain[self.header.toc_byte_size :]
            if names_plausibility(self.names_plain) >= DEFAULT_NAME_PLAUSIBILITY:
                self.decryption = "aes256_ecb"
            else:
                self.decryption = "wrong_key"

        if self.toc_plain is None:
            return
        for i in range(self.header.entry_count):
            off = i * ENTRY_SIZE
            self.entries.append(parse_entry(i, self.toc_plain, off))

    def toc_readable(self) -> bool:
        return self.decryption in {"plaintext", "aes256_ecb"}

    def info(self) -> dict[str, object]:
        h = self.header
        return {
            "path": str(h.path),
            "base_offset": h.base_offset,
            "toc_byte_size": h.toc_byte_size,
            "names_byte_size": h.names_byte_size,
            "entry_count": h.entry_count,
            "encryption": h.encryption,
            "encryption_hex": f"{h.encryption:#x}",
            "archive_id": [f"{h.archive_id[0]:#x}", f"{h.archive_id[1]:#x}"],
            "platform_tag": h.platform_tag,
            "platform_flags": h.platform_flags,
            "decryption": self.decryption,
            "toc_readable": self.toc_readable(),
            "names_plausibility": (
                names_plausibility(self.names_plain) if self.names_plain else 0.0
            ),
            "data_offset": h.data_offset,
        }

    def list_paths(self) -> list[str]:
        if not self.toc_readable() or self.names_plain is None:
            return []
        paths: list[str] = []
        self._walk(0, "", paths)
        return paths

    def _walk(self, entry_index: int, prefix: str, out: list[str]) -> None:
        if entry_index < 0 or entry_index >= len(self.entries):
            return
        entry = self.entries[entry_index]
        if entry.kind == EntryKind.DIRECTORY:
            name = read_name(self.names_plain or b"", entry.name_offset)
            sub = f"{prefix}/{name}" if name else prefix or ""
            first = entry.entries_index
            count = entry.entries_count
            for child in range(first, first + count):
                self._walk(child, sub, out)
            return
        name = read_name(self.names_plain or b"", entry.name_offset)
        rel = f"{prefix}/{name}".lstrip("/") if name else f"entry_{entry_index:04d}"
        out.append(rel)

    def _read_file_payload(self, blob: bytes, entry_index: int) -> bytes | None:
        entry = self.entries[entry_index]
        if entry.kind == EntryKind.DIRECTORY:
            return None
        offset = self.header.base_offset + entry.file_offset_blocks * BLOCK_SIZE
        size = entry.file_size or entry.file_uncompressed_size
        if size <= 0:
            return b""
        return blob[offset : offset + size]

    @staticmethod
    def _maybe_inflate(data: bytes, compressed: bool) -> bytes:
        if not compressed or not data:
            return data
        try:
            return zlib.decompress(data, wbits=-zlib.MAX_WBITS)
        except zlib.error:
            return data

    def extract_all(
        self,
        output_dir: Path,
        blob: bytes | None = None,
        *,
        decompress: bool = True,
    ) -> dict[str, int]:
        if not self.toc_readable():
            msg = f"TOC not readable (decryption={self.decryption}); set GTA6_AES_KEY_HEX"
            raise RuntimeError(msg)
        output_dir.mkdir(parents=True, exist_ok=True)
        with self.header.path.open("rb") as fh:
            blob = fh.read()
        stats = {"files": 0, "bytes": 0, "skipped_dirs": 0}
        for i, entry in enumerate(self.entries):
            if entry.kind == EntryKind.DIRECTORY:
                stats["skipped_dirs"] += 1
                continue
            name = read_name(self.names_plain or b"", entry.name_offset) or f"entry_{i:04d}"
            rel = name
            payload = self._read_file_payload(blob, i)
            if payload is None:
                continue
            compressed = entry.file_size > 0
            payload = self._maybe_inflate(payload, decompress and compressed)
            dest = output_dir / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(payload)
            stats["files"] += 1
            stats["bytes"] += len(payload)
        return stats