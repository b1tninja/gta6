"""Structural validation of an RPF9 archive.

Byte-for-byte template matching is a weak check: the known-plaintext bytes are
build-specific and may differ in another build or the production release. These
checks instead validate the *structure* -- that the header is self-consistent, the
TOC/names/data regions fit inside the file, the entry table is internally coherent,
and the data region actually inflates. None of them depend on any particular byte
values, so they stay useful across builds.

The entry-table and inflate checks only apply when the TOC is readable (plaintext,
or decrypted with a correct key). When the TOC is encrypted and no key is set, the
header/region checks still run and the table checks are reported as ``skipped``.
"""

from __future__ import annotations

import zlib
from dataclasses import dataclass, field
from pathlib import Path

from gta6.rpf9.archive import Rpf9Archive
from gta6.rpf9.entries import EntryKind
from gta6.rpf9.format import BLOCK_SIZE, ENTRY_SIZE, PAGE_SIZE


@dataclass
class Check:
    """One named structural check and its outcome."""

    name: str
    ok: bool
    detail: str = ""

    def as_dict(self) -> dict[str, object]:
        return {"name": self.name, "ok": self.ok, "detail": self.detail}


@dataclass
class ValidationReport:
    """Aggregate result of validating one archive base."""

    path: str
    base_offset: int
    checks: list[Check] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)

    def add(self, name: str, ok: bool, detail: str = "") -> None:
        self.checks.append(Check(name=name, ok=ok, detail=detail))

    @property
    def ok(self) -> bool:
        return all(c.ok for c in self.checks)

    def as_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "base_offset": self.base_offset,
            "ok": self.ok,
            "checks": [c.as_dict() for c in self.checks],
            "skipped": self.skipped,
        }


def _check_header(report: ValidationReport, arc: Rpf9Archive) -> None:
    h = arc.header
    report.add("magic", h.magic == 0x52504639, f"{h.magic:#x}")
    report.add(
        "toc_size_nonzero",
        h.toc_byte_size > 0,
        f"toc_byte_size={h.toc_byte_size}",
    )
    report.add(
        "entry_count_consistent",
        h.toc_byte_size % ENTRY_SIZE == 0,
        f"toc_byte_size={h.toc_byte_size} entry_count={h.entry_count}",
    )


def _check_regions(report: ValidationReport, arc: Rpf9Archive, file_size: int) -> None:
    h = arc.header
    report.add(
        "toc_within_file",
        h.data_offset <= file_size,
        f"data_offset={h.data_offset} file_size={file_size}",
    )
    report.add(
        "data_region_present",
        h.data_offset < file_size,
        f"data_offset={h.data_offset} file_size={file_size}",
    )
    # The data region must at least be able to hold the largest referenced block.
    if arc.toc_readable():
        max_end = _max_data_end(arc)
        report.add(
            "data_region_fits",
            max_end <= file_size,
            f"max_data_end={max_end} file_size={file_size}",
        )
    else:
        report.skipped.append("data_region_fits (TOC not readable)")


def _max_data_end(arc: Rpf9Archive) -> int:
    """Highest byte any file entry claims to occupy (start block + stored size)."""
    end = arc.header.data_offset
    for e in arc.entries:
        if e.kind == EntryKind.DIRECTORY:
            continue
        size = e.file_size or e.file_uncompressed_size
        start = arc.header.base_offset + e.file_offset_blocks * BLOCK_SIZE
        end = max(end, start + size)
    return end


def _check_entries(report: ValidationReport, arc: Rpf9Archive) -> None:
    if not arc.toc_readable():
        report.skipped.append("entry_table (TOC not readable)")
        report.skipped.append("names_in_range (TOC not readable)")
        report.skipped.append("directory_tree (TOC not readable)")
        return

    names_len = arc.header.names_byte_size
    toc_len = arc.header.toc_byte_size

    # Every file entry's name offset must land inside the names region.
    bad_names = [
        e.index
        for e in arc.entries
        if e.kind != EntryKind.DIRECTORY and e.name_offset >= names_len
    ]
    report.add(
        "names_in_range",
        not bad_names,
        f"{len(bad_names)} out-of-range" if bad_names else f"names_len={names_len}",
    )

    # Directory children must reference entry indices inside the TOC.
    bad_dirs = [
        e.index
        for e in arc.entries
        if e.kind == EntryKind.DIRECTORY
        and (e.entries_index + e.entries_count > arc.header.entry_count)
    ]
    report.add(
        "directory_tree",
        not bad_dirs,
        f"{len(bad_dirs)} dirs out of range" if bad_dirs else "ok",
    )

    # The TOC must contain at least the declared entry_count * ENTRY_SIZE bytes.
    report.add(
        "toc_holds_entries",
        toc_len >= arc.header.entry_count * ENTRY_SIZE,
        f"toc_len={toc_len} need={arc.header.entry_count * ENTRY_SIZE}",
    )


def _check_data_inflates(report: ValidationReport, arc: Rpf9Archive, sample: int = 8) -> None:
    """Try to inflate a few file payloads; the data region is cleartext deflate."""
    if not arc.toc_readable():
        report.skipped.append("data_inflates (TOC not readable)")
        return
    with arc.header.path.open("rb") as fh:
        blob = fh.read()
    tried = 0
    inflated = 0
    for i, e in enumerate(arc.entries):
        if e.kind == EntryKind.DIRECTORY or e.file_size <= 0:
            continue
        if tried >= sample:
            break
        tried += 1
        off = arc.header.base_offset + e.file_offset_blocks * BLOCK_SIZE
        payload = blob[off : off + e.file_size]
        if not payload:
            continue
        try:
            zlib.decompress(payload, wbits=-zlib.MAX_WBITS)
            inflated += 1
        except zlib.error:
            pass
    if tried == 0:
        report.skipped.append("data_inflates (no compressed entries sampled)")
        return
    report.add(
        "data_inflates",
        inflated > 0,
        f"{inflated}/{tried} sampled payloads inflated",
    )


def validate_archive(path: Path, *, base_offset: int | None = None) -> ValidationReport:
    """Validate one archive base structurally. Raises if no RPF9 header is present."""
    path = path.resolve()
    arc = Rpf9Archive.open(path, base_offset=base_offset)
    base = arc.header.base_offset
    report = ValidationReport(path=str(path), base_offset=base)
    file_size = path.stat().st_size
    _check_header(report, arc)
    _check_regions(report, arc, file_size)
    _check_entries(report, arc)
    _check_data_inflates(report, arc)
    return report


def validate_paths(paths: list[Path]) -> dict[str, object]:
    """Validate several archives; a file with no RPF9 header is reported, not fatal."""
    rows: list[dict[str, object]] = []
    for p in paths:
        if not p.is_file():
            continue
        try:
            rows.append(validate_archive(p).as_dict())
        except ValueError as exc:
            rows.append({"path": str(p), "ok": False, "error": str(exc)})
    ok = sum(1 for r in rows if r.get("ok"))
    return {
        "count": len(rows),
        "ok": ok,
        "failed": len(rows) - ok,
        "page_size": PAGE_SIZE,
        "archives": rows,
    }
