from __future__ import annotations

import struct
import subprocess
from dataclasses import dataclass
from pathlib import Path

RPF_MAGIC = {
    0x52504630: "RPF0",
    0x52504632: "RPF2",
    0x52504633: "RPF3",
    0x52504634: "RPF4",
    0x52504636: "RPF6",
    0x52504637: "RPF7",
    0x52504638: "RPF8",
    0x52504639: "RPF9",
}


@dataclass(frozen=True, slots=True)
class RpfHeader:
    path: Path
    magic: int
    version: str
    table_size: int
    entry_count: int


def read_rpf_header(path: Path) -> RpfHeader:
    with path.open("rb") as f:
        magic, table_size, entry_count = struct.unpack("<III", f.read(12))
    version = RPF_MAGIC.get(magic, f"unknown (0x{magic:08X})")
    return RpfHeader(
        path=path,
        magic=magic,
        version=version,
        table_size=table_size,
        entry_count=entry_count,
    )


def rpf_cli_list(rpf_cli: Path, archive: Path, *, pattern: str | None = None) -> str:
    cmd = [str(rpf_cli), "list", str(archive)]
    if pattern:
        cmd.append(pattern)
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    out = (result.stdout or "") + (result.stderr or "")
    if result.returncode != 0 and "Not a valid RPF7" in out:
        hdr = read_rpf_header(archive)
        out = (
            f"{out.strip()}\n"
            f"Detected on disk: {hdr.version} "
            f"(entries={hdr.entry_count}, toc_bytes={hdr.table_size}). "
            "Bundled rpf-cli only supports RPF7; GTA VI Xbox builds use RPF9."
        )
    return out.strip()


def iter_rpf_files(game_root: Path) -> list[Path]:
    return sorted(game_root.rglob("*.rpf"))


def script_archives(game_root: Path) -> list[Path]:
    return [p for p in iter_rpf_files(game_root) if "script" in p.name.lower()]