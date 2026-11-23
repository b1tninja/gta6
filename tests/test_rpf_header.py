from __future__ import annotations

import struct
import tempfile
from pathlib import Path

from gta6.rpf import read_rpf_header


def test_read_rpf_header_roundtrip() -> None:
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "sample.rpf"
        magic = 0x52504639
        table_size = 4096
        entry_count = 42
        path.write_bytes(struct.pack("<III", magic, table_size, entry_count))
        hdr = read_rpf_header(path)
        assert hdr.version == "RPF9"
        assert hdr.table_size == table_size
        assert hdr.entry_count == entry_count