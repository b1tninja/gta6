//! Parsing the RPF9 TOC entry table and the name blob.
//!
//! Each TOC entry is four little-endian dwords (16 bytes). The layout of `dword1`
//! selects the entry kind:
//!
//! * `dword1 == 0x7FFFFF00` -> **directory**: `dword0` is the name offset,
//!   `dword2`/`dword3` are the first child index and child count.
//! * `dword1` high bit clear -> **binary file**: the two dwords form a 64-bit packed
//!   field — name offset (16 bits), file size (24 bits) and start block (24 bits).
//! * `dword1` high bit set -> **resource**: a different packing of the same fields.
//!
//! The name blob is a NUL-separated ASCII pool; entries reference it by byte offset.
//! This is a clean-room reconstruction from observed bytes, so the resource packing is
//! best-effort and marked [`EntryKind::Resource`] rather than claimed exact.

use crate::format::DIR_MARKER;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    Directory,
    Binary,
    Resource,
    Unknown,
}

/// One decoded TOC entry, normalised across the three `dword1` layouts.
#[derive(Debug, Clone, Copy)]
pub struct Entry {
    pub index: usize,
    pub kind: EntryKind,
    pub name_offset: u32,
    pub file_offset_blocks: u32,
    pub file_size: u32,
    pub file_uncompressed_size: u32,
    pub encryption_type: u32,
    pub entries_index: u32,
    pub entries_count: u32,
}

fn dwords(raw: &[u8], offset: usize) -> [u32; 4] {
    let mut out = [0u32; 4];
    for (i, slot) in out.iter_mut().enumerate() {
        let o = offset + i * 4;
        *slot = u32::from_le_bytes([raw[o], raw[o + 1], raw[o + 2], raw[o + 3]]);
    }
    out
}

/// Decode one 16-byte entry at `offset` in `raw` (the TOC blob).
pub fn parse_entry(index: usize, raw: &[u8], offset: usize) -> Entry {
    let [d0, d1, d2, d3] = dwords(raw, offset);
    if d1 == DIR_MARKER {
        return Entry {
            index,
            kind: EntryKind::Directory,
            name_offset: d0,
            file_offset_blocks: 0,
            file_size: 0,
            file_uncompressed_size: 0,
            encryption_type: 0,
            entries_index: d2,
            entries_count: d3,
        };
    }
    if d1 & 0x8000_0000 == 0 {
        // Binary file: d0|d1 is one 64-bit field -> name(16) size(24) block(24).
        let packed = (d0 as u64) | ((d1 as u64) << 32);
        return Entry {
            index,
            kind: EntryKind::Binary,
            name_offset: (packed & 0xFFFF) as u32,
            file_size: ((packed >> 16) & 0xFF_FFFF) as u32,
            file_offset_blocks: ((packed >> 40) & 0xFF_FFFF) as u32,
            file_uncompressed_size: d2,
            encryption_type: d3,
            entries_index: 0,
            entries_count: 0,
        };
    }
    // Resource: high bit set, a different packing of the same fields.
    Entry {
        index,
        kind: EntryKind::Resource,
        name_offset: d0 & 0xFFFF,
        file_offset_blocks: (d1 >> 8) & 0xFF_FFFF,
        file_size: d1 & 0xFF_FFFF,
        file_uncompressed_size: d2,
        encryption_type: d3,
        entries_index: 0,
        entries_count: 0,
    }
}

/// Parse every entry in a TOC blob of `entry_count` entries.
pub fn parse_entries(toc: &[u8], entry_count: usize) -> Vec<Entry> {
    (0..entry_count)
        .map(|i| parse_entry(i, toc, i * crate::format::ENTRY_SIZE))
        .collect()
}

/// Read the NUL-terminated ASCII name at `offset`; `""` if not printable ASCII.
pub fn read_name(names: &[u8], offset: usize) -> String {
    if offset >= names.len() {
        return String::new();
    }
    let end = names[offset..]
        .iter()
        .position(|&b| b == 0)
        .map(|p| offset + p)
        .unwrap_or(names.len());
    let chunk = &names[offset..end];
    if chunk.is_empty() || chunk.iter().any(|&b| b < 0x20 || b > 0x7E) {
        return String::new();
    }
    String::from_utf8_lossy(chunk).into_owned()
}

/// Fraction of bytes that are NUL or printable ASCII — a wrong-key detector.
pub fn names_plausibility(names: &[u8]) -> f64 {
    if names.is_empty() || names.iter().all(|&b| b == 0) {
        return 0.0;
    }
    let useful = names
        .iter()
        .filter(|&&b| b == 0 || (0x20..=0x7E).contains(&b))
        .count();
    useful as f64 / names.len() as f64
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directory_entry_decodes() {
        // dword1 == DIR_MARKER marks a directory; d2/d3 are child index/count.
        let mut raw = Vec::new();
        raw.extend_from_slice(&7u32.to_le_bytes()); // name offset
        raw.extend_from_slice(&DIR_MARKER.to_le_bytes());
        raw.extend_from_slice(&3u32.to_le_bytes()); // first child
        raw.extend_from_slice(&5u32.to_le_bytes()); // child count
        let e = parse_entry(0, &raw, 0);
        assert_eq!(e.kind, EntryKind::Directory);
        assert_eq!(e.name_offset, 7);
        assert_eq!(e.entries_index, 3);
        assert_eq!(e.entries_count, 5);
    }

    #[test]
    fn binary_entry_unpacks_packed_fields() {
        // name(16) size(24) block(24) packed into d0|d1, high bit of d1 clear.
        let name = 0x1234u64;
        let size = 0xABCDEFu64;
        let block = 0x001234u64;
        let packed = name | (size << 16) | (block << 40);
        let d0 = (packed & 0xFFFF_FFFF) as u32;
        let d1 = ((packed >> 32) & 0xFFFF_FFFF) as u32;
        let mut raw = Vec::new();
        raw.extend_from_slice(&d0.to_le_bytes());
        raw.extend_from_slice(&d1.to_le_bytes());
        raw.extend_from_slice(&0u32.to_le_bytes());
        raw.extend_from_slice(&0u32.to_le_bytes());
        let e = parse_entry(0, &raw, 0);
        assert_eq!(e.kind, EntryKind::Binary);
        assert_eq!(e.name_offset as u64, name);
        assert_eq!(e.file_size as u64, size);
        assert_eq!(e.file_offset_blocks as u64, block);
    }

    #[test]
    fn read_name_rejects_non_ascii() {
        assert_eq!(read_name(b"hi\x00there\x00", 0), "hi");
        assert_eq!(read_name(&[0xff, 0x00], 0), "");
    }

    #[test]
    fn plausibility_detects_ascii() {
        assert!(names_plausibility(b"models\x00vehicles\x00") > 0.9);
        assert!(names_plausibility(&[0x01, 0x02, 0x03, 0x04]) < 0.5);
    }
}
