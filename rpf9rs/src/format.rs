//! RPF9 container framing: the 32-byte header and how the regions are laid out.
//!
//! A single `.rpf` file may hold several concatenated RPF9 archives ("bases"), each
//! located by scanning for the `RPF9` magic. Each base is:
//!
//! ```text
//! header (32 B)   magic + sizes + flags
//! TOC || names    (encrypted on retail builds)
//! data region     (cleartext, block-aligned raw-deflate streams)
//! ```
//!
//! The header is eight little-endian dwords. Region offsets are derived from the two
//! size fields (see [`Header`]); the data region always starts right after the names
//! blob. This module only frames the container — parsing the entry table lives in
//! [`crate::entries`] and decryption in [`crate::crypto`].

use thiserror::Error;

pub const RPF9_MAGIC: u32 = 0x5250_4639; // ASCII "RPF9", little-endian
pub const HEADER_SIZE: usize = 32; // eight little-endian dwords
pub const ENTRY_SIZE: usize = 16; // one TOC entry = four dwords (see entries::parse_entry)
pub const BLOCK_SIZE: usize = 512; // data region is addressed in 512-byte blocks
pub const DIR_MARKER: u32 = 0x7FFF_FF00; // dword1 sentinel marking a directory entry
pub const PAGE_SIZE: usize = 4096; // on-disk alignment granularity

/// Errors surfaced while framing or reading an archive.
#[derive(Debug, Error)]
pub enum Rpf9Error {
    #[error("{path}: {msg}")]
    Format { path: String, msg: String },
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// One parsed RPF9 base header, with derived region offsets.
#[derive(Debug, Clone, Copy)]
pub struct Header {
    pub base_offset: u64,
    pub magic: u32,
    pub toc_byte_size: u32,
    pub names_byte_size: u32,
    pub encryption: u32,
    pub archive_id: (u32, u32),
    pub platform_tag: u32,
    pub platform_flags: u32,
}

impl Header {
    pub fn entry_count(&self) -> usize {
        (self.toc_byte_size as usize) / ENTRY_SIZE
    }

    pub fn toc_offset(&self) -> u64 {
        self.base_offset + HEADER_SIZE as u64
    }

    pub fn names_offset(&self) -> u64 {
        self.toc_offset() + self.toc_byte_size as u64
    }

    pub fn data_offset(&self) -> u64 {
        self.names_offset() + self.names_byte_size as u64
    }

    /// Zero, or the ASCII "OPEN", means the TOC blob is stored cleartext.
    pub fn is_encrypted_toc(&self) -> bool {
        self.encryption != 0 && self.encryption != 0x4E45_504F
    }
}

/// Read eight little-endian dwords starting at `at` in `data`.
fn dwords(data: &[u8], at: usize) -> [u32; 8] {
    let mut out = [0u32; 8];
    for (i, slot) in out.iter_mut().enumerate() {
        let o = at + i * 4;
        *slot = u32::from_le_bytes([data[o], data[o + 1], data[o + 2], data[o + 3]]);
    }
    out
}

/// Offsets of every `RPF9` magic in `data` (a file may hold several bases).
pub fn find_rpf9_bases(data: &[u8]) -> Vec<usize> {
    let needle = RPF9_MAGIC.to_le_bytes();
    let mut bases = Vec::new();
    let mut start = 0;
    while let Some(rel) = find_slice(&data[start..], &needle) {
        bases.push(start + rel);
        start += rel + 4;
    }
    bases
}

/// Minimal byte-substring search (avoids pulling in a crate for one call).
fn find_slice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Parse and validate the 32-byte header at `base_offset` within `data`.
pub fn parse_header(data: &[u8], base_offset: usize, path: &str) -> Result<Header, Rpf9Error> {
    if base_offset + HEADER_SIZE > data.len() {
        return Err(Rpf9Error::Format {
            path: path.to_string(),
            msg: format!("truncated header at offset {base_offset}"),
        });
    }
    let f = dwords(data, base_offset);
    if f[0] != RPF9_MAGIC {
        return Err(Rpf9Error::Format {
            path: path.to_string(),
            msg: format!("expected RPF9 at {base_offset}, got {:#x}", f[0]),
        });
    }
    Ok(Header {
        base_offset: base_offset as u64,
        magic: f[0],
        toc_byte_size: f[1],
        names_byte_size: f[2],
        encryption: f[3],
        archive_id: (f[4], f[5]),
        platform_tag: f[6],
        platform_flags: f[7],
    })
}
