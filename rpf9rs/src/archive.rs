//! High-level RPF9 archive reader: open, decrypt-if-possible, list, extract.
//!
//! [`Archive`] locates the first base in a file, reads its header, and tries to make
//! the TOC/names readable. The decryption state ([`Archive::decryption`]) is one of:
//!
//! * `plaintext`        - header says the TOC is cleartext (encryption 0 / "OPEN");
//! * `encrypted_no_key` - TOC is encrypted and no AES key is configured;
//! * `aes256_ecb`       - decrypted and the names blob looks like ASCII (key accepted);
//! * `wrong_key`        - decrypted but the names blob is not plausible ASCII.
//!
//! The file is accessed through a read-only memory map ([`memmap2::Mmap`]) rather than
//! being read into a buffer. Retail archives can be tens of gigabytes, so this keeps
//! memory bounded: the OS pages in only the regions actually touched (the small header
//! and TOC blob, then individual payloads on demand), and the map is shared cheaply
//! across rayon workers via `Arc`. File payloads are addressed as
//! `base + start_block * 512`; the data region is cleartext, so extraction only needs a
//! readable TOC to know *where* files live, then slices + raw-inflates each payload.
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;

use flate2::bufread::DeflateDecoder;
use memmap2::Mmap;

use crate::crypto::{DEFAULT_NAME_PLAUSIBILITY, decrypt_toc_and_names};
use crate::entries::{Entry, EntryKind, names_plausibility, parse_entries, read_name};
use crate::format::{BLOCK_SIZE, Header, Rpf9Error, find_rpf9_bases, parse_header};

/// How readable the TOC currently is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decryption {
    Plaintext,
    EncryptedNoKey,
    Aes256Ecb,
    WrongKey,
    Unknown,
}

impl Decryption {
    pub fn as_str(&self) -> &'static str {
        match self {
            Decryption::Plaintext => "plaintext",
            Decryption::EncryptedNoKey => "encrypted_no_key",
            Decryption::Aes256Ecb => "aes256_ecb",
            Decryption::WrongKey => "wrong_key",
            Decryption::Unknown => "unknown",
        }
    }
}

/// Cap on the prefix scanned for the `RPF9` magic (a file may hold several bases).
const MAGIC_PROBE_BYTES: usize = 4 * 1024 * 1024;

/// An opened RPF9 base with its header, (maybe) decrypted tables and entries.
///
/// The file is held as a shared read-only memory map; nothing is buffered in RAM beyond
/// the small header/TOC data and whatever payload a caller asks for.
pub struct Archive {
    pub path: std::path::PathBuf,
    pub header: Header,
    pub toc_plain: Option<Vec<u8>>,
    pub names_plain: Option<Vec<u8>>,
    pub decryption: Decryption,
    pub entries: Vec<Entry>,
    pub file_size: u64,
    map: Arc<Mmap>,
}

impl Archive {
    /// Open the first base (or `base_offset`) and attempt to read its tables.
    ///
    /// `key` is the optional 32-byte AES key; when `None` and the TOC is encrypted, the
    /// archive is left in [`Decryption::EncryptedNoKey`]. The file is memory-mapped, so
    /// opening a multi-gigabyte archive is cheap.
    pub fn open(path: &Path, base_offset: Option<usize>, key: Option<&[u8]>) -> Result<Self, Rpf9Error> {
        let path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
        let file = File::open(&path)?;
        // SAFETY: the file is mapped read-only and we never mutate it while mapped.
        // (A concurrent external truncation would be UB; acceptable for read-only
        // analysis of installed game files.)
        let map = unsafe { Mmap::map(&file) }?;
        let file_size = map.len() as u64;
        // Scan a bounded prefix for the magic rather than the whole (huge) map.
        let probe_len = map.len().min(MAGIC_PROBE_BYTES);
        let bases = find_rpf9_bases(&map[..probe_len]);
        let base = match base_offset.or_else(|| bases.first().copied()) {
            Some(b) => b,
            None => {
                return Err(Rpf9Error::Format {
                    path: path.display().to_string(),
                    msg: "no RPF9 header found".to_string(),
                });
            }
        };
        let header = parse_header(&map, base, &path.display().to_string())?;
        let mut arc = Archive {
            path,
            header,
            toc_plain: None,
            names_plain: None,
            decryption: Decryption::Unknown,
            entries: Vec::new(),
            file_size,
            map: Arc::new(map),
        };
        arc.load_tables(key);
        Ok(arc)
    }

    /// Read the TOC||names blob (small) and set the decryption state; parse entries if readable.
    fn load_tables(&mut self, key: Option<&[u8]>) {
        let start = self.header.toc_offset() as usize;
        let end = (self.header.data_offset() as usize).min(self.map.len());
        let blob = &self.map[start..end];
        let toc_len = (self.header.toc_byte_size as usize).min(blob.len());

        if !self.header.is_encrypted_toc() {
            self.toc_plain = Some(blob[..toc_len].to_vec());
            self.names_plain = Some(blob[toc_len..].to_vec());
            self.decryption = Decryption::Plaintext;
        } else {
            match key {
                None => {
                    self.toc_plain = Some(blob[..toc_len].to_vec());
                    self.names_plain = Some(blob[toc_len..].to_vec());
                    self.decryption = Decryption::EncryptedNoKey;
                    return;
                }
                Some(k) => {
                    let plain = decrypt_toc_and_names(blob, k);
                    let toc = &plain[..toc_len.min(plain.len())];
                    let names = &plain[toc_len.min(plain.len())..];
                    self.decryption = if names_plausibility(names) >= DEFAULT_NAME_PLAUSIBILITY {
                        Decryption::Aes256Ecb
                    } else {
                        Decryption::WrongKey
                    };
                    self.toc_plain = Some(toc.to_vec());
                    self.names_plain = Some(names.to_vec());
                }
            }
        }

        if let Some(toc) = &self.toc_plain {
            self.entries = parse_entries(toc, self.header.entry_count());
        }
    }

    pub fn toc_readable(&self) -> bool {
        matches!(self.decryption, Decryption::Plaintext | Decryption::Aes256Ecb)
    }

    /// Raw-inflate (wbits = -15); returns `data` unchanged if it is not deflate.
    pub fn maybe_inflate(data: &[u8]) -> Vec<u8> {
        if data.is_empty() {
            return data.to_vec();
        }
        let mut dec = DeflateDecoder::new(data);
        let mut out = Vec::new();
        match dec.read_to_end(&mut out) {
            Ok(_) => out,
            Err(_) => data.to_vec(),
        }
    }

    /// Borrow a file's bytes from the data region (cleartext; addressed by block).
    /// Returns `None` for directories or out-of-range offsets.
    pub fn payload_slice(&self, entry: &Entry) -> Option<&[u8]> {
        if entry.kind == EntryKind::Directory {
            return None;
        }
        let offset = self.header.base_offset as usize + (entry.file_offset_blocks as usize) * BLOCK_SIZE;
        let size = if entry.file_size > 0 {
            entry.file_size
        } else {
            entry.file_uncompressed_size
        } as usize;
        if size == 0 {
            return Some(&[]);
        }
        let end = offset.saturating_add(size).min(self.map.len());
        if offset >= self.map.len() {
            return Some(&[]);
        }
        Some(&self.map[offset..end])
    }

    /// Write every file entry under `output_dir`; needs a readable TOC.
    ///
    /// Uses rayon to inflate + write entries in parallel; each worker borrows the shared
    /// map (no per-thread file reads). Returns `(files, bytes, skipped_dirs)`.
    pub fn extract_all(&self, output_dir: &Path, decompress: bool) -> Result<(usize, usize, usize), Rpf9Error> {
        if !self.toc_readable() {
            return Err(Rpf9Error::Format {
                path: self.path.display().to_string(),
                msg: format!("TOC not readable (decryption={})", self.decryption.as_str()),
            });
        }
        std::fs::create_dir_all(output_dir)?;
        use rayon::prelude::*;
        let results: Vec<Option<(String, Vec<u8>)>> = self
            .entries
            .par_iter()
            .map(|entry| {
                if entry.kind == EntryKind::Directory {
                    return None;
                }
                let name = read_name(self.names_plain.as_deref().unwrap_or(&[]), entry.name_offset as usize);
                let name = if name.is_empty() {
                    format!("entry_{:04}", entry.index)
                } else {
                    name
                };
                let payload = self.payload_slice(entry)?;
                let payload = if decompress && entry.file_size > 0 {
                    Archive::maybe_inflate(payload)
                } else {
                    payload.to_vec()
                };
                Some((name, payload))
            })
            .collect();

        let mut files = 0;
        let mut total = 0usize;
        let mut skipped_dirs = 0;
        for r in results.into_iter() {
            match r {
                None => skipped_dirs += 1,
                Some((name, payload)) => {
                    let dest = output_dir.join(&name);
                    if let Some(parent) = dest.parent() {
                        std::fs::create_dir_all(parent)?;
                    }
                    std::fs::write(&dest, &payload)?;
                    files += 1;
                    total += payload.len();
                }
            }
        }
        Ok((files, total, skipped_dirs))
    }
}
