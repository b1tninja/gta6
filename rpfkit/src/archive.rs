//! High-level RPF9 archive reader: open, decrypt-if-possible, list, extract.
//!
//! [`Archive`] locates the first base in a file, reads its header, and tries to make
//! the TOC/names readable. The decryption state ([`Archive::decryption`]) is one of:
//!
//! * `plaintext`        - header says the TOC is cleartext (encryption 0 / "OPEN");
//! * `encrypted_no_key` - TOC is encrypted and no key material is configured;
//! * `whitened_aes_cbc` - decrypted with the whitened AES-256-CBC cipher from a
//!   `key_ctx` blob and the names blob looks like ASCII (accepted);
//! * `aes256_ecb`       - decrypted with a raw key under the ECB hypothesis and the
//!   names blob looks like ASCII (key accepted);
//! * `wrong_key`        - decrypted but the names blob is not plausible ASCII.
//!
//! The whitened cipher is the model identified in the retail executable (§4 of
//! `docs/rpf9-research.md`); the ECB path is retained as the falsifiable RPF7-style
//! hypothesis. When a [`KeySource::KeyCtx`] blob is supplied it is tried first; if its
//! output is not plausible ASCII the reader falls back to the ECB path (when a raw key
//! is also present) so neither model is silently dropped.
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

use crate::crypto::{
    DEFAULT_NAME_PLAUSIBILITY, KEY_CTX_SIZE, WhitenedAesCbc, decrypt_toc_and_names,
};
use crate::entries::{Entry, EntryKind, names_plausibility, parse_entries, read_name};
use crate::format::{BLOCK_SIZE, Header, Rpf9Error, find_rpf9_bases, parse_header};

/// How readable the TOC currently is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decryption {
    Plaintext,
    EncryptedNoKey,
    WhitenedAesCbc,
    Aes256Ecb,
    WrongKey,
    Unknown,
}

impl Decryption {
    pub fn as_str(&self) -> &'static str {
        match self {
            Decryption::Plaintext => "plaintext",
            Decryption::EncryptedNoKey => "encrypted_no_key",
            Decryption::WhitenedAesCbc => "whitened_aes_cbc",
            Decryption::Aes256Ecb => "aes256_ecb",
            Decryption::WrongKey => "wrong_key",
            Decryption::Unknown => "unknown",
        }
    }
}

/// Key material used to make an encrypted TOC readable.
///
/// The two variants map to the two cipher models in [`crate::crypto`]:
///
/// * [`KeySource::KeyCtx`] — the precomputed key-context blob recovered from the
///   executable; drives the whitened AES-256-CBC cipher (the retail model). This is the
///   path that actually decrypts real archives.
/// * [`KeySource::Key`] — a raw 32-byte AES key; drives the ECB hypothesis.
///
/// [`KeySource::Both`] carries both so the reader can try the whitened cipher first and
/// fall back to ECB. Build one with [`KeySource::from_key`],
/// [`KeySource::from_key_ctx`] or [`KeySource::both`], or pass `None` for no key.
#[derive(Debug, Clone, Default)]
pub struct KeySource {
    key: Option<Vec<u8>>,
    key_ctx: Option<Vec<u8>>,
}

impl KeySource {
    /// A raw 32-byte AES key (ECB hypothesis).
    pub fn from_key(key: &[u8]) -> Self {
        Self {
            key: Some(key.to_vec()),
            key_ctx: None,
        }
    }

    /// A key-context blob (whitened AES-256-CBC). Padded to [`KEY_CTX_SIZE`] if short,
    /// since the recovered blob length (`0x10f4`) is below the size the reader needs to
    /// read the trailing IV slot.
    pub fn from_key_ctx(key_ctx: &[u8]) -> Self {
        let mut blob = key_ctx.to_vec();
        if blob.len() < KEY_CTX_SIZE {
            blob.resize(KEY_CTX_SIZE, 0);
        }
        Self {
            key: None,
            key_ctx: Some(blob),
        }
    }

    /// Both a raw key and a key-context blob; the whitened cipher is tried first.
    pub fn both(key: &[u8], key_ctx: &[u8]) -> Self {
        let mut ctx = key_ctx.to_vec();
        if ctx.len() < KEY_CTX_SIZE {
            ctx.resize(KEY_CTX_SIZE, 0);
        }
        Self {
            key: Some(key.to_vec()),
            key_ctx: Some(ctx),
        }
    }

    /// `true` when there is no key material at all.
    pub fn is_empty(&self) -> bool {
        self.key.is_none() && self.key_ctx.is_none()
    }
}

impl From<Option<&[u8]>> for KeySource {
    fn from(key: Option<&[u8]>) -> Self {
        match key {
            Some(k) => Self::from_key(k),
            None => Self::default(),
        }
    }
}

impl From<&KeySource> for KeySource {
    fn from(key: &KeySource) -> Self {
        key.clone()
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
    /// `key` is the optional key material; when empty and the TOC is encrypted, the
    /// archive is left in [`Decryption::EncryptedNoKey`]. Pass a [`KeySource::KeyCtx`]
    /// (or [`KeySource::both`]) to use the whitened AES-256-CBC cipher. The file is
    /// memory-mapped, so opening a multi-gigabyte archive is cheap.
    pub fn open(
        path: &Path,
        base_offset: Option<usize>,
        key: impl Into<KeySource>,
    ) -> Result<Self, Rpf9Error> {
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
        let key = key.into();
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
        arc.load_tables(&key);
        Ok(arc)
    }

    /// Read the TOC||names blob (small) and set the decryption state; parse entries if readable.
    fn load_tables(&mut self, key: &KeySource) {
        let start = self.header.toc_offset() as usize;
        let end = (self.header.data_offset() as usize).min(self.map.len());
        let blob = &self.map[start..end];
        let toc_len = (self.header.toc_byte_size as usize).min(blob.len());

        if !self.header.is_encrypted_toc() {
            self.toc_plain = Some(blob[..toc_len].to_vec());
            self.names_plain = Some(blob[toc_len..].to_vec());
            self.decryption = Decryption::Plaintext;
        } else if key.is_empty() {
            self.toc_plain = Some(blob[..toc_len].to_vec());
            self.names_plain = Some(blob[toc_len..].to_vec());
            self.decryption = Decryption::EncryptedNoKey;
        } else {
            // Try the whitened AES-256-CBC cipher first (the retail model), then fall
            // back to the ECB hypothesis if a raw key is also present. Each candidate is
            // accepted only if the decrypted names blob looks like ASCII.
            let mut candidates: Vec<(Decryption, Vec<u8>)> = Vec::new();
            if let Some(ctx) = &key.key_ctx {
                let cipher = WhitenedAesCbc::from_key_ctx(ctx, None);
                candidates.push((Decryption::WhitenedAesCbc, cipher.decrypt(blob, None)));
            }
            if let Some(k) = &key.key {
                candidates.push((Decryption::Aes256Ecb, decrypt_toc_and_names(blob, k)));
            }
            let cut = toc_len.min(blob.len());
            let chosen = candidates.iter().find(|(_, plain)| {
                names_plausibility(&plain[cut.min(plain.len())..]) >= DEFAULT_NAME_PLAUSIBILITY
            });
            let (state, plain) = chosen.cloned().unwrap_or_else(|| {
                candidates
                    .into_iter()
                    .next()
                    .unwrap_or((Decryption::WrongKey, Vec::new()))
            });
            let cut = cut.min(plain.len());
            self.decryption = if names_plausibility(&plain[cut..]) >= DEFAULT_NAME_PLAUSIBILITY {
                state
            } else {
                Decryption::WrongKey
            };
            self.toc_plain = Some(plain[..cut].to_vec());
            self.names_plain = Some(plain[cut..].to_vec());
        }

        if let Some(toc) = &self.toc_plain {
            self.entries = parse_entries(toc, self.header.entry_count());
        }
    }

    pub fn toc_readable(&self) -> bool {
        matches!(
            self.decryption,
            Decryption::Plaintext | Decryption::Aes256Ecb | Decryption::WhitenedAesCbc
        )
    }

    /// Walk the directory tree and return `(entry_index, relative_path)` for every
    /// **file** entry, with `relative_path` reconstructed from the directory nesting
    /// (mirrors Python `list_paths`/`_walk`). Returns an empty vec if the TOC is not
    /// readable. Directory entries contribute path components, not results.
    pub fn file_paths(&self) -> Vec<(usize, String)> {
        if !self.toc_readable() {
            return Vec::new();
        }
        let mut out = Vec::new();
        self.walk(0, "", &mut out);
        out
    }

    fn walk(&self, idx: usize, prefix: &str, out: &mut Vec<(usize, String)>) {
        let Some(entry) = self.entries.get(idx) else {
            return;
        };
        let names = self.names_plain.as_deref().unwrap_or(&[]);
        let name = read_name(names, entry.name_offset as usize);
        if entry.kind == EntryKind::Directory {
            let sub = if name.is_empty() {
                prefix.to_string()
            } else if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            };
            // A directory's children are the contiguous range [first, first+count).
            // Each child occupies its own subtree, so advance by that subtree's size
            // rather than by 1 (a child directory's block is nested inside the range).
            let first = entry.entries_index as usize;
            let end = first + entry.entries_count as usize;
            let mut child = first;
            while child < end {
                self.walk(child, &sub, out);
                child += self.subtree_size(child);
            }
            return;
        }
        let rel = if name.is_empty() {
            format!("entry_{idx:04}")
        } else if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        out.push((idx, rel));
    }

    /// Number of TOC entries spanned by the subtree rooted at `idx` (the entry itself
    /// plus, for a directory, the contiguous child range it owns).
    fn subtree_size(&self, idx: usize) -> usize {
        let Some(entry) = self.entries.get(idx) else {
            return 1;
        };
        if entry.kind != EntryKind::Directory {
            return 1;
        }
        let first = entry.entries_index as usize;
        let end = first + entry.entries_count as usize;
        let mut size = 1;
        let mut child = first;
        while child < end {
            size += self.subtree_size(child);
            child += self.subtree_size(child);
        }
        size
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
        let offset =
            self.header.base_offset as usize + (entry.file_offset_blocks as usize) * BLOCK_SIZE;
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
    /// Paths are reconstructed from the directory tree (via [`Archive::file_paths`]), so
    /// nested archives do not collide on leaf-name clashes. Uses rayon to inflate + write
    /// entries in parallel; each worker borrows the shared map (no per-thread file reads).
    /// Returns `(files, bytes, skipped_dirs)`.
    pub fn extract_all(
        &self,
        output_dir: &Path,
        decompress: bool,
    ) -> Result<(usize, usize, usize), Rpf9Error> {
        if !self.toc_readable() {
            return Err(Rpf9Error::Format {
                path: self.path.display().to_string(),
                msg: format!("TOC not readable (decryption={})", self.decryption.as_str()),
            });
        }
        std::fs::create_dir_all(output_dir)?;
        use rayon::prelude::*;

        // Total directory entries = entries not yielded by the tree walk (the walk only
        // emits file entries). Counted up front so the parallel map stays pure.
        let file_list = self.file_paths();
        let skipped_dirs = self.entries.len().saturating_sub(file_list.len());

        let results: Vec<Option<Vec<u8>>> = file_list
            .par_iter()
            .map(|(idx, _rel)| {
                let entry = &self.entries[*idx];
                let payload = self.payload_slice(entry)?;
                let payload = if decompress && entry.file_size > 0 {
                    Archive::maybe_inflate(payload)
                } else {
                    payload.to_vec()
                };
                Some(payload)
            })
            .collect();

        let mut files = 0;
        let mut total = 0usize;
        for ((_, rel), payload) in file_list.iter().zip(results) {
            let Some(payload) = payload else { continue };
            // `rel` uses '/' separators; join() handles them on every platform.
            let dest = output_dir.join(rel);
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&dest, &payload)?;
            files += 1;
            total += payload.len();
        }
        Ok((files, total, skipped_dirs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::{DIR_MARKER, ENTRY_SIZE, HEADER_SIZE, RPF9_MAGIC};
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;

    /// A raw-deflate (wbits = -15) stream — what the data region stores. Encoded with
    /// the gzip wrapper (header + trailer) and then unwrapped, since flate2 has no
    /// bare-deflate *writer*; the result is the raw DEFLATE bitstream alone.
    fn raw_deflate(data: &[u8]) -> Vec<u8> {
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(data).unwrap();
        let z = enc.finish().unwrap();
        // Gzip: 10-byte fixed header, raw deflate, 8-byte CRC+ISIZE trailer.
        let raw = &z[10..z.len() - 8];
        // Round-trip through the reader to prove it is valid raw deflate.
        assert_eq!(Archive::maybe_inflate(raw), data.to_vec());
        raw.to_vec()
    }

    /// A binary-file TOC entry: name(16) size(24) block(24) packed into d0|d1, with
    /// `usize` (the uncompressed size) in dword2. `size` is the on-disk (compressed)
    /// size; `size == 0` means stored, in which case `usize` is the byte length.
    /// Fields are extracted from the full 64-bit packed value (as `parse_entry` does),
    /// so the 16-bit name can straddle the d0/d1 boundary for small sizes.
    fn bin_entry(name: u32, size: u32, usize_: u32, block: u32) -> [u8; ENTRY_SIZE] {
        let packed = (name as u64) | ((size as u64) << 16) | ((block as u64) << 40);
        let mut e = [0u8; ENTRY_SIZE];
        e[0..4].copy_from_slice(&((packed & 0xFFFF_FFFF) as u32).to_le_bytes());
        e[4..8].copy_from_slice(&(((packed >> 32) & 0xFFFF_FFFF) as u32).to_le_bytes());
        e[8..12].copy_from_slice(&usize_.to_le_bytes());
        e
    }

    /// A directory TOC entry: name offset, DIR_MARKER, first child, child count.
    fn dir_entry(name: u32, first: u32, count: u32) -> [u8; ENTRY_SIZE] {
        let mut e = [0u8; ENTRY_SIZE];
        e[0..4].copy_from_slice(&name.to_le_bytes());
        e[4..8].copy_from_slice(&DIR_MARKER.to_le_bytes());
        e[8..12].copy_from_slice(&first.to_le_bytes());
        e[12..16].copy_from_slice(&count.to_le_bytes());
        e
    }

    /// Build a small plaintext archive with a nested directory tree. Directory children
    /// are the contiguous range `[first, first+count)`, so the layout is strictly nested:
    ///
    /// ```text
    /// root (0, unnamed) -> [ sub (1), other (3) ]
    ///   sub   (1)       -> [ a.txt (2) ]
    ///   other (3)       -> [ b.txt (4), top.txt (5) ]
    /// ```
    ///
    /// `a.txt`/`b.txt` are raw-deflate; `top.txt` is stored (size 0). Returns the file
    /// path and the expected plaintext of each file keyed by its tree-relative path.
    fn build_tree_archive(dir: &Path) -> (std::path::PathBuf, Vec<(String, Vec<u8>)>) {
        let a_plain = b"alpha-payload-contents".to_vec();
        let b_plain = b"bravo-payload".to_vec();
        let top_plain = b"top-level-stored".to_vec();
        let a_defl = raw_deflate(&a_plain);
        let b_defl = raw_deflate(&b_plain);

        // Name pool: NUL-separated. Root is unnamed (offset 0 = empty string), matching
        // a real RPF archive root. Offsets: ""=0 "sub"=1 "a.txt"=5 "other"=11 "b.txt"=17
        // "top.txt"=23
        let names: Vec<u8> = b"\0sub\0a.txt\0other\0b.txt\0top.txt\0".to_vec();

        // Payloads live at ABSOLUTE block addresses (base + block*BLOCK_SIZE), so the
        // data region starts at the first whole block after the tables. Compute those
        // block numbers first, then build the TOC in index order with them.
        let tables_end = HEADER_SIZE + 6 * ENTRY_SIZE + names.len();
        let block0 = tables_end.div_ceil(BLOCK_SIZE); // first whole block after tables
        let a_block = block0;
        let b_block = block0 + 1;
        let top_block = block0 + 2;

        // TOC: 6 entries. Each directory owns a contiguous child range.
        let mut toc: Vec<u8> = Vec::new();
        toc.extend_from_slice(&dir_entry(0, 1, 5)); // 0 root (unnamed) -> children [1..5]
        toc.extend_from_slice(&dir_entry(1, 2, 1)); // 1 sub   -> children [2]
        toc.extend_from_slice(&bin_entry(
            5,
            a_defl.len() as u32,
            a_plain.len() as u32,
            a_block as u32,
        )); // 2 a.txt
        toc.extend_from_slice(&dir_entry(11, 4, 2)); // 3 other -> children [4,5]
        toc.extend_from_slice(&bin_entry(
            17,
            b_defl.len() as u32,
            b_plain.len() as u32,
            b_block as u32,
        )); // 4 b.txt
        toc.extend_from_slice(&bin_entry(23, 0, top_plain.len() as u32, top_block as u32)); // 5 top.txt, stored

        // Data region: absolute blocks block0..block0+2, zero-padded to BLOCK_SIZE each.
        let data_start = block0 * BLOCK_SIZE;
        let mut file = vec![0u8; data_start + BLOCK_SIZE * 3];
        // header + toc + names occupy the prefix (within the first `data_start` bytes).
        let mut header = [0u8; HEADER_SIZE];
        header[0..4].copy_from_slice(&RPF9_MAGIC.to_le_bytes());
        header[4..8].copy_from_slice(&(toc.len() as u32).to_le_bytes());
        header[8..12].copy_from_slice(&(names.len() as u32).to_le_bytes());
        // encryption (f[3]) stays 0.
        file[..HEADER_SIZE].copy_from_slice(&header);
        file[HEADER_SIZE..HEADER_SIZE + toc.len()].copy_from_slice(&toc);
        file[HEADER_SIZE + toc.len()..HEADER_SIZE + toc.len() + names.len()]
            .copy_from_slice(&names);
        // payloads at their absolute block addresses
        file[data_start..data_start + a_defl.len()].copy_from_slice(&a_defl);
        file[b_block * BLOCK_SIZE..b_block * BLOCK_SIZE + b_defl.len()].copy_from_slice(&b_defl);
        file[top_block * BLOCK_SIZE..top_block * BLOCK_SIZE + top_plain.len()]
            .copy_from_slice(&top_plain);

        let path = dir.join("tree.rpf");
        std::fs::write(&path, &file).unwrap();

        let expected = vec![
            ("sub/a.txt".to_string(), a_plain),
            ("other/b.txt".to_string(), b_plain),
            ("other/top.txt".to_string(), top_plain),
        ];
        (path, expected)
    }

    #[test]
    fn file_paths_reconstructs_the_tree() {
        let dir = std::env::temp_dir().join(format!("rpf9_tree_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (path, _expected) = build_tree_archive(&dir);

        let arc = Archive::open(&path, None, None).unwrap();
        assert!(arc.toc_readable());
        let paths: Vec<String> = arc.file_paths().into_iter().map(|(_, p)| p).collect();
        let got: Vec<&str> = paths.iter().map(String::as_str).collect();
        assert_eq!(got, vec!["sub/a.txt", "other/b.txt", "other/top.txt"]);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn extract_all_writes_the_directory_tree() {
        let dir = std::env::temp_dir().join(format!("rpf9_extract_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (path, expected) = build_tree_archive(&dir);

        let arc = Archive::open(&path, None, None).unwrap();
        let out = dir.join("out");
        let (files, bytes, dirs) = arc.extract_all(&out, true).unwrap();

        // 3 files, 3 directory entries skipped (root, sub, other).
        assert_eq!(files, 3);
        assert_eq!(dirs, 3);

        // Each file must land at its tree-relative path with the right (inflated) bytes.
        for (rel, plain) in &expected {
            let dest = out.join(rel);
            assert!(dest.is_file(), "missing {rel}");
            let got = std::fs::read(&dest).unwrap();
            assert_eq!(
                got.len(),
                plain.len(),
                "size mismatch at {rel}: got {got:?}"
            );
            assert_eq!(got, *plain, "bad bytes at {rel}");
        }
        let expected_bytes: usize = expected.iter().map(|(_, p)| p.len()).sum();
        assert_eq!(bytes, expected_bytes);
        // The nested directories must actually exist (not a flat layout).
        assert!(out.join("sub").is_dir());
        assert!(out.join("other").is_dir());

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Build a small *encrypted* archive: the TOC||names blob is whitened-CBC ciphertext
    /// (encrypted with a synthetic key-context), the data region is cleartext. Returns the
    /// file path and the key-context blob to decrypt it with.
    fn build_encrypted_archive(dir: &Path) -> (std::path::PathBuf, Vec<u8>) {
        let names: Vec<u8> = b"\0hello.txt\0".to_vec();
        let plain = b"hello world".to_vec();
        let plain_defl = raw_deflate(&plain);

        // One file entry under an unnamed root.
        let tables_end = HEADER_SIZE + 2 * ENTRY_SIZE + names.len();
        let block0 = tables_end.div_ceil(BLOCK_SIZE);
        let mut toc: Vec<u8> = Vec::new();
        toc.extend_from_slice(&dir_entry(0, 1, 1)); // 0 root -> [1]
        toc.extend_from_slice(&bin_entry(
            1,
            plain_defl.len() as u32,
            plain.len() as u32,
            block0 as u32,
        )); // 1 hello.txt

        // Encrypt the TOC||names blob with a synthetic whitened-CBC key-context.
        let mut key_ctx = vec![0u8; KEY_CTX_SIZE];
        for (i, b) in key_ctx.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(31).wrapping_add(7);
        }
        let cipher = WhitenedAesCbc::from_key_ctx(&key_ctx, None);
        let mut blob = toc.clone();
        blob.extend_from_slice(&names);
        let enc = cipher.encrypt(&blob, None);

        let data_start = block0 * BLOCK_SIZE;
        let mut file = vec![0u8; data_start + BLOCK_SIZE];
        let mut header = [0u8; HEADER_SIZE];
        header[0..4].copy_from_slice(&RPF9_MAGIC.to_le_bytes());
        header[4..8].copy_from_slice(&(toc.len() as u32).to_le_bytes());
        header[8..12].copy_from_slice(&(names.len() as u32).to_le_bytes());
        header[12..16].copy_from_slice(&1u32.to_le_bytes()); // encryption != 0 => encrypted TOC
        file[..HEADER_SIZE].copy_from_slice(&header);
        file[HEADER_SIZE..HEADER_SIZE + enc.len()].copy_from_slice(&enc);
        file[data_start..data_start + plain_defl.len()].copy_from_slice(&plain_defl);

        let path = dir.join("enc.rpf");
        std::fs::write(&path, &file).unwrap();
        (path, key_ctx)
    }

    #[test]
    fn whitened_cbc_key_ctx_makes_the_toc_readable() {
        let dir = std::env::temp_dir().join(format!("rpf9_wcbc_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (path, key_ctx) = build_encrypted_archive(&dir);

        // No key: encrypted, TOC not readable.
        let no_key = Archive::open(&path, None, None).unwrap();
        assert_eq!(no_key.decryption, Decryption::EncryptedNoKey);
        assert!(!no_key.toc_readable());

        // With the key-context: whitened-CBC decrypts and the names look like ASCII.
        let arc = Archive::open(&path, None, KeySource::from_key_ctx(&key_ctx)).unwrap();
        assert_eq!(arc.decryption, Decryption::WhitenedAesCbc);
        assert!(arc.toc_readable());
        let paths: Vec<String> = arc.file_paths().into_iter().map(|(_, p)| p).collect();
        assert_eq!(paths, vec!["hello.txt"]);

        std::fs::remove_dir_all(&dir).ok();
    }
}
