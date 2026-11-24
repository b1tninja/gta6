//! Automatic AES key-context recovery from the game binary — heuristic, no hard-coded
//! bytes.
//!
//! Port of the primary path in the Python `gta6/rpf9/sbox_key.py`, but the table is found
//! **structurally** rather than by scanning for a byte pattern. Nothing here copies opcode
//! or key bytes from the game; every discriminator is a structural property of the data.
//!
//! ## What is recovered
//!
//! The block-cipher provider registry is a static table of 24-byte entries:
//!
//! ```text
//! { u64 key, u64 val0, u32 len, u32 pad }   // stride 0x18
//! ```
//!
//! confirmed by the registry builder `FUN_141b952e0`, which walks the table with stride
//! `0x18` reading fields at `+0`, `+8`, `+0x10`. `key` packs `(handle << 32) | (flags << 24)`;
//! `val0` points at a key-context blob of `len` bytes. The AES-256 whitened-CBC key context
//! is the **largest high-entropy** `val0` (measured: entropy 8.00, length `0x10f4`).
//!
//! ## How it is found (heuristic)
//!
//! 1. Scan `.rdata` for a run of `>= MIN_ENTRIES` 24-byte entries that all satisfy the
//!    registry signature:
//!    * `flags = (key >> 24) & 0xFF` is in `{0, 2, 3}` (the observed families),
//!    * `val0` is either null or a VA that maps into the image,
//!    * `len` is a plausible blob size.
//! 2. Keep a candidate only if at least one entry's `val0` is a **high-entropy** blob
//!    (Shannon entropy >= `HIGH_ENTROPY_BITS`). A real key schedule / whitening table is
//!    ~8.0 bits/byte; an IV slot or pointer table is far lower. This is the discriminator
//!    that separates the crypto registry from other `{ ptr, len }` tables.
//! 3. Return the largest high-entropy blob in that table (length derived from the data).
//!
//! The descriptor getter (`FUN_1456c9600`: `*p = &table; *(p+1) = count;`) is the *source*
//! of the table, but we do not need to match its bytes — scanning the table directly is
//! byte-free and equally reliable. Optional `handle`/`flags` filters pin a specific key
//! (e.g. `handle=1, flags=2` is the static archive key).

use std::path::Path;

use goblin::pe::PE;
use memmap2::Mmap;

/// Provider-registry entry size: `{ u64 key, u64 val0, u32 len, u32 pad }`.
pub const REGISTRY_ENTRY_SIZE: usize = 24;
/// Minimum entries a table must have to be considered the registry.
pub const MIN_ENTRIES: usize = 4;
/// Upper bound on a plausible key-context blob length (guards against random matches).
pub const MAX_BLOB_LEN: u32 = 0x4000;
/// Shannon entropy (bits/byte) at/above which a region is treated as key material.
pub const HIGH_ENTROPY_BITS: f64 = 7.5;
/// The *expected* key-context blob size (round keys + final whitening tables + IV slot).
/// Reporting only — discovery derives the length from the data.
pub const KEY_CTX_LEN: usize = 0x10F4;
/// Cap on the entropy sample so a huge `len` does not make the scan slow.
const ENTROPY_CAP: usize = 0x2000;
/// Registry key packing is `(handle << 32) | (flags << 24)`; these are the observed
/// families (2 = block-cipher family, internal alg ids 0x10..0x15; 0/3 appear elsewhere).
const VALID_REGISTRY_FLAGS: [u8; 3] = [0, 2, 3];

/// One section of the PE, with the file-offset <-> VA mapping we need.
#[derive(Debug, Clone)]
struct Section {
    name: String,
    va: u64,
    vsize: usize,
    raw: usize,
    raw_size: usize,
}

/// Minimal PE view over a memory-mapped executable: file-offset <-> VA mapping and
/// section access. Mirrors the Python `PeView` but maps instead of reading whole bytes.
pub struct PeView {
    map: Mmap,
    image_base: u64,
    sections: Vec<Section>,
}

impl PeView {
    /// Memory-map `path` and parse its PE headers.
    pub fn open(path: &Path) -> Result<Self, RecoveryError> {
        let file = std::fs::File::open(path)
            .map_err(|e| RecoveryError::Io(path.display().to_string(), e.to_string()))?;
        // SAFETY: read-only map; the exe is not mutated or truncated while mapped.
        let map = unsafe { Mmap::map(&file) }
            .map_err(|e| RecoveryError::Io(path.display().to_string(), e.to_string()))?;
        let pe = PE::parse(&map[..])
            .map_err(|e| RecoveryError::Pe(path.display().to_string(), e.to_string()))?;
        let image_base = pe.image_base;
        let sections = pe
            .sections
            .iter()
            .map(|s| {
                let name = String::from_utf8_lossy(&s.name[..])
                    .trim_end_matches('\0')
                    .to_string();
                Section {
                    name,
                    va: image_base + s.virtual_address as u64,
                    vsize: (s.virtual_size.max(s.size_of_raw_data)) as usize,
                    raw: s.pointer_to_raw_data as usize,
                    raw_size: s.size_of_raw_data as usize,
                }
            })
            .collect();
        Ok(Self {
            map,
            image_base,
            sections,
        })
    }

    pub fn image_base(&self) -> u64 {
        self.image_base
    }

    /// File offset for a VA, if it lands inside a mapped section's raw extent.
    pub fn va_to_file(&self, va: u64) -> Option<usize> {
        for s in &self.sections {
            if s.va <= va && va < s.va + s.vsize as u64 {
                let off = s.raw + (va - s.va) as usize;
                if off < self.map.len() {
                    return Some(off);
                }
            }
        }
        None
    }

    fn section_by_name(&self, name: &str) -> Option<&Section> {
        self.sections.iter().find(|s| s.name == name)
    }

    /// Bytes at a VA (bounded by the map length), or `None` if unmapped.
    pub fn read_at_va(&self, va: u64, size: usize) -> Option<&[u8]> {
        let off = self.va_to_file(va)?;
        let end = off.saturating_add(size).min(self.map.len());
        if off >= self.map.len() || end <= off {
            return None;
        }
        Some(&self.map[off..end])
    }

    /// Read the recovered key-context blob's bytes (for driving the whitened cipher).
    ///
    /// Returns the `length` bytes at `blob_off`, clamped to the map length. The blob
    /// length is the recovered value (`0x10f4`); callers that need the full
    /// [`crate::crypto::KEY_CTX_SIZE`] should pad (see [`crate::KeySource::from_key_ctx`]).
    pub fn read_key_ctx_blob(&self, r: &RecoveredKeyCtx) -> Option<Vec<u8>> {
        let end = r
            .blob_off
            .saturating_add(r.length as usize)
            .min(self.map.len());
        if r.blob_off >= self.map.len() || end <= r.blob_off {
            return None;
        }
        Some(self.map[r.blob_off..end].to_vec())
    }
}

/// One 24-byte provider-registry entry `{ key, val0, len }`.
#[derive(Debug, Clone, Copy)]
pub struct RegistryEntry {
    pub key: u64,
    pub val0: u64,
    pub length: u32,
}

impl RegistryEntry {
    pub fn handle(&self) -> u64 {
        self.key >> 32
    }
    pub fn flags(&self) -> u8 {
        ((self.key >> 24) & 0xFF) as u8
    }
}

/// A registry table located by the structural scan.
#[derive(Debug, Clone, Copy)]
pub struct RegistryTable {
    pub table_va: u64,
    pub count: u32,
}

/// The recovered key-context blob: where it lives and how it was found.
#[derive(Debug, Clone, Copy)]
pub struct RecoveredKeyCtx {
    pub blob_va: u64,
    pub blob_off: usize,
    pub length: u32,
    pub table_va: u64,
    pub handle: u64,
    pub flags: u8,
}

#[derive(Debug, thiserror::Error)]
pub enum RecoveryError {
    #[error("{0}: {1}")]
    Io(String, String),
    #[error("{0}: not a parseable PE: {1}")]
    Pe(String, String),
}

/// Shannon entropy in bits/byte (0..8). Used to spot key-schedule regions.
fn shannon_entropy(buf: &[u8]) -> f64 {
    if buf.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in buf {
        counts[b as usize] += 1;
    }
    let n = buf.len() as f64;
    let mut h = 0.0f64;
    for &c in &counts {
        if c != 0 {
            let p = c as f64 / n;
            h -= p * p.log2();
        }
    }
    h
}

/// True if the region at `va` looks like key material (high entropy).
fn is_high_entropy(view: &PeView, va: u64, length: u32) -> bool {
    if va == 0 || length == 0 {
        return false;
    }
    let want = (length as usize).min(ENTROPY_CAP);
    let raw = match view.read_at_va(va, want) {
        Some(r) => r,
        None => return false,
    };
    if raw.len() < (length as usize).min(64) {
        return false;
    }
    shannon_entropy(raw) >= HIGH_ENTROPY_BITS
}

/// Parse `count` 24-byte `{ u64 key, u64 val0, u32 len }` entries at `table_va`.
/// Returns an empty list if the table is not fully mapped.
pub fn parse_registry_table(view: &PeView, table_va: u64, count: u32) -> Vec<RegistryEntry> {
    if count == 0 {
        return Vec::new();
    }
    let need = count as usize * REGISTRY_ENTRY_SIZE;
    let raw = match view.read_at_va(table_va, need) {
        Some(r) if r.len() >= need => r,
        _ => return Vec::new(),
    };
    let mut out = Vec::with_capacity(count as usize);
    for i in 0..count as usize {
        let base = i * REGISTRY_ENTRY_SIZE;
        let key = u64::from_le_bytes(raw[base..base + 8].try_into().unwrap());
        let val0 = u64::from_le_bytes(raw[base + 8..base + 16].try_into().unwrap());
        let length = u32::from_le_bytes(raw[base + 16..base + 20].try_into().unwrap());
        out.push(RegistryEntry { key, val0, length });
    }
    out
}

/// True if `entries` look like the block-cipher provider registry (structural only).
pub fn is_crypto_registry(entries: &[RegistryEntry], view: &PeView) -> bool {
    if entries.len() < MIN_ENTRIES {
        return false;
    }
    if !entries
        .iter()
        .all(|e| VALID_REGISTRY_FLAGS.contains(&e.flags()))
    {
        return false;
    }
    if !entries
        .iter()
        .all(|e| e.length == 0 || e.length <= MAX_BLOB_LEN)
    {
        return false;
    }
    if !entries
        .iter()
        .any(|e| is_high_entropy(view, e.val0, e.length))
    {
        return false;
    }
    entries
        .iter()
        .all(|e| e.val0 == 0 || view.va_to_file(e.val0).is_some())
}

/// Scan `.rdata` for registry tables matching the structural signature.
///
/// Walks the section at 8-byte alignment (tables are pointer-aligned) and, at each
/// candidate offset, reads forward as long as consecutive entries satisfy the per-entry
/// signature. A run of `>= MIN_ENTRIES` such entries whose table also contains a
/// high-entropy blob is reported.
pub fn find_registry_tables(view: &PeView) -> Vec<RegistryTable> {
    let rdata = match view.section_by_name(".rdata") {
        Some(s) => s,
        None => return Vec::new(),
    };
    let data = match view.read_at_va(rdata.va, rdata.raw_size) {
        Some(d) => d,
        None => return Vec::new(),
    };
    let base_va = rdata.va;
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + REGISTRY_ENTRY_SIZE <= data.len() {
        // Count how many consecutive entries satisfy the per-entry signature.
        let mut n = 0usize;
        let mut p = off;
        while p + REGISTRY_ENTRY_SIZE <= data.len() {
            let key = u64::from_le_bytes(data[p..p + 8].try_into().unwrap());
            let val0 = u64::from_le_bytes(data[p + 8..p + 16].try_into().unwrap());
            let length = u32::from_le_bytes(data[p + 16..p + 20].try_into().unwrap());
            let flags = ((key >> 24) & 0xFF) as u8;
            let ok = VALID_REGISTRY_FLAGS.contains(&flags)
                && (length == 0 || length <= MAX_BLOB_LEN)
                && (val0 == 0 || view.va_to_file(val0).is_some());
            if !ok {
                break;
            }
            n += 1;
            p += REGISTRY_ENTRY_SIZE;
        }
        if n >= MIN_ENTRIES {
            let table_va = base_va + off as u64;
            let entries = parse_registry_table(view, table_va, n as u32);
            if is_crypto_registry(&entries, view) {
                out.push(RegistryTable {
                    table_va,
                    count: n as u32,
                });
            }
            // Skip past this table so we do not re-report overlapping sub-runs.
            off = p;
        } else {
            off += 8;
        }
    }
    out
}

/// Recover the AES key-context blob address from the executable.
///
/// Finds the registry table structurally, then returns the key-context blob: the
/// **largest high-entropy** `val0` in that table (length derived from the data).
/// `handle`/`flags` are optional filters (e.g. `handle=1, flags=2` pins the static archive
/// key); when omitted, the first table's largest high-entropy blob is returned.
pub fn recover_key_ctx_blob(
    view: &PeView,
    handle: Option<u64>,
    flags: Option<u8>,
) -> Option<RecoveredKeyCtx> {
    for table in find_registry_tables(view) {
        let entries = parse_registry_table(view, table.table_va, table.count);
        let mut best: Option<&RegistryEntry> = None;
        for e in entries.iter() {
            if !is_high_entropy(view, e.val0, e.length) {
                continue;
            }
            if view.va_to_file(e.val0).is_none() {
                continue;
            }
            if handle.is_some_and(|h| e.handle() != h) {
                continue;
            }
            if flags.is_some_and(|f| e.flags() != f) {
                continue;
            }
            // Largest length wins; ties keep the earliest entry.
            match best {
                Some(cur) if cur.length >= e.length => {}
                _ => best = Some(e),
            }
        }
        if let Some(e) = best {
            let blob_off = view.va_to_file(e.val0)?;
            return Some(RecoveredKeyCtx {
                blob_va: e.val0,
                blob_off,
                length: e.length,
                table_va: table.table_va,
                handle: e.handle(),
                flags: e.flags(),
            });
        }
    }
    None
}

/// Recover the key-context blob and return a JSON-friendly report (the CLI entry point).
pub fn recover_key_ctx_report(
    exe: &Path,
    handle: Option<u64>,
    flags: Option<u8>,
) -> Result<serde_json::Value, RecoveryError> {
    let view = PeView::open(exe)?;
    let tables = find_registry_tables(&view);
    let mut report = serde_json::Map::new();
    report.insert(
        "exe".into(),
        serde_json::Value::String(exe.display().to_string()),
    );
    report.insert(
        "image_base".into(),
        serde_json::Value::String(format!("{:#x}", view.image_base())),
    );
    let table_json: Vec<_> = tables
        .iter()
        .map(|t| {
            serde_json::json!({
                "table_va": format!("{:#x}", t.table_va),
                "count": t.count,
            })
        })
        .collect();
    report.insert(
        "registry_tables".into(),
        serde_json::Value::Array(table_json),
    );
    match recover_key_ctx_blob(&view, handle, flags) {
        Some(r) => {
            report.insert(
                "key_ctx".into(),
                serde_json::json!({
                    "blob_va": format!("{:#x}", r.blob_va),
                    "blob_off": r.blob_off,
                    "length": format!("{:#x}", r.length),
                    "table_va": format!("{:#x}", r.table_va),
                    "handle": format!("{:#x}", r.handle),
                    "flags": r.flags,
                }),
            );
            report.insert("status".into(), serde_json::Value::String("ok".into()));
        }
        None => {
            report.insert("key_ctx".into(), serde_json::Value::Null);
            report.insert(
                "status".into(),
                serde_json::Value::String("no_registry".into()),
            );
        }
    }
    Ok(serde_json::Value::Object(report))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_entry(data: &mut [u8], off: usize, handle: u64, flags: u8, val0: u64, len: u32) {
        let key = (handle << 32) | ((flags as u64) << 24);
        data[off..off + 8].copy_from_slice(&key.to_le_bytes());
        data[off + 8..off + 16].copy_from_slice(&val0.to_le_bytes());
        data[off + 16..off + 20].copy_from_slice(&len.to_le_bytes());
    }

    #[test]
    fn entropy_distinguishes_key_material() {
        let key_like: Vec<u8> = (0..0x1000)
            .map(|i| (i as u32).wrapping_mul(2654435761) % 256)
            .map(|v| v as u8)
            .collect();
        assert!(shannon_entropy(&key_like) >= HIGH_ENTROPY_BITS);
        let zeros = vec![0u8; 0x1000];
        assert!(shannon_entropy(&zeros) < HIGH_ENTROPY_BITS);
    }

    #[test]
    fn entry_packing_roundtrips() {
        let mut buf = [0u8; 24];
        write_entry(&mut buf, 0, 0x10000004, 2, 0x1466e6c60, 0x10f4);
        let e = RegistryEntry {
            key: u64::from_le_bytes(buf[0..8].try_into().unwrap()),
            val0: u64::from_le_bytes(buf[8..16].try_into().unwrap()),
            length: u32::from_le_bytes(buf[16..20].try_into().unwrap()),
        };
        assert_eq!(e.handle(), 0x10000004);
        assert_eq!(e.flags(), 2);
        assert_eq!(e.val0, 0x1466e6c60);
        assert_eq!(e.length, 0x10f4);
    }
}
