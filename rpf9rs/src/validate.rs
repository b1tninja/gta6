//! Structural validation of an RPF9 archive.
//!
//! Byte-for-byte template matching is a weak check: the known-plaintext bytes are
//! build-specific and may differ in another build or the production release. These
//! checks instead validate the *structure* — that the header is self-consistent, the
//! TOC/names/data regions fit inside the file, the entry table is internally coherent,
//! and the data region actually inflates. None of them depend on any particular byte
//! values, so they stay useful across builds.
//!
//! The entry-table and inflate checks only apply when the TOC is readable (plaintext,
//! or decrypted with a correct key). When the TOC is encrypted and no key is set, the
//! header/region checks still run and the table checks are reported as skipped.

use std::path::Path;

use crate::archive::Archive;
use crate::entries::EntryKind;
use crate::format::{BLOCK_SIZE, ENTRY_SIZE, PAGE_SIZE, Rpf9Error};

/// One named structural check and its outcome.
#[derive(Debug, Clone)]
pub struct Check {
    pub name: String,
    pub ok: bool,
    pub detail: String,
}

/// Aggregate result of validating one archive base.
#[derive(Debug, Default)]
pub struct ValidationReport {
    pub path: String,
    pub base_offset: u64,
    pub checks: Vec<Check>,
    pub skipped: Vec<String>,
}

impl ValidationReport {
    fn add(&mut self, name: &str, ok: bool, detail: String) {
        self.checks.push(Check {
            name: name.to_string(),
            ok,
            detail,
        });
    }

    pub fn ok(&self) -> bool {
        self.checks.iter().all(|c| c.ok)
    }
}

fn check_header(report: &mut ValidationReport, arc: &Archive) {
    let h = &arc.header;
    report.add("magic", h.magic == crate::format::RPF9_MAGIC, format!("{:#x}", h.magic));
    report.add(
        "toc_size_nonzero",
        h.toc_byte_size > 0,
        format!("toc_byte_size={}", h.toc_byte_size),
    );
    report.add(
        "entry_count_consistent",
        (h.toc_byte_size as usize) % ENTRY_SIZE == 0,
        format!("toc_byte_size={} entry_count={}", h.toc_byte_size, h.entry_count()),
    );
}

/// Highest byte any file entry claims to occupy (start block + stored size).
fn max_data_end(arc: &Archive) -> usize {
    let mut end = arc.header.data_offset() as usize;
    for e in &arc.entries {
        if e.kind == EntryKind::Directory {
            continue;
        }
        let size = if e.file_size > 0 { e.file_size } else { e.file_uncompressed_size } as usize;
        let start = arc.header.base_offset as usize + (e.file_offset_blocks as usize) * BLOCK_SIZE;
        end = end.max(start + size);
    }
    end
}

fn check_regions(report: &mut ValidationReport, arc: &Archive, file_size: usize) {
    let h = &arc.header;
    let data_offset = h.data_offset() as usize;
    report.add(
        "toc_within_file",
        data_offset <= file_size,
        format!("data_offset={data_offset} file_size={file_size}"),
    );
    report.add(
        "data_region_present",
        data_offset < file_size,
        format!("data_offset={data_offset} file_size={file_size}"),
    );
    // The data region must at least be able to hold the largest referenced block.
    if arc.toc_readable() {
        let max_end = max_data_end(arc);
        report.add(
            "data_region_fits",
            max_end <= file_size,
            format!("max_data_end={max_end} file_size={file_size}"),
        );
    } else {
        report.skipped.push("data_region_fits (TOC not readable)".to_string());
    }
}

fn check_entries(report: &mut ValidationReport, arc: &Archive) {
    if !arc.toc_readable() {
        report.skipped.push("entry_table (TOC not readable)".to_string());
        report.skipped.push("names_in_range (TOC not readable)".to_string());
        report.skipped.push("directory_tree (TOC not readable)".to_string());
        return;
    }

    let names_len = arc.header.names_byte_size as usize;
    let toc_len = arc.header.toc_byte_size as usize;

    // Every file entry's name offset must land inside the names region.
    let bad_names = arc
        .entries
        .iter()
        .filter(|e| e.kind != EntryKind::Directory && (e.name_offset as usize) >= names_len)
        .count();
    report.add(
        "names_in_range",
        bad_names == 0,
        if bad_names > 0 {
            format!("{bad_names} out-of-range")
        } else {
            format!("names_len={names_len}")
        },
    );

    // Directory children must reference entry indices inside the TOC.
    let bad_dirs = arc
        .entries
        .iter()
        .filter(|e| {
            e.kind == EntryKind::Directory
                && ((e.entries_index + e.entries_count) as usize) > arc.header.entry_count()
        })
        .count();
    report.add(
        "directory_tree",
        bad_dirs == 0,
        if bad_dirs > 0 {
            format!("{bad_dirs} dirs out of range")
        } else {
            "ok".to_string()
        },
    );

    // The TOC must contain at least the declared entry_count * ENTRY_SIZE bytes.
    report.add(
        "toc_holds_entries",
        toc_len >= arc.header.entry_count() * ENTRY_SIZE,
        format!("toc_len={toc_len} need={}", arc.header.entry_count() * ENTRY_SIZE),
    );
}

/// Try to inflate a few file payloads; the data region is cleartext deflate.
fn check_data_inflates(report: &mut ValidationReport, arc: &Archive, sample: usize) {
    if !arc.toc_readable() {
        report.skipped.push("data_inflates (TOC not readable)".to_string());
        return;
    }
    let mut tried = 0;
    let mut inflated = 0;
    for e in &arc.entries {
        if e.kind == EntryKind::Directory || e.file_size == 0 {
            continue;
        }
        if tried >= sample {
            break;
        }
        tried += 1;
        let payload = arc.payload_slice(e).unwrap_or(&[]);
        if payload.is_empty() {
            continue;
        }
        if !Archive::maybe_inflate(payload).is_empty() {
            inflated += 1;
        }
    }
    if tried == 0 {
        report.skipped.push("data_inflates (no compressed entries sampled)".to_string());
        return;
    }
    report.add(
        "data_inflates",
        inflated > 0,
        format!("{inflated}/{tried} sampled payloads inflated"),
    );
}

/// Validate one archive base structurally. Raises if no RPF9 header is present.
pub fn validate_archive(
    path: &Path,
    base_offset: Option<usize>,
    key: Option<&[u8]>,
) -> Result<ValidationReport, Rpf9Error> {
    let arc = Archive::open(path, base_offset, key)?;
    let base = arc.header.base_offset;
    let mut report = ValidationReport {
        path: arc.path.display().to_string(),
        base_offset: base,
        checks: Vec::new(),
        skipped: Vec::new(),
    };
    let file_size = arc.file_size as usize;
    check_header(&mut report, &arc);
    check_regions(&mut report, &arc, file_size);
    check_entries(&mut report, &arc);
    check_data_inflates(&mut report, &arc, 8);
    Ok(report)
}

/// Summary of validating several archives in parallel.
pub struct ValidateSummary {
    pub count: usize,
    pub ok: usize,
    pub failed: usize,
    pub page_size: usize,
    pub rows: Vec<ValidationReport>,
    pub errors: Vec<(String, String)>,
}

/// Validate several archives; a file with no RPF9 header is reported, not fatal.
///
/// Archives are validated in parallel with rayon — the point of the Rust port.
pub fn validate_paths(paths: &[std::path::PathBuf], key: Option<&[u8]>) -> ValidateSummary {
    use rayon::prelude::*;
    let existing: Vec<_> = paths.iter().filter(|p| p.is_file()).cloned().collect();
    let results: Vec<Result<ValidationReport, Rpf9Error>> = existing
        .par_iter()
        .map(|p| validate_archive(p, None, key))
        .collect();

    let mut rows = Vec::new();
    let mut errors = Vec::new();
    for r in results {
        match r {
            Ok(rep) => rows.push(rep),
            Err(e) => errors.push((path_of(&e), e.to_string())),
        }
    }
    let ok = rows.iter().filter(|r| r.ok()).count();
    ValidateSummary {
        count: rows.len() + errors.len(),
        ok,
        failed: rows.len() - ok + errors.len(),
        page_size: PAGE_SIZE,
        rows,
        errors,
    }
}

fn path_of(e: &Rpf9Error) -> String {
    match e {
        Rpf9Error::Format { path, .. } => path.clone(),
        Rpf9Error::Io(_) => "<io>".to_string(),
    }
}
