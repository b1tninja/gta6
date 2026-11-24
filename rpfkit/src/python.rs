//! Native Python bindings for the rpfkit RPF9 reader (pyo3 0.30).
//!
//! Compiled only with the `python` feature (maturin enables it). Exposes the archive
//! reader, structural validator and key-context recovery to Python as the `rpfkit`
//! extension module, mirroring the `gta6.rpf9` surface so the Python CLI can call the
//! AES-NI / multithreaded Rust core directly.
//!
//! The Rust error types are surfaced as a single `Rpf9Error` Python exception (a
//! subclass of `OSError`, since most failures are I/O or format problems).

use std::path::PathBuf;

use pyo3::create_exception;
use pyo3::exceptions::PyOSError;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyDictMethods, PyList, PyListMethods};

use crate::archive::Archive;
use crate::recovery::recover_key_ctx_report;
use crate::validate;

// Python exception raised for every Rust-side failure (I/O, format, recovery).
create_exception!(rpfkit, Rpf9Error, PyOSError);

/// Wrap a Rust error as the module's `Rpf9Error` exception.
fn pyerr<E: std::fmt::Display>(e: E) -> PyErr {
    Rpf9Error::new_err(e.to_string())
}

/// Resolve an explicit key, else fall back to `GTA6_AES_KEY_HEX` / `GTA6_AES_KEY_FILE`
/// (the same environment the CLI reads). Returns `None` when neither is set.
fn resolve_key(key: Option<Vec<u8>>) -> Option<Vec<u8>> {
    key.or_else(crate::keys::load_aes_key)
}

/// An opened RPF9 archive.
///
/// Open with `rpfkit.Archive(path)` (optionally `base_offset=` and `key=`). When no
/// `key` is given, the reader falls back to the `GTA6_AES_KEY_HEX` / `GTA6_AES_KEY_FILE`
/// environment variables, matching the CLI.
#[pyclass(name = "Archive")]
pub struct PyArchive {
    inner: Archive,
}

#[pymethods]
impl PyArchive {
    #[new]
    #[pyo3(signature = (path, *, base_offset=None, key=None))]
    fn new(path: PathBuf, base_offset: Option<usize>, key: Option<Vec<u8>>) -> PyResult<Self> {
        let key = resolve_key(key);
        let inner = Archive::open(&path, base_offset, key.as_deref()).map_err(pyerr)?;
        Ok(Self { inner })
    }

    /// Header + decryption state as a plain dict (mirrors `Rpf9Archive.info()`).
    fn info<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let h = &self.inner.header;
        let d = PyDict::new(py);
        d.set_item("path", self.inner.path.display().to_string())?;
        d.set_item("base_offset", h.base_offset)?;
        d.set_item("magic", h.magic)?;
        d.set_item("toc_byte_size", h.toc_byte_size)?;
        d.set_item("names_byte_size", h.names_byte_size)?;
        d.set_item("entry_count", h.entry_count())?;
        d.set_item("encryption", h.encryption)?;
        d.set_item("archive_id_0", h.archive_id.0)?;
        d.set_item("archive_id_1", h.archive_id.1)?;
        d.set_item("platform_tag", h.platform_tag)?;
        d.set_item("platform_flags", h.platform_flags)?;
        d.set_item("toc_offset", h.toc_offset())?;
        d.set_item("names_offset", h.names_offset())?;
        d.set_item("data_offset", h.data_offset())?;
        d.set_item("file_size", self.inner.file_size)?;
        d.set_item("decryption", self.inner.decryption.as_str())?;
        d.set_item("toc_readable", self.inner.toc_readable())?;
        Ok(d)
    }

    /// Whether the TOC decrypted into readable names.
    #[getter]
    fn toc_readable(&self) -> bool {
        self.inner.toc_readable()
    }

    /// How the TOC was decrypted: "plaintext", "encrypted_no_key", "aes256_ecb", ...
    #[getter]
    fn decryption(&self) -> &'static str {
        self.inner.decryption.as_str()
    }

    /// Every file path in the archive (needs a readable TOC).
    fn list_paths(&self) -> Vec<String> {
        self.inner
            .file_paths()
            .into_iter()
            .map(|(_, p)| p)
            .collect()
    }

    /// Extract every file entry under `output_dir`, preserving the directory tree.
    ///
    /// Returns `{files, bytes, skipped_dirs}`. `decompress=False` writes stored bytes
    /// as-is instead of raw-inflating them.
    #[pyo3(signature = (output_dir, *, decompress=true))]
    fn extract_all<'py>(
        &self,
        py: Python<'py>,
        output_dir: PathBuf,
        decompress: bool,
    ) -> PyResult<Bound<'py, PyDict>> {
        let (files, bytes, dirs) = self
            .inner
            .extract_all(&output_dir, decompress)
            .map_err(pyerr)?;
        let d = PyDict::new(py);
        d.set_item("files", files)?;
        d.set_item("bytes", bytes)?;
        d.set_item("skipped_dirs", dirs)?;
        Ok(d)
    }

    fn __repr__(&self) -> String {
        format!(
            "Archive(path='{}', toc_readable={})",
            self.inner.path.display(),
            self.inner.toc_readable()
        )
    }
}

/// Structurally validate one archive; returns a dict report.
#[pyfunction]
#[pyo3(signature = (path, *, base_offset=None, key=None))]
fn validate_archive<'py>(
    py: Python<'py>,
    path: PathBuf,
    base_offset: Option<usize>,
    key: Option<Vec<u8>>,
) -> PyResult<Bound<'py, PyDict>> {
    let key = resolve_key(key);
    let report = validate::validate_archive(&path, base_offset, key.as_deref()).map_err(pyerr)?;
    let d = PyDict::new(py);
    d.set_item("path", report.path.clone())?;
    d.set_item("base_offset", report.base_offset)?;
    d.set_item("ok", report.ok())?;
    let checks = PyList::empty(py);
    for c in &report.checks {
        let row = PyDict::new(py);
        row.set_item("name", c.name.as_str())?;
        row.set_item("ok", c.ok)?;
        row.set_item("detail", c.detail.as_str())?;
        checks.append(row)?;
    }
    d.set_item("checks", checks)?;
    d.set_item("skipped", report.skipped.clone())?;
    Ok(d)
}

/// Validate many archives in parallel; returns a summary dict.
#[pyfunction]
#[pyo3(signature = (paths, *, key=None))]
fn validate_paths<'py>(
    py: Python<'py>,
    paths: Vec<PathBuf>,
    key: Option<Vec<u8>>,
) -> Bound<'py, PyDict> {
    let key = resolve_key(key);
    let summary = validate::validate_paths(&paths, key.as_deref());
    let d = PyDict::new(py);
    d.set_item("count", summary.count).unwrap();
    d.set_item("ok", summary.ok).unwrap();
    d.set_item("failed", summary.failed).unwrap();
    d.set_item("page_size", summary.page_size).unwrap();
    let rows = PyList::empty(py);
    for r in &summary.rows {
        let row = PyDict::new(py);
        row.set_item("path", r.path.clone()).unwrap();
        row.set_item("base_offset", r.base_offset).unwrap();
        row.set_item("ok", r.ok()).unwrap();
        rows.append(row).unwrap();
    }
    d.set_item("rows", rows).unwrap();
    let errors = PyList::empty(py);
    for (p, e) in &summary.errors {
        errors.append((p.clone(), e.clone())).unwrap();
    }
    d.set_item("errors", errors).unwrap();
    d
}

/// Recover the AES key-context blob address from the exe (no key material).
///
/// Returns the JSON report as a Python object. `handle`/`flags` are optional filters
/// (e.g. `handle=1` pins the static archive key, `flags=2` the block-cipher family).
#[pyfunction]
#[pyo3(signature = (exe, *, handle=None, flags=None))]
fn recover_key_ctx(
    py: Python<'_>,
    exe: PathBuf,
    handle: Option<u64>,
    flags: Option<u8>,
) -> PyResult<Py<PyAny>> {
    let report = recover_key_ctx_report(&exe, handle, flags).map_err(pyerr)?;
    let json = serde_json::to_string(&report).map_err(pyerr)?;
    let json_module = py.import("json")?;
    let loaded = json_module.call_method1("loads", (json,))?;
    Ok(loaded.unbind())
}

/// The `rpfkit` native extension module.
///
/// The exported Python names are the Rust item names, so the functions are named
/// exactly as they should appear in Python (`validate_archive`, `validate_paths`,
/// `recover_key_ctx`) and the class is renamed to `Archive` via `#[pyclass(name)]`.
#[pymodule]
#[pyo3(name = "rpfkit")]
mod rpfkit_module {
    #[pymodule_export]
    use super::PyArchive;
    #[pymodule_export]
    use super::Rpf9Error;
    #[pymodule_export]
    use super::recover_key_ctx;
    #[pymodule_export]
    use super::validate_archive;
    #[pymodule_export]
    use super::validate_paths;
}
