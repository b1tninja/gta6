//! Clean-room RPF9 (GTA VI Xbox) archive reader in Rust.
//!
//! This crate is a port of the Python package under `gta6/rpf9/`, focused on the
//! extractor core: container framing ([`format`]), TOC entry parsing ([`entries`]),
//! AES-256 / whitened-CBC decryption ([`crypto`]), the archive reader ([`archive`]),
//! and structural validation ([`validate`]).
//!
//! Two reasons the port exists:
//!
//! * **AES-NI** - the `aes` crate emits hardware AES instructions on x86_64, so TOC
//!   decryption is far faster than the pure-Python path.
//! * **Multithreading** - `rayon` parallelises validation across archives and
//!   inflate/write across entries within an archive.
//!
//! The modules mirror their Python counterparts one-for-one so the two stay easy to
//! cross-check.

pub mod archive;
pub mod crypto;
pub mod entries;
pub mod format;
pub mod keys;
pub mod recovery;
pub mod validate;

#[cfg(feature = "python")]
mod python;

pub use archive::{Archive, Decryption};
pub use format::{Header, Rpf9Error};
pub use recovery::{PeView, RecoveredKeyCtx, recover_key_ctx_blob, recover_key_ctx_report};
pub use validate::{ValidationReport, validate_archive, validate_paths};
