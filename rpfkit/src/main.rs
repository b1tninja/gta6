//! Thin CLI over the rpfkit library: info / list / extract / validate.
//!
//! Mirrors the Python `gta6` CLI subcommands. Validation runs across all given paths in
//! parallel (rayon); extraction inflates and writes entries in parallel.

use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use rpfkit::Archive;
use rpfkit::KeySource;
use rpfkit::keys::load_aes_key;
use rpfkit::recovery::PeView;
use rpfkit::validate::validate_paths;

#[derive(Parser)]
#[command(
    name = "rpfkit",
    about = "RPF9 archive reader (AES-NI + multithreaded)"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Print header + decryption state for one archive.
    Info {
        path: PathBuf,
        /// Recover the whitened-CBC key-context from this exe and use it to decrypt.
        #[arg(long)]
        key_ctx: Option<PathBuf>,
    },
    /// List file paths inside one archive (needs a readable TOC).
    List {
        path: PathBuf,
        /// Recover the whitened-CBC key-context from this exe and use it to decrypt.
        #[arg(long)]
        key_ctx: Option<PathBuf>,
    },
    /// Extract every file entry under an output directory.
    Extract {
        path: PathBuf,
        #[arg(long)]
        out: PathBuf,
        /// Skip raw-inflate; write stored bytes as-is.
        #[arg(long)]
        no_decompress: bool,
        /// Recover the whitened-CBC key-context from this exe and use it to decrypt.
        #[arg(long)]
        key_ctx: Option<PathBuf>,
    },
    /// Structurally validate one or more archives (parallel).
    Validate { paths: Vec<PathBuf> },
    /// Recover the AES key-context blob address from the exe (no key material).
    RecoverKeyctx {
        /// Path to game_scarlett_master.exe (or a leaked build).
        exe: PathBuf,
        /// Optional handle filter (e.g. 1 pins the static archive key). Accepts hex (0x…).
        #[arg(long, value_parser = parse_u64_any)]
        handle: Option<u64>,
        /// Optional flags filter (2 is the block-cipher family). Accepts hex (0x…).
        #[arg(long, value_parser = parse_u8_any)]
        flags: Option<u8>,
        /// Also write the JSON report to this path.
        #[arg(long)]
        manifest: Option<PathBuf>,
    },
}

/// Parse a u64 accepting decimal or `0x`-prefixed hex.
fn parse_u64_any(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).map_err(|e| e.to_string())
    } else {
        s.parse::<u64>().map_err(|e| e.to_string())
    }
}

/// Parse a u8 accepting decimal or `0x`-prefixed hex.
fn parse_u8_any(s: &str) -> Result<u8, String> {
    let v = parse_u64_any(s)?;
    u8::try_from(v).map_err(|_| format!("{v} does not fit in u8"))
}

/// Build the key material: a raw key from the environment, plus (optionally) the
/// whitened-CBC key-context blob recovered from `key_ctx_exe`.
fn build_key_source(key_ctx_exe: Option<&Path>) -> KeySource {
    let key = load_aes_key();
    let ctx = key_ctx_exe.and_then(recover_key_ctx_bytes);
    match (key, ctx) {
        (Some(k), Some(c)) => KeySource::both(&k, &c),
        (Some(k), None) => KeySource::from_key(&k),
        (None, Some(c)) => KeySource::from_key_ctx(&c),
        (None, None) => KeySource::default(),
    }
}

/// Recover the key-context blob bytes from an exe (handle=1, flags=2 = static archive key).
fn recover_key_ctx_bytes(exe: &Path) -> Option<Vec<u8>> {
    let view = PeView::open(exe).ok()?;
    let r = rpfkit::recovery::recover_key_ctx_blob(&view, Some(1), Some(2))?;
    view.read_key_ctx_blob(&r)
}

fn main() {
    let cli = Cli::parse();
    let code = run(cli.cmd);
    std::process::exit(code);
}

fn run(cmd: Cmd) -> i32 {
    match cmd {
        Cmd::Info { path, key_ctx } => {
            let key = build_key_source(key_ctx.as_deref());
            match Archive::open(&path, None, &key) {
                Ok(arc) => {
                    let h = &arc.header;
                    println!("path            {}", arc.path.display());
                    println!("base_offset     {}", h.base_offset);
                    println!("toc_byte_size   {}", h.toc_byte_size);
                    println!("names_byte_size {}", h.names_byte_size);
                    println!("entry_count     {}", h.entry_count());
                    println!("encryption      {:#x}", h.encryption);
                    println!(
                        "archive_id      {:#x} {:#x}",
                        h.archive_id.0, h.archive_id.1
                    );
                    println!("decryption      {}", arc.decryption.as_str());
                    println!("toc_readable    {}", arc.toc_readable());
                    println!("data_offset     {}", h.data_offset());
                    0
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    1
                }
            }
        }
        Cmd::List { path, key_ctx } => {
            let key = build_key_source(key_ctx.as_deref());
            match Archive::open(&path, None, &key) {
                Ok(arc) => {
                    if !arc.toc_readable() {
                        eprintln!(
                            "TOC not readable (decryption={}); pass --key-ctx <exe> or set GTA6_AES_KEY_HEX",
                            arc.decryption.as_str()
                        );
                        return 1;
                    }
                    for (_idx, p) in arc.file_paths() {
                        println!("{p}");
                    }
                    0
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    1
                }
            }
        }
        Cmd::Extract {
            path,
            out,
            no_decompress,
            key_ctx,
        } => {
            let key = build_key_source(key_ctx.as_deref());
            match Archive::open(&path, None, &key) {
                Ok(arc) => match arc.extract_all(&out, !no_decompress) {
                    Ok((files, bytes, dirs)) => {
                        println!("extracted {files} files, {bytes} bytes ({dirs} dirs skipped)");
                        0
                    }
                    Err(e) => {
                        eprintln!("error: {e}");
                        1
                    }
                },
                Err(e) => {
                    eprintln!("error: {e}");
                    1
                }
            }
        }
        Cmd::Validate { paths } => {
            let summary = validate_paths(&paths, None);
            for r in &summary.rows {
                let status = if r.ok() { "ok" } else { "FAIL" };
                println!("[{status}] {} base={}", r.path, r.base_offset);
                for c in &r.checks {
                    if !c.ok {
                        println!("    FAIL {} {}", c.name, c.detail);
                    }
                }
                for s in &r.skipped {
                    println!("    skip {s}");
                }
            }
            for (p, e) in &summary.errors {
                println!("[ERR ] {p}: {e}");
            }
            println!(
                "validated {} archives: {} ok, {} failed",
                summary.count, summary.ok, summary.failed
            );
            if summary.failed > 0 { 1 } else { 0 }
        }
        Cmd::RecoverKeyctx {
            exe,
            handle,
            flags,
            manifest,
        } => match rpfkit::recovery::recover_key_ctx_report(&exe, handle, flags) {
            Ok(payload) => {
                println!("{}", serde_json::to_string_pretty(&payload).unwrap());
                if let Some(m) = manifest {
                    if let Some(parent) = m.parent() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                    let _ = std::fs::write(&m, serde_json::to_string_pretty(&payload).unwrap());
                }
                if payload.get("status").and_then(|s| s.as_str()) == Some("ok") {
                    0
                } else {
                    1
                }
            }
            Err(e) => {
                eprintln!("error: {e}");
                1
            }
        },
    }
}
