//! Thin CLI over the rpf9rs library: info / list / extract / validate.
//!
//! Mirrors the Python `gta6` CLI subcommands. Validation runs across all given paths in
//! parallel (rayon); extraction inflates and writes entries in parallel.

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use rpf9rs::Archive;
use rpf9rs::keys::load_aes_key;
use rpf9rs::validate::validate_paths;

#[derive(Parser)]
#[command(name = "rpf9rs", about = "RPF9 archive reader (AES-NI + multithreaded)")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Print header + decryption state for one archive.
    Info { path: PathBuf },
    /// List file paths inside one archive (needs a readable TOC).
    List { path: PathBuf },
    /// Extract every file entry under an output directory.
    Extract {
        path: PathBuf,
        #[arg(long)]
        out: PathBuf,
        /// Skip raw-inflate; write stored bytes as-is.
        #[arg(long)]
        no_decompress: bool,
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

fn main() {
    let cli = Cli::parse();
    let key = load_aes_key();
    let key = key.as_deref();
    let code = run(cli.cmd, key);
    std::process::exit(code);
}

fn run(cmd: Cmd, key: Option<&[u8]>) -> i32 {
    match cmd {
        Cmd::Info { path } => match Archive::open(&path, None, key) {
            Ok(arc) => {
                let h = &arc.header;
                println!("path            {}", arc.path.display());
                println!("base_offset     {}", h.base_offset);
                println!("toc_byte_size   {}", h.toc_byte_size);
                println!("names_byte_size {}", h.names_byte_size);
                println!("entry_count     {}", h.entry_count());
                println!("encryption      {:#x}", h.encryption);
                println!("archive_id      {:#x} {:#x}", h.archive_id.0, h.archive_id.1);
                println!("decryption      {}", arc.decryption.as_str());
                println!("toc_readable    {}", arc.toc_readable());
                println!("data_offset     {}", h.data_offset());
                0
            }
            Err(e) => {
                eprintln!("error: {e}");
                1
            }
        },
        Cmd::List { path } => match Archive::open(&path, None, key) {
            Ok(arc) => {
                if !arc.toc_readable() {
                    eprintln!(
                        "TOC not readable (decryption={}); set GTA6_AES_KEY_HEX",
                        arc.decryption.as_str()
                    );
                    return 1;
                }
                for p in list_paths(&arc) {
                    println!("{p}");
                }
                0
            }
            Err(e) => {
                eprintln!("error: {e}");
                1
            }
        },
        Cmd::Extract {
            path,
            out,
            no_decompress,
        } => match Archive::open(&path, None, key) {
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
        },
        Cmd::Validate { paths } => {
            let summary = validate_paths(&paths, key);
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
            if summary.failed > 0 {
                1
            } else {
                0
            }
        }
        Cmd::RecoverKeyctx {
            exe,
            handle,
            flags,
            manifest,
        } => match rpf9rs::recovery::recover_key_ctx_report(&exe, handle, flags) {
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

/// Walk the directory tree and return file paths (mirrors Python `list_paths`).
fn list_paths(arc: &Archive) -> Vec<String> {
    let mut out = Vec::new();
    walk(arc, 0, "", &mut out);
    out
}

fn walk(arc: &Archive, idx: usize, prefix: &str, out: &mut Vec<String>) {
    let Some(entry) = arc.entries.get(idx) else { return };
    let names = arc.names_plain.as_deref().unwrap_or(&[]);
    if entry.kind == rpf9rs::entries::EntryKind::Directory {
        let name = rpf9rs::entries::read_name(names, entry.name_offset as usize);
        let sub = if name.is_empty() {
            prefix.to_string()
        } else if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        let first = entry.entries_index as usize;
        let count = entry.entries_count as usize;
        for child in first..first + count {
            walk(arc, child, &sub, out);
        }
        return;
    }
    let name = rpf9rs::entries::read_name(names, entry.name_offset as usize);
    let rel = if name.is_empty() {
        format!("entry_{idx:04}")
    } else if prefix.is_empty() {
        name
    } else {
        format!("{prefix}/{name}")
    };
    out.push(rel);
}
