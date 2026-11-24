# rpfkit

Native RPF9 (GTA VI Xbox) archive reader — the AES-NI, multithreaded core behind the
`gta6` tooling. Rust crate with an optional pyo3 extension module.

## What it does

Reads RPF9 archives (the Xbox Scarlett container format): parses the header and TOC,
decrypts the file tables with the whitened AES-256-CBC cipher driven by a key-context
blob recovered from the game executable, reconstructs the directory tree, and extracts
file payloads (raw-inflating the cleartext deflate data region). Validation checks the
container *structure* (header self-consistency, region bounds, entry-table coherence,
data-region inflate) rather than build-specific bytes.

## CLI

```
cargo build --release
./target/release/rpfkit info   <archive.rpf> [--key-ctx <game.exe>]
./target/release/rpfkit list   <archive.rpf> [--key-ctx <game.exe>]
./target/release/rpfkit extract <archive.rpf> --out <dir> [--key-ctx <game.exe>]
./target/release/rpfkit validate <archive.rpf> [...]
./target/release/rpfkit recover-keyctx <game.exe> [--handle 1] [--flags 2]
```

`--key-ctx <exe>` recovers the key-context blob from the executable and decrypts with
the whitened cipher. A raw key (ECB hypothesis) can be supplied via `GTA6_AES_KEY_HEX`
/ `GTA6_AES_KEY_FILE`; when both are present the whitened cipher is tried first.

## Python bindings

Built with maturin (see `pyproject.toml`):

```
maturin develop --release     # installs the `rpfkit` module into the active venv
```

```python
import rpfkit
arc = rpfkit.Archive("appdata0.rpf", key_ctx_exe="game_scarlett_master.exe")
print(arc.info())              # header + decryption state
print(arc.list_paths()[:20])   # needs a readable TOC
arc.extract_all("out/")        # -> {files, bytes, skipped_dirs}
rpfkit.validate_paths(["a.rpf", "b.rpf"], key_ctx_exe="game_scarlett_master.exe")
rpfkit.recover_key_ctx("game_scarlett_master.exe", handle=1, flags=2)
```

## Status

The whitened-CBC cipher runs end-to-end, but real archives currently report
`wrong_key`: the whitening byte orderings are still being pinned by a dynamic trace of
the AES block transform (see `../docs/rpf9-research.md`). The names-plausibility oracle
is the acceptance gate, so an unproven model degrades to `wrong_key` rather than
producing garbage.
