# gta6

Tools and reverse-engineering notes for **GTA VI** (current focus: the Xbox Series
install layout). This repository is dedicated to **clean-room** tooling: the RPF9
reader/extractor under `gta6/rpf9/` is written from observed file behaviour and
format analysis, not derived from any existing extractor.

Game files and extracted output stay **outside** this repository. Paths come from
`.env` (see `.env.example`). No game data, keys, or extraction output is committed.

## Setup

```powershell
cd D:\code\gta6
python -m venv .venv
.\.venv\Scripts\pip install -e ".[dev]"
copy .env.example .env
# edit .env if your game or artifact root differs
```

Optional extras:

- `.[crypto]` — `cryptography`, used for the AES fast paths.
- `.[disasm]` — `capstone` + `keystone-engine`, used by the key-context recovery
  tool to assemble/disassemble byte patterns. The module degrades gracefully
  without them.

## Paths

```powershell
python -m gta6 paths
```

Default artifact tree (created on demand):

- `GTA6_ARTIFACT_ROOT/extractions/` — RPF extract output
- `GTA6_ARTIFACT_ROOT/manifests/` — JSON logs per extraction
- `GTA6_ARTIFACT_ROOT/note-attachments/` — blobs linked from notes

## Inventory

```powershell
python -m gta6 inventory --scripts-only
```

## Extraction

### Piliii RPF-Extractor (RPF7)

Headless wrapper around the bundled `extract.py` and `rpf-cli.exe`:

```powershell
python -m gta6 extract-rpf pack\story000\story000_script.rpf
python -m gta6 extract-install
```

`rpf-cli` is RPF7-only; it does not understand the Xbox RPF9 layout.

### RPF9 (in-tree, clean-room)

Xbox builds use **RPF9** (magic `0x52504639`). The in-tree reader parses the
container, entry table and name table, and inflates the (cleartext) data region:

```powershell
python -m gta6 rpf9-info     pack\story000\story000_script.rpf
python -m gta6 rpf9-extract  pack\story000\story000_script.rpf
python -m gta6 rpf9-validate pack\story000\story000_script.rpf
```

`rpf9-validate` checks an archive **structurally** (header self-consistency, region
bounds, entry-table coherence, and that the data region inflates). It does not match
any build-specific bytes, so it stays valid across builds and the production release.

The TOC and name tables are **encrypted** on this retail layout. Set
`GTA6_AES_KEY_HEX` (hex) or `GTA6_AES_KEY_FILE` (raw key file) in `.env` once a
key is known; without it, `rpf9-extract` reports the archive as `blocked` and
lists the data region only.

## Key recovery

The archive cipher is a table-driven **AES-256 with input/output whitening in CBC
mode**, driven by a precomputed key-context blob the game keeps in its image. The
blob's *address* is build-specific, so it is recovered from the executable rather
than hard-coded:

```powershell
python -m gta6 rpf9-recover-keyctx        # derive the key-context blob address
python -m gta6 rpf9-recover-keys --template-hex <96 hex chars>   # sweep for the TOC key
```

`rpf9-recover-keys` uses a known-plaintext region as an oracle. Those bytes are
build-specific and are **not** committed; pass the 48-byte region (96 hex chars) from
your own survey with `--template-hex`.

`rpf9-recover-keyctx` locates the blob by scanning for the provider descriptor
getter and validating the registry structurally (the getter byte pattern is
assembled via keystone; the blob length is derived from the data). No key bytes or
absolute addresses are stored in this repo — they are read from the exe at run time.

## Offline run helper

```powershell
python -m gta6 net-offline -- --timeout 600
```

Blocks all outbound traffic for the game executable (Windows Firewall rules, with
self-elevation), launches it, and waits for it to exit — used to observe the game's
behaviour with no network access.

## Research notes

A publishable summary of the RPF9 findings lives in
[docs/rpf9-research.md](docs/rpf9-research.md) - container layout, structural
validation, the known-plaintext key-recovery model, what was ruled out, and the
key-recovery method, described without build-specific constants.

The day-to-day working notes under docs/notes/ are kept local and **not**
published, because they quote build-specific static addresses, Ghidra symbols, and
raw key/template bytes lifted from the proprietary executable.

### What is known (summary)

- **Container:** a file may hold several concatenated RPF9 archives ("bases"),
  found by scanning for the magic. Each base is a 32-byte header, an encrypted
  `TOC || names` blob, then a **cleartext** data region of raw-deflate streams.
- **Data region is cleartext**, so file *content* extraction does not need the key;
  only the TOC/name tables do.
- **Known plaintext (key-recovery aid):** within one build the TOC blob has a fixed
  48-byte region at a constant offset, plus (in some archives) long all-zero name
  runs — enough guaranteed plaintext to reject wrong keys. These bytes are
  build-specific and not committed; they feed the key sweep, not the validity check.
- **Validity is structural:** `rpf9-validate` confirms an archive is well-formed from
  its header, region bounds, entry table and inflate behaviour — no byte matching, so
  it holds across builds.
- **Ruled out:** plain AES-256-ECB of the whole blob, a single global keystream, and
  simple header-derived keys.
- **Identified:** whitened AES-256-CBC (above). Key recovery is the remaining step.

## Layout

```text
gta6/
  rpf9/            clean-room RPF9 reader (format, entries, crypto, extract)
  cli.py           `python -m gta6 ...` entry point
  net_offline.py   offline run helper
tests/             unit tests (synthetic fixtures; no game data)
docs/notes/        local research notes (gitignored)
tools/             one-off probe scripts (gitignored)
```

## License

Apache-2.0. See `LICENSE`. Game assets and the executable are trademarks/copyright
of their respective owners and are **not** included in this repository.
