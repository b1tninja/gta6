# RPF9 container & TOC crypto — public research summary

This is the publishable summary of the RPF9 reverse-engineering work. It describes
the container format and the crypto model in terms of *structure and method*, and
deliberately omits build-specific constants (absolute image addresses, Ghidra
`FUN_`/`DAT_` symbols, and raw key/template bytes) that are quoted in the local
working notes. Those constants are recovered from the executable at run time by the
tooling rather than hard-coded here.

## 1. Container layout

A single `.rpf` file may contain **several concatenated RPF9 archives** ("bases"),
each located by scanning for the `RPF9` magic. Each base is:

```text
┌──────────────────────────────────────────────┐
│ header (32 B)   magic 'RPF9' + sizes + flags  │
├──────────────────────────────────────────────┤
│ TOC || names blob   (ENCRYPTED)                │
├──────────────────────────────────────────────┤
│ data region        (CLEAINTEXT)               │
│   block-aligned raw-deflate streams           │
└──────────────────────────────────────────────┘
```

The header is eight little-endian dwords: magic, TOC byte size, names byte size, an
opaque `encryption` field, two archive-id words, a platform tag and platform flags.

```text
toc_offset  = base + 32
data_offset = toc_offset + toc_byte_size + names_byte_size
```

`is_encrypted_toc` treats the `encryption` field as a flag: zero, or the ASCII
`"OPEN"`, means cleartext; anything else means the TOC blob is encrypted.

## 2. The data region is cleartext

Payloads at block-aligned offsets are raw-deflate streams (zlib `wbits=-15`);
inter-entry padding is literal zeros. **Extracting file content therefore does not
need the key** — only the TOC and name tables do. The in-tree reader inflates the
data region directly.

## 3. Known plaintext in the TOC blob (a key-recovery aid)

The encrypted `TOC || names` blob has a fixed structure at its start:

```text
blob offset
0        16                    64                    toc_size
┌────────┬────────────────────┬──────────────────────┬─ ─ ─ ─ ─ ─ ─┐
│ head   │ 48-BYTE REGION     │ entry table          │  names       │
│ 16 B   │ (constant within   │ (ciphertext)         │  region      │
│ varies │  one build)        │                      │              │
└────────┴────────────────────┴──────────────────────┴─ ─ ─ ─ ─ ─ ─┘
```

- Within one build, the **48-byte region** at a constant offset is byte-identical
  across every archive and base sampled, and some archives also have **long
  all-zero runs** in the names region. Together that is ≥ ~112 bytes of guaranteed
  plaintext per archive, enough to reject a wrong key decisively. The region is
  three *distinct* 16-byte blocks, which is what rules out "AES-ECB of zeros".
- These bytes are **build-specific and are not committed** to the repo. They are a
  *key-recovery* aid: you supply them (from your own survey) to the key sweep, which
  uses them as a known-plaintext oracle. They are deliberately **not** used to decide
  whether an archive is valid — see §3b.

## 3b. Structural validation (build-independent)

Whether an archive is well-formed is checked by *structure*, not by matching any
particular bytes, so the checks stay valid across builds and the eventual production
release. The native reader (`rpfkit validate <archive>`, or
`cargo run -p rpfkit --release -- validate <archive>`) verifies:

- the header is self-consistent (magic, non-zero TOC size, entry count divides the
  TOC size);
- the TOC/names/data regions fit inside the file and the data region is present;
- the entry table is internally coherent (name offsets land inside the names region,
  directory child ranges stay inside the TOC);
- the data region actually inflates (a few sampled payloads are raw-deflate).

None of these depend on the template bytes, so they are the preferred correctness
check.

## 4. Crypto model

### Ruled out

- ✗ **AES-256-ECB of the whole blob** — the template blocks differ, so ECB-of-zeros
  cannot produce them.
- ✗ **One global keystream for all archives** — where plaintext is known equal, the
  ciphertext differs per archive.
- ✗ **Simple header-derived keys** (archive-id / header-dword KDFs) — tested and
  rejected against the template oracle.

### Identified

The cipher is a **table-driven AES-256 with input and output whitening, run in CBC
mode**. It is driven by a precomputed *key-context blob* the game keeps in its
image, laid out as:

```text
+0x0000  initial whitening keys      16 B
+0x0010  round keys                  AES-256: 15 x 16 B
+0x00f0  16 final whitening tables   16 x 256 B = 0x1000
+0x10f0  IV / chaining slot          16 B   (total 0x10f4)
```

Because the whitening is folded into the tables, a plain `AES-256-CBC` from a
standard crypto library will **not** match unless the whitening is reproduced. The
whitened transform is implemented in the native reader (`rpfkit/src/crypto.rs`).

### Recovering the key statically

The key-context blob's **address is build-specific**, so it is not hard-coded. The
tooling recovers it from the executable:

1. Scan the code section for the provider **descriptor getter** (a tiny function
   that returns a pointer to a registry table and stores its entry count). The
   getter's byte pattern is *assembled from mnemonics*, not copied as a literal, so
   it is not tied to one build's encoding.
2. Validate the pointed-to table **structurally** as a crypto provider registry
   (packed key-handle keys, block-cipher-family flags, and a high-entropy key-context
   blob operand).
3. Read the blob operand; its **length is derived from the data**, not matched
   against a fixed constant.

```powershell
rpfkit recover-keyctx game_scarlett_master.exe   # derive the key-context blob address
# or: cargo run -p rpfkit --release -- recover-keyctx game_scarlett_master.exe
```

This recovery runs automatically when the reader lists or extracts an archive (the exe
is read from `GTA6_GAME_EXE`). The earlier known-plaintext key sweep (which used a
build-specific template supplied via `--template-hex` as an oracle, accepting candidate
keys only if they reproduced it under the whitened-CBC model) was part of the Python
research layer that has since been dropped; it is preserved in the git history.

## 5. Open questions

- The exact whitening byte orderings are pinned by a dynamic trace of the AES block
  transform; until that trace is folded in, the whitening/IV fields are read from the
  blob offsets and exposed as overridable fields.
- A second occurrence of the 48-byte region appears deeper in some archives
  (inside the names region) — unexplained; candidates include a second table copy or
  a directory-node marker.
- The semantics of the head dword fields and the `encryption` field beyond the
  encrypted/open test remain open.

## 6. Method note (clean room)

Everything in the `rpfkit/` reader is implemented from observed byte patterns and
format analysis of the archives plus static analysis of the executable — not from any
existing extractor. The bundled `rpf-cli` is RPF7-only and is not used for RPF9.
