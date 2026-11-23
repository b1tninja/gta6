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

## 3. Known plaintext in the TOC blob

The encrypted `TOC || names` blob has a fixed structure at its start:

```text
blob offset
0        16                    64                    toc_size
┌────────┬────────────────────┬──────────────────────┬─ ─ ─ ─ ─ ─ ─┐
│ head   │ 48-BYTE TEMPLATE   │ entry table          │  names       │
│ 16 B   │ (constant, every   │ (ciphertext)         │  region      │
│ varies │  archive/base)     │                      │              │
└────────┴────────────────────┴──────────────────────┴─ ─ ─ ─ ─ ─ ─┘
```

- The **48-byte template** at a constant offset is byte-identical across every
  archive and base sampled. It is the primary known-plaintext anchor.
- Some archives also have **long all-zero runs** in the names region — additional
  guaranteed plaintext.

Together that is ≥ ~112 bytes of guaranteed plaintext per archive (up to ~700 B in
small archives), enough to reject a wrong key decisively. The template is three
*distinct* 16-byte blocks, which is what rules out "AES-ECB of zeros".

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
`WhitenedAesCbc` class in `gta6/rpf9/crypto.py` implements the whitened transform.

### Recovering the key statically

The key-context blob's **address is build-specific**, so it is not hard-coded. The
tooling recovers it from the executable:

1. Scan the code section for the provider **descriptor getter** (a tiny function
   that returns a pointer to a registry table and stores its entry count). The
   getter's byte pattern is *assembled from mnemonics* via keystone, not copied as a
   literal, so it is not tied to one build's encoding.
2. Validate the pointed-to table **structurally** as a crypto provider registry
   (packed key-handle keys, block-cipher-family flags, and a high-entropy key-context
   blob operand).
3. Read the blob operand; its **length is derived from the data**, not matched
   against a fixed constant.

```powershell
python -m gta6 rpf9-recover-keyctx     # derive the key-context blob address
python -m gta6 rpf9-recover-keys       # sweep the exe for the TOC key
```

The known-plaintext template is used as an oracle: candidate keys are accepted only
if they reproduce the template under the whitened-CBC model.

## 5. Open questions

- The exact whitening byte orderings are pinned by a dynamic trace of the AES block
  transform; until that trace is folded in, the whitening/IV fields are read from the
  blob offsets and exposed as overridable fields.
- A second occurrence of the 48-byte template appears deeper in some archives
  (inside the names region) — unexplained; candidates include a second table copy or
  a directory-node marker.
- The semantics of the head dword fields and the `encryption` field beyond the
  encrypted/open test remain open.

## 6. Method note (clean room)

Everything in `gta6/rpf9/` is implemented from observed byte patterns and format
analysis of the archives plus static analysis of the executable — not from any
existing extractor. The bundled `rpf-cli` is RPF7-only and is not used for RPF9.
