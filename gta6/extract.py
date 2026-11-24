"""Extract one RPF archive using the native ``rpfkit`` core.

RPF9 (the Xbox Scarlett layout) is handled entirely by the Rust reader: it recovers the
key-context blob from the game executable, decrypts the file tables with the whitened
AES-256-CBC cipher, reconstructs the directory tree and inflates the cleartext data
region. Older RPF versions (RPF7 and below) are not supported by this reader and are
reported as ``blocked`` rather than silently mis-extracted.

The manifest dict is returned and also written under the artifact ``manifests/`` tree so
extraction runs are reproducible and auditable.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from gta6.config import Gta6Paths, load_paths
from gta6.rpf import read_rpf_header
from gta6.rpfkit_native import require_native


def _key_ctx_exe(paths: Gta6Paths) -> Path | None:
    """The exe to recover the whitened-CBC key-context from, if present.

    Prefers ``GTA6_GAME_EXE`` (set in ``.env``); otherwise the conventional
    ``game_scarlett_master.exe`` under the game root. Returns ``None`` when neither
    exists, in which case the reader leaves an encrypted TOC undecrypted.
    """
    exe = paths.game_exe
    return exe if exe.is_file() else None


def extract_rpf(
    archive: Path,
    output_dir: Path,
    *,
    paths: Gta6Paths | None = None,
    decompress: bool = True,
) -> dict[str, object]:
    """Extract ``archive`` into ``output_dir`` with the native reader.

    Returns a manifest dict (also written under ``manifests/``). ``status`` is ``ok``
    when files were written, ``blocked`` when the TOC could not be decrypted (or the
    archive is not RPF9), and ``error`` on an I/O failure.
    """
    paths = paths or load_paths()
    paths.ensure_artifact_tree()
    output_dir.mkdir(parents=True, exist_ok=True)

    native: Any = require_native()
    hdr = read_rpf_header(archive)
    manifest: dict[str, object] = {
        "status": "pending",
        "archive": str(archive),
        "rpf_version": hdr.version,
        "output_dir": str(output_dir),
        "timestamp": datetime.now(UTC).isoformat(),
    }

    if hdr.magic != 0x52504639:
        manifest["status"] = "blocked"
        manifest["reason"] = "not_rpf9"
        manifest["hint"] = (
            "the native reader handles RPF9 (Xbox Scarlett) only; "
            f"this archive is {hdr.version}."
        )
        _write_manifest(paths, archive, manifest)
        return manifest

    key_ctx_exe = _key_ctx_exe(paths)
    try:
        arc = native.Archive(archive, key_ctx_exe=key_ctx_exe)
    except Exception as exc:  # native Rpf9Error (I/O / format)
        manifest["status"] = "error"
        manifest["error"] = str(exc)
        _write_manifest(paths, archive, manifest)
        return manifest

    manifest["header"] = arc.info()
    if not arc.toc_readable:
        manifest["status"] = "blocked"
        manifest["reason"] = (
            "encrypted_toc"
            if arc.decryption == "encrypted_no_key"
            else "wrong_aes_key_or_cipher"
        )
        manifest["hint"] = (
            "the file tables did not decrypt to plausible names. Pass a readable "
            "key-context exe (GTA6_GAME_EXE) or a raw key (GTA6_AES_KEY_HEX); the "
            "whitened-CBC whitening orderings are still being pinned by a dynamic trace."
        )
        _write_manifest(paths, archive, manifest)
        return manifest

    try:
        stats = arc.extract_all(output_dir, decompress=decompress)
    except Exception as exc:
        manifest["status"] = "error"
        manifest["error"] = str(exc)
        _write_manifest(paths, archive, manifest)
        return manifest

    manifest["status"] = "ok"
    manifest["stats"] = stats
    manifest["sample_paths"] = arc.list_paths()[:20]
    _write_manifest(paths, archive, manifest)
    return manifest


def _write_manifest(paths: Gta6Paths, archive: Path, manifest: dict[str, object]) -> None:
    out = paths.manifests_dir / f"{archive.stem}-extract.json"
    out.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
