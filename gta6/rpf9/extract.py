from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from gta6.config import Gta6Paths, load_paths
from gta6.rpf9.archive import Rpf9Archive


def extract_rpf9(
    archive: Path,
    output_dir: Path,
    *,
    paths: Gta6Paths | None = None,
    decompress: bool = True,
) -> dict[str, object]:
    paths = paths or load_paths()
    paths.ensure_artifact_tree()
    output_dir.mkdir(parents=True, exist_ok=True)
    arc = Rpf9Archive.open(archive)
    manifest: dict[str, object] = {
        "status": "pending",
        "archive": str(archive),
        "output_dir": str(output_dir),
        "header": arc.info(),
        "timestamp": datetime.now(UTC).isoformat(),
    }
    if not arc.toc_readable():
        manifest["status"] = "blocked"
        manifest["reason"] = (
            "encrypted_toc"
            if arc.decryption == "encrypted_no_key"
            else "wrong_aes_key_or_cipher"
        )
        manifest["hint"] = (
            "Xbox leak assets use RPF9 with encrypted file tables. "
            "Keys are expected from game_scarlett_master.exe (missing from this rip). "
            "Set GTA6_AES_KEY_HEX or GTA6_AES_KEY_FILE in .env when a key is known."
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
    out = paths.manifests_dir / f"{archive.stem}-rpf9-extract.json"
    out.write_text(json.dumps(manifest, indent=2), encoding="utf-8")