from __future__ import annotations

import importlib.util
import json
import sys
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from gta6.config import Gta6Paths, load_paths
from gta6.rpf import read_rpf_header
from gta6.rpf9.extract import extract_rpf9


def _load_piliii_extract(extractor_dir: Path) -> Any:
    script = extractor_dir / "extract.py"
    if not script.is_file():
        msg = f"Piliii extract.py not found: {script}"
        raise FileNotFoundError(msg)
    spec = importlib.util.spec_from_file_location("piliii_extract", script)
    if spec is None or spec.loader is None:
        msg = f"Could not load module from {script}"
        raise ImportError(msg)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["piliii_extract"] = mod
    spec.loader.exec_module(mod)
    return mod


def extract_rpf(
    archive: Path,
    output_dir: Path,
    *,
    paths: Gta6Paths | None = None,
    progress: Callable[[int, int, str], None] | None = None,
) -> dict[str, object]:
    """
    Run Piliii RPF-Extractor logic headlessly into ``output_dir``.

    Returns a manifest dict (also written under artifact manifests/).
  """
    paths = paths or load_paths()
    paths.ensure_artifact_tree()
    output_dir.mkdir(parents=True, exist_ok=True)

    hdr = read_rpf_header(archive)
    if hdr.magic == 0x52504639:
        return extract_rpf9(archive, output_dir, paths=paths)
    if hdr.magic != 0x52504637:
        manifest: dict[str, object] = {
            "status": "blocked",
            "reason": "rpf_cli_rpf7_only",
            "archive": str(archive),
            "rpf_version": hdr.version,
            "magic_hex": f"0x{hdr.magic:08X}",
            "output_dir": str(output_dir),
            "timestamp": datetime.now(UTC).isoformat(),
        }
        manifest_path = paths.manifests_dir / f"{archive.stem}-extract.json"
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        return manifest

    if not paths.rpf_cli.is_file():
        msg = f"RPF CLI missing: {paths.rpf_cli}"
        raise FileNotFoundError(msg)

    piliii = _load_piliii_extract(paths.rpf_extractor_dir)
    moved, error, _extracted_rpfs = piliii.extract_rpf_recursive(
        str(archive),
        str(paths.rpf_cli),
        str(output_dir),
        "rpf",
        progress,
        is_nested=False,
    )

    manifest = {
        "status": "ok" if error is None and moved else "error",
        "archive": str(archive),
        "rpf_version": hdr.version,
        "output_dir": str(output_dir),
        "moved": moved,
        "error": error,
        "timestamp": datetime.now(UTC).isoformat(),
    }
    manifest_path = paths.manifests_dir / f"{archive.stem}-extract.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest