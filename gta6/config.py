from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

_ENV_LOADED = False


def _ensure_dotenv() -> None:
    global _ENV_LOADED
    if _ENV_LOADED:
        return
    for candidate in (
        Path(__file__).resolve().parent.parent / ".env",
        Path.cwd() / ".env",
    ):
        if candidate.is_file():
            load_dotenv(candidate, override=False)
            break
    else:
        load_dotenv(override=False)
    _ENV_LOADED = True


def _path_from_env(key: str, default: str | None = None) -> Path:
    _ensure_dotenv()
    raw = os.environ.get(key, default)
    if not raw:
        msg = f"Missing required environment variable {key} (set it in .env)"
        raise ValueError(msg)
    return Path(raw).expanduser().resolve()


@dataclass(frozen=True, slots=True)
class Gta6Paths:
    """Resolved paths for game install and out-of-repo artifacts."""

    game_root: Path
    artifact_root: Path
    rpf_cli: Path
    rpf_extractor_dir: Path

    @property
    def extractions_dir(self) -> Path:
        return self.artifact_root / "extractions"

    @property
    def manifests_dir(self) -> Path:
        return self.artifact_root / "manifests"

    @property
    def notes_attachments_dir(self) -> Path:
        return self.artifact_root / "note-attachments"

    def ensure_artifact_tree(self) -> None:
        for d in (
            self.artifact_root,
            self.extractions_dir,
            self.manifests_dir,
            self.notes_attachments_dir,
        ):
            d.mkdir(parents=True, exist_ok=True)


def load_paths() -> Gta6Paths:
    # No defaults: the game install and the RPF-Extractor live outside the repo and
    # differ per machine, so they must come from .env (see .env.example).
    return Gta6Paths(
        game_root=_path_from_env("GTA6_GAME_ROOT"),
        artifact_root=_path_from_env("GTA6_ARTIFACT_ROOT"),
        rpf_cli=_path_from_env("GTA6_RPF_CLI"),
        rpf_extractor_dir=_path_from_env("GTA6_RPF_EXTRACTOR_DIR"),
    )
