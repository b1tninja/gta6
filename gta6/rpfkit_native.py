"""Thin bridge to the native ``rpfkit`` extension module.

The Rust crate under ``rpfkit/`` is the AES-NI, multithreaded RPF9 reader. It is built
separately with maturin (see ``rpfkit/pyproject.toml``) and imported as ``rpfkit``. This
module centralises the import so the rest of the package has one place to go through the
native core, and degrades with a clear message when the extension is not installed.

The native module is required for the info/extract commands. They surface this
module's :func:`require_native` error when it is missing.
"""

from __future__ import annotations

from typing import Any

_MISSING = (
    "the native `rpfkit` module is not installed; build it with "
    "`maturin develop --release` from the rpfkit/ directory "
    "(see rpfkit/README.md)"
)

try:  # pragma: no cover - exercised by whichever branch the environment has
    import rpfkit as _native
except ImportError:  # pragma: no cover
    _native = None


def available() -> bool:
    """True when the native extension module is importable."""
    return _native is not None


def require_native() -> Any:
    """Return the native module, raising a clear ImportError when it is absent."""
    if _native is None:  # pragma: no cover
        raise ImportError(_MISSING)
    return _native
