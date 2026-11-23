# Instructions for coding agents

`gta6` is a Python 3.12+ notes and tooling repo for GTA VI reverse engineering.

## Commands

Run from `D:\code\gta6` only (do not lint the parent `D:\code` tree).

```
python -m pip install -e ".[dev]"
python -m gta6 paths
python -m gta6 inventory --scripts-only
python -m gta6 rpf9-info pack\\story000\\story000_script.rpf
python -m gta6 rpf9-extract pack\\story000\\story000_script.rpf
python -m pytest -q
python -m ruff check .
```

## Invariants

- **Never** commit game install files or extraction output. `GTA6_ARTIFACT_ROOT` (from `.env`) is the only place for artifacts.
- `.env` is local; `.env.example` documents variables.
- Xbox VI `.rpf` files are **RPF9**; bundled `rpf-cli` is RPF7-only — document blockers in manifests, do not pretend extraction succeeded.

## Finding work

If the person gave you a task, do that task here. Otherwise ask what to work on next (RPF9 tooling, script bytecode, note templates).