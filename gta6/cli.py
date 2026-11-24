from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from gta6.config import load_paths
from gta6.extract import extract_rpf, extract_scripts
from gta6.rpf import iter_rpf_files, script_archives
from gta6.rpfkit_native import require_native


def _cmd_paths(_: argparse.Namespace) -> int:
    p = load_paths()
    p.ensure_artifact_tree()
    rows = {
        "game_root": str(p.game_root),
        "artifact_root": str(p.artifact_root),
        "extractions_dir": str(p.extractions_dir),
        "manifests_dir": str(p.manifests_dir),
        "rpf_output_root": str(p.rpf_output_root),
        "game_exe": str(p.game_exe),
    }
    print(json.dumps(rows, indent=2))
    return 0


def _cmd_inventory(args: argparse.Namespace) -> int:
    p = load_paths()
    if args.scripts_only:
        archives = script_archives(p.game_root)
    else:
        archives = iter_rpf_files(p.game_root)
    for arch in archives:
        print(arch)
    print(f"# total: {len(archives)}", file=sys.stderr)
    return 0


def _cmd_rpf_info(args: argparse.Namespace) -> int:
    p = load_paths()
    arch = args.archive if args.archive.is_absolute() else p.game_root / args.archive
    native = require_native()
    key_ctx_exe = p.game_exe if p.game_exe.is_file() else None
    arc = native.Archive(arch, key_ctx_exe=key_ctx_exe)
    paths = arc.list_paths()
    if args.pattern:
        paths = [x for x in paths if args.pattern in x]
    print(json.dumps({"info": arc.info(), "paths": paths}, indent=2))
    return 0


def _cmd_extract_rpf(args: argparse.Namespace) -> int:
    p = load_paths()
    arch = args.archive if args.archive.is_absolute() else p.game_root / args.archive
    out = (
        args.output
        if args.output and args.output.is_absolute()
        else p.extractions_dir / (args.output or arch.stem)
    )
    manifest = extract_rpf(arch, out)
    print(json.dumps(manifest, indent=2))
    return 0 if manifest.get("status") == "ok" else 1


def _cmd_rpf9_extract(args: argparse.Namespace) -> int:
    p = load_paths()
    arch = args.archive if args.archive.is_absolute() else p.game_root / args.archive
    out = (
        args.output
        if args.output and args.output.is_absolute()
        else p.extractions_dir / (args.output or arch.stem)
    )
    manifest = extract_rpf(
        arch,
        out,
        paths=p,
        decompress=not args.no_decompress,
    )
    print(json.dumps(manifest, indent=2))
    return 0 if manifest.get("status") == "ok" else 1


def _cmd_extract_scripts(args: argparse.Namespace) -> int:
    """Extract every script archive into rpf_output_root (raw-data dump if TOC encrypted)."""
    manifests = extract_scripts(inflate_each=not args.raw)
    for m in manifests:
        print(json.dumps(m, indent=2))
    # Non-zero only if every archive errored; a raw-data dump counts as success.
    if manifests and all(m.get("status") == "error" for m in manifests):
        return 1
    return 0


def _cmd_extract_install(args: argparse.Namespace) -> int:
    """Extract script RPFs first, then any other paths passed on CLI."""
    p = load_paths()
    targets: list = list(args.only) if args.only else script_archives(p.game_root)
    if not targets:
        print("No archives matched.", file=sys.stderr)
        return 1
    exit_code = 0
    for rel in targets:
        arch = rel if rel.is_absolute() else p.game_root / rel
        out = p.extractions_dir / arch.relative_to(p.game_root).with_suffix("")
        manifest = extract_rpf(arch, out)
        print(json.dumps(manifest, indent=2))
        if manifest.get("status") != "ok":
            exit_code = 1
    return exit_code


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    parser = argparse.ArgumentParser(prog="gta6", description="GTA VI RE helpers")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("paths", help="Print resolved .env paths").set_defaults(
        func=_cmd_paths
    )

    inv = sub.add_parser("inventory", help="List .rpf files under game root")
    inv.add_argument("--scripts-only", action="store_true")
    inv.set_defaults(func=_cmd_inventory)

    info = sub.add_parser("rpf-info", help="List an archive via the native rpfkit reader")
    info.add_argument("archive", type=Path)
    info.add_argument("pattern", nargs="?", default=None)
    info.set_defaults(func=_cmd_rpf_info)

    ext = sub.add_parser("extract-rpf", help="Extract one archive via the native rpfkit reader")
    ext.add_argument("archive", type=Path)
    ext.add_argument("-o", "--output", type=Path, default=None)
    ext.set_defaults(func=_cmd_extract_rpf)

    bulk = sub.add_parser(
        "extract-install",
        help="Batch extract (default: every *script*.rpf under game root)",
    )
    bulk.add_argument(
        "only",
        nargs="*",
        type=Path,
        help="Optional relative paths; default is script archives",
    )
    bulk.set_defaults(func=_cmd_extract_install)

    r9ext = sub.add_parser("rpf9-extract", help="Extract via the native rpfkit reader")
    r9ext.add_argument("archive", type=Path)
    r9ext.add_argument("-o", "--output", type=Path, default=None)
    r9ext.add_argument("--no-decompress", action="store_true")
    r9ext.set_defaults(func=_cmd_rpf9_extract)

    scr = sub.add_parser(
        "extract-scripts",
        help="Extract every *script*.rpf into rpf_output_root "
        "(raw-data dump while the TOC is encrypted)",
    )
    scr.add_argument(
        "--raw",
        action="store_true",
        help="Copy the data region verbatim instead of carving each deflate stream",
    )
    scr.set_defaults(func=_cmd_extract_scripts)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
