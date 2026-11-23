from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from gta6.config import load_paths
from gta6.extract_piliii import extract_rpf
from gta6.rpf import iter_rpf_files, rpf_cli_list, script_archives
from gta6.rpf9.archive import Rpf9Archive
from gta6.rpf9.extract import extract_rpf9
from gta6.rpf9.format import find_rpf9_bases
from gta6.rpf9.keys import load_aes_key, scan_exe_for_key_candidates


def _cmd_paths(_: argparse.Namespace) -> int:
    p = load_paths()
    p.ensure_artifact_tree()
    rows = {
        "game_root": str(p.game_root),
        "artifact_root": str(p.artifact_root),
        "extractions_dir": str(p.extractions_dir),
        "manifests_dir": str(p.manifests_dir),
        "rpf_cli": str(p.rpf_cli),
        "rpf_extractor_dir": str(p.rpf_extractor_dir),
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
    print(rpf_cli_list(p.rpf_cli, arch, pattern=args.pattern))
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


def _cmd_rpf9_info(args: argparse.Namespace) -> int:
    p = load_paths()
    arch = args.archive if args.archive.is_absolute() else p.game_root / args.archive
    data = arch.read_bytes()
    bases = find_rpf9_bases(data)
    infos = []
    for base in bases:
        arc = Rpf9Archive.open(arch, base_offset=base)
        row = arc.info()
        row["paths_found"] = len(arc.list_paths())
        infos.append(row)
    payload = {
        "bases": bases,
        "archives": infos,
        "aes_key_loaded": load_aes_key() is not None,
    }
    print(json.dumps(payload, indent=2))
    return 0


def _cmd_rpf9_extract(args: argparse.Namespace) -> int:
    p = load_paths()
    arch = args.archive if args.archive.is_absolute() else p.game_root / args.archive
    out = (
        args.output
        if args.output and args.output.is_absolute()
        else p.extractions_dir / (args.output or arch.stem)
    )
    manifest = extract_rpf9(
        arch,
        out,
        paths=p,
        decompress=not args.no_decompress,
    )
    print(json.dumps(manifest, indent=2))
    return 0 if manifest.get("status") == "ok" else 1


def _cmd_rpf9_toc_probe(args: argparse.Namespace) -> int:
    from gta6.rpf9.toc_probe import probe_paths

    p = load_paths()
    if args.archives:
        paths = [a if a.is_absolute() else p.game_root / a for a in args.archives]
    else:
        paths = sorted(
            p.game_root.rglob("*.rpf"),
            key=lambda x: x.stat().st_size,
        )[:12]
    print(json.dumps(probe_paths(paths), indent=2))
    return 0


def _cmd_rpf9_validate(args: argparse.Namespace) -> int:
    """Structurally validate archives (header/regions/entry table/inflate)."""
    from gta6.rpf9.validate import validate_paths

    p = load_paths()
    if args.archives:
        paths = [a if a.is_absolute() else p.game_root / a for a in args.archives]
    else:
        paths = sorted(
            p.game_root.rglob("*.rpf"),
            key=lambda x: x.stat().st_size,
        )[:12]
    print(json.dumps(validate_paths(paths), indent=2))
    return 0


def _cmd_rpf9_correlate(args: argparse.Namespace) -> int:
    from gta6.rpf9.correlate import correlate_archives

    p = load_paths()
    if args.archives:
        paths = [a if a.is_absolute() else p.game_root / a for a in args.archives]
    else:
        paths = [
            x
            for x in sorted(p.game_root.rglob("*.rpf"), key=lambda z: z.stat().st_size)
            if x.stat().st_size < 100_000_000
        ]
    print(json.dumps(correlate_archives(paths), indent=2))
    return 0


def _cmd_rpf9_derived_keys(args: argparse.Namespace) -> int:
    from gta6.rpf9.derived_keys import try_derived_keys

    p = load_paths()
    arch = args.archive if args.archive.is_absolute() else p.game_root / args.archive
    print(json.dumps(try_derived_keys(arch), indent=2))
    return 0


def _cmd_rpf9_recover_keys(args: argparse.Namespace) -> int:
    """Sweep the leaked exe for a key that explains the global TOC template."""
    from gta6.rpf9 import toc_key

    p = load_paths()
    if args.exe is None:
        print("pass the exe path (or set GTA6_GAME_EXE)", file=sys.stderr)
        return 1
    exe = args.exe if args.exe.is_absolute() else p.game_root / args.exe
    if not exe.is_file():
        print(f"not found: {exe}", file=sys.stderr)
        return 1
    arch = args.archive if args.archive.is_absolute() else p.game_root / args.archive
    if not args.template_hex:
        print(
            "supply the known-plaintext template with --template-hex "
            "(48 bytes / 96 hex chars from your survey)",
            file=sys.stderr,
        )
        return 1
    try:
        template = bytes.fromhex(args.template_hex)
    except ValueError:
        print("--template-hex must be hex", file=sys.stderr)
        return 1
    nonces: list[tuple[str, bytes]] = [("zero", bytes(16))]
    if arch.is_file():
        nonces = toc_key.standard_nonces(arch.read_bytes()[:32], arch)

    lengths = tuple(int(x) for x in args.key_lengths.split(","))
    workers = args.workers or max(1, min(8, exe.stat().st_size // (16 << 20)))
    hits = toc_key.sweep_file(
        exe,
        template=template,
        nonces=nonces,
        key_lengths=lengths,
        workers=workers,
        stop_after=args.stop_after,
        verbose=True,
    )
    payload = {
        "exe": str(exe),
        "archive": str(arch),
        "template_hex": template.hex(),
        "template_is_three_distinct_blocks": toc_key.TemplateOracle(template).distinct,
        "nonces_tried": [name for name, _ in nonces],
        "key_lengths": list(lengths),
        "hits": [h.as_dict() for h in hits],
    }
    print(json.dumps(payload, indent=2))
    if args.manifest:
        args.manifest.parent.mkdir(parents=True, exist_ok=True)
        args.manifest.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return 0 if hits else 1


def _cmd_rpf9_recover_keyctx(args: argparse.Namespace) -> int:
    """Recover the AES key-context blob address from the exe (no key material).

    Derives the provider-registry table and the AES-256 whitened-CBC key-context blob
    location from the executable itself, so the repo can stay public without committing
    key material or a hard-coded exe pointer.
    """
    from gta6.rpf9 import sbox_key

    p = load_paths()
    exe = args.exe if args.exe.is_absolute() else p.game_root / args.exe
    if not exe.is_file():
        print(f"not found: {exe}", file=sys.stderr)
        return 1
    payload = sbox_key.recover_key_ctx_report(exe, handle=args.handle, flags=args.flags)
    print(json.dumps(payload, indent=2))
    if args.manifest:
        args.manifest.parent.mkdir(parents=True, exist_ok=True)
        args.manifest.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return 0 if payload.get("status") == "ok" else 1


def _cmd_rpf9_hunt_keys(args: argparse.Namespace) -> int:
    from gta6.rpf9.key_hunt import load_toc_and_names, trial_keys_on_archive

    p = load_paths()
    arch = args.archive if args.archive.is_absolute() else p.game_root / args.archive
    tail, names = load_toc_and_names(arch)
    hits = trial_keys_on_archive(args.binary, tail, names, limit=args.limit)
    print(
        json.dumps(
            {
                "binary": str(args.binary),
                "archive": str(arch),
                "tail_bytes": len(tail),
                "names_bytes": len(names),
                "candidates_tried": args.limit,
                "hits": hits,
            },
            indent=2,
        )
    )
    return 0 if hits else 1


def _cmd_rpf9_xor_survey(args: argparse.Namespace) -> int:
    from gta6.rpf9.xor_analysis import analyze

    p = load_paths()
    if args.archives:
        paths = [a if a.is_absolute() else p.game_root / a for a in args.archives]
    else:
        paths = [
            p
            for p in sorted(p.game_root.rglob("*.rpf"), key=lambda x: x.stat().st_size)
            if p.stat().st_size < 50_000_000
        ][:32]
    print(json.dumps(analyze(paths), indent=2))
    return 0


def _cmd_rpf9_trial_keys(args: argparse.Namespace) -> int:
    import os

    p = load_paths()
    arch = args.archive if args.archive.is_absolute() else p.game_root / args.archive
    candidates = scan_exe_for_key_candidates(args.exe, limit=args.limit)
    best: list[dict[str, object]] = []
    from gta6.rpf9.crypto import decrypt_toc_and_names
    from gta6.rpf9.entries import names_plausibility

    data = arch.read_bytes()
    arc = Rpf9Archive.open(arch)
    blob = data[arc.header.toc_offset : arc.header.data_offset]
    for idx, key in enumerate(candidates):
        plain = decrypt_toc_and_names(blob, key)
        names = plain[arc.header.toc_byte_size :]
        score = names_plausibility(names)
        if score > 0.5:
            best.append({"index": idx, "score": score, "key_hex": key.hex()})
    print(json.dumps({"tried": len(candidates), "hits": best}, indent=2))
    if best:
        os.environ["GTA6_AES_KEY_HEX"] = str(best[0]["key_hex"])
        print("# best key exported to GTA6_AES_KEY_HEX for this process only", file=sys.stderr)
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


def _cmd_net_offline(args: argparse.Namespace) -> int:
    """Block all outbound traffic for one exe, run it, and wait for it to exit."""
    from gta6 import net_offline

    forwarded: list[str] = []
    if args.block_only:
        forwarded.append("--block-only")
    if args.unblock_only:
        forwarded.append("--unblock-only")
    if args.keep:
        forwarded.append("--keep")
    if args.no_elevate:
        forwarded.append("--no-elevate")
    if args.timeout is not None:
        forwarded += ["--timeout", str(args.timeout)]
    if args.exe is not None:
        forwarded += ["--exe", str(args.exe)]
    if args.prog_args:
        # The child's own flags follow "--" so they never hit our option table.
        forwarded += ["--", *args.prog_args]
    return net_offline.main(forwarded)


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    # Everything after the first "--" is the child program's command line (only
    # net-offline has one). Splice it out before parsing and hand it to the
    # subcommand verbatim, so a child flag like "-n 2" never reaches argparse.
    prog_args: list[str] = []
    if "--" in argv:
        i = argv.index("--")
        prog_args = argv[i + 1 :]
        argv = argv[:i]

    parser = argparse.ArgumentParser(prog="gta6", description="GTA VI RE helpers")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("paths", help="Print resolved .env paths").set_defaults(
        func=_cmd_paths
    )

    inv = sub.add_parser("inventory", help="List .rpf files under game root")
    inv.add_argument("--scripts-only", action="store_true")
    inv.set_defaults(func=_cmd_inventory)

    info = sub.add_parser("rpf-info", help="Run rpf-cli list (with RPF9 detection)")
    info.add_argument("archive", type=Path)
    info.add_argument("pattern", nargs="?", default=None)
    info.set_defaults(func=_cmd_rpf_info)

    ext = sub.add_parser("extract-rpf", help="Extract one archive via Piliii + rpf-cli")
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

    r9info = sub.add_parser("rpf9-info", help="Parse RPF9 header / decryption state")
    r9info.add_argument("archive", type=Path)
    r9info.set_defaults(func=_cmd_rpf9_info)

    r9ext = sub.add_parser("rpf9-extract", help="Extract via in-tree RPF9 reader")
    r9ext.add_argument("archive", type=Path)
    r9ext.add_argument("-o", "--output", type=Path, default=None)
    r9ext.add_argument("--no-decompress", action="store_true")
    r9ext.set_defaults(func=_cmd_rpf9_extract)

    trial = sub.add_parser(
        "rpf9-trial-keys",
        help="Try AES key candidates from a Scarlett exe against one archive TOC",
    )
    trial.add_argument("exe", type=Path)
    trial.add_argument("archive", type=Path)
    trial.add_argument("--limit", type=int, default=50)
    trial.set_defaults(func=_cmd_rpf9_trial_keys)

    xor_survey = sub.add_parser(
        "rpf9-xor-survey",
        help="XOR/compare encrypted TOC regions across archives",
    )
    xor_survey.add_argument(
        "archives",
        nargs="*",
        type=Path,
        help="Optional paths (default: 24 smallest .rpf)",
    )
    xor_survey.set_defaults(func=_cmd_rpf9_xor_survey)

    probe = sub.add_parser("rpf9-toc-probe", help="Parse cleartext TOC head + regions")
    probe.add_argument("archives", nargs="*", type=Path)
    probe.set_defaults(func=_cmd_rpf9_toc_probe)

    validate = sub.add_parser(
        "rpf9-validate",
        help="Structurally validate archives (no build-specific bytes)",
    )
    validate.add_argument(
        "archives",
        nargs="*",
        type=Path,
        help="Optional paths (default: 12 smallest .rpf)",
    )
    validate.set_defaults(func=_cmd_rpf9_validate)

    hunt = sub.add_parser(
        "rpf9-hunt-keys",
        help="Heuristic AES key scan from a PE against TOC tail + names",
    )
    hunt.add_argument("binary", type=Path)
    hunt.add_argument("archive", type=Path)
    hunt.add_argument("--limit", type=int, default=2000)
    hunt.set_defaults(func=_cmd_rpf9_hunt_keys)

    corr = sub.add_parser("rpf9-correlate", help="Correlate cleartext TOC head vs header fields")
    corr.add_argument("archives", nargs="*", type=Path)
    corr.set_defaults(func=_cmd_rpf9_correlate)

    derived = sub.add_parser(
        "rpf9-derived-keys",
        help="Try AES keys derived from header / filename material",
    )
    derived.add_argument("archive", type=Path)
    derived.set_defaults(func=_cmd_rpf9_derived_keys)

    recover = sub.add_parser(
        "rpf9-recover-keys",
        help="Sweep the exe for the TOC key using a known-plaintext template",
    )
    recover.add_argument("exe", type=Path, nargs="?", default=None)
    recover.add_argument(
        "archive",
        type=Path,
        nargs="?",
        default=Path("pack/story000/story000_script.rpf"),
    )
    recover.add_argument(
        "--template-hex",
        default=None,
        help="known-plaintext template, 96 hex chars (48 bytes) from your survey",
    )
    recover.add_argument("--key-lengths", default="32,24,16", help="comma list, e.g. 32")
    recover.add_argument(
        "--workers",
        type=int,
        default=0,
        help="0 = one per 16 MB of the exe, capped at 8",
    )
    recover.add_argument("--stop-after", type=int, default=0, help="0 = scan the whole exe")
    recover.add_argument("--manifest", type=Path, default=None)
    recover.set_defaults(func=_cmd_rpf9_recover_keys)

    keyctx = sub.add_parser(
        "rpf9-recover-keyctx",
        help="Recover the AES key-context blob address from the exe (no key material)",
    )
    keyctx.add_argument(
        "exe", type=Path, nargs="?", default=Path("game_scarlett_master.exe")
    )
    keyctx.add_argument(
        "--handle",
        type=lambda s: int(s, 0),
        default=1,
        help="provider key handle (default 0x1, the static archive key)",
    )
    keyctx.add_argument(
        "--flags",
        type=lambda s: int(s, 0),
        default=2,
        help="registry flags nibble (default 2 = block-cipher family)",
    )
    keyctx.add_argument("--manifest", type=Path, default=None)
    keyctx.set_defaults(func=_cmd_rpf9_recover_keyctx)

    offline = sub.add_parser(
        "net-offline",
        help="Block all outbound network traffic for an exe, run it, wait for exit",
    )
    offline.add_argument(
        "--exe",
        type=Path,
        default=None,
        help="program to block and run (default: GTA6_GAME_EXE / game root)",
    )
    offline.add_argument("--block-only", action="store_true")
    offline.add_argument("--unblock-only", action="store_true")
    offline.add_argument("--keep", action="store_true", help="leave the rules in place")
    offline.add_argument("--no-elevate", action="store_true", help="skip the UAC relaunch")
    offline.add_argument("--timeout", type=float, default=None)
    offline.set_defaults(func=_cmd_net_offline)

    args = parser.parse_args(argv)
    args.prog_args = prog_args
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())