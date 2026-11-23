"""Block all network traffic for one process, run it, and wait for it to exit.

The point is the experiment behind ``docs/notes/2026-11-23-exe-networking.md``:
the exe links WinHTTP, Winsock and libHttpClient, so the only reliable way to
prove what happens offline is to deny the *process* every outbound flow, launch
it, and watch.

The block is a set of Windows Firewall rules scoped by application path, which
is what makes it follow the game no matter which child process ends up owning
the sockets. ``netsh`` is used rather than the ``NetSecurity`` cmdlets so the
script also works on builds where those cmdlets are slow or unavailable.

Requires elevation (``netsh advfirewall`` writes need admin).

Usage:
    python -m gta6 net-offline                      # the exe from GTA6_GAME_EXE
    python -m gta6 net-offline -- "D:\\game\\game_scarlett_master.exe" -someArg
    python -m gta6 net-offline --block-only
    python -m gta6 net-offline --unblock-only
"""

from __future__ import annotations

import argparse
import ctypes
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

GROUP = "gta6-net-offline"  # reserved; netsh on this build rejects `group=` in add rule
RULE_TCP = "gta6 offline (block outbound TCP)"
RULE_UDP = "gta6 offline (block outbound UDP)"
RULE_ICMP = "gta6 offline (block outbound ICMPv4)"
RULE_ICMP6 = "gta6 offline (block outbound ICMPv6)"

# TCP + UDP alone still lets ping.exe through, because ICMP is its own protocol
# number in the WFP filter rather than a transport port. (Caveat found by test:
# on this build an ICMPv4 rule scoped by *program* is listed by netsh yet does
# not drop ping.exe's traffic, whereas the same TCP rule does block curl.exe.
# ICMP is therefore best-effort; the TCP/UDP pair is what the game experiment
# actually depends on.)
RULES: tuple[tuple[str, str], ...] = (
    ("TCP", RULE_TCP),
    ("UDP", RULE_UDP),
    ("ICMPv4", RULE_ICMP),
    ("ICMPv6", RULE_ICMP6),
)

# Where the exe lives when the command line does not say. GTA6_GAME_EXE wins;
# otherwise fall back to the known name inside GTA6_GAME_ROOT.
GAME_EXE_NAMES = ("game_scarlett_master.exe",)


def default_game_exe() -> Path | None:
    """Resolve the game executable from the environment, or None."""
    raw = os.environ.get("GTA6_GAME_EXE", "").strip()
    if raw:
        return Path(raw).expanduser()
    try:
        from gta6.config import load_paths

        root = load_paths().game_root
    except (OSError, ValueError):
        return None
    for name in GAME_EXE_NAMES:
        candidate = root / name
        if candidate.is_file():
            return candidate
    return None


@dataclass(frozen=True)
class Result:
    """Outcome of one ``netsh`` invocation."""

    argv: list[str]
    code: int
    out: str

    @property
    def ok(self) -> bool:
        return self.code == 0


def _is_admin() -> bool:
    if not sys.platform.startswith("win"):
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except OSError:
        return False


def _run(argv: list[str]) -> Result:
    proc = subprocess.run(
        argv,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    out = (proc.stdout or "") + (proc.stderr or "")
    return Result(argv=argv, code=proc.returncode, out=out.strip())


def _rule_exists(name: str) -> bool:
    res = _run(["netsh", "advfirewall", "firewall", "show", "rule", f"name={name}"])
    return res.ok and "No rules match" not in res.out


def block(exe: str, *, verbose: bool = True) -> list[Result]:
    """Add outbound block rules for *exe*. Idempotent: existing rules are replaced."""
    results: list[Result] = []
    for proto, rule in RULES:
        if _rule_exists(rule):
            results.append(_run(_unblock_argv(rule)))
        results.append(
            _run(
                [
                    "netsh",
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    f"name={rule}",
                    "dir=out",
                    "action=block",
                    "enable=yes",
                    f"protocol={proto}",
                    f"program={exe}",
                    "description=Added by `python -m gta6 net-offline`.",
                ]
            )
        )
        if verbose:
            last = results[-1]
            flag = "ok" if last.ok else f"FAILED rc={last.code}"
            print(f"  block {proto:3s} {exe}  [{flag}]", file=sys.stderr)
            if not last.ok:
                print(f"    {last.out}", file=sys.stderr)
    return results


def _unblock_argv(rule: str) -> list[str]:
    return ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule}"]


def unblock(*, verbose: bool = True) -> list[Result]:
    """Remove the rules this script adds. Safe to call when they are absent."""
    results: list[Result] = []
    for rule in (r for _, r in RULES):
        if not _rule_exists(rule):
            if verbose:
                print(f"  no rule to remove: {rule}", file=sys.stderr)
            continue
        res = _run(_unblock_argv(rule))
        results.append(res)
        if verbose:
            flag = "ok" if res.ok else f"FAILED rc={res.code}"
            print(f"  unblock {rule}  [{flag}]", file=sys.stderr)
    return results


def run_blocked(exe: str, args: list[str], *, timeout: float | None) -> int:
    """Launch *exe* with *args* and wait for it to exit. Returns its exit code.

    stdout/stderr are inherited so the program's own output is visible, but that
    also means a GUI exe with no console shows nothing -- rely on the exit code
    and on whatever log files it writes next to itself.
    """
    argv = [exe, *args]
    print(f"  launching: {' '.join(argv)}", file=sys.stderr)
    started = time.monotonic()
    proc = subprocess.Popen(argv)
    if timeout is None:
        return proc.wait()
    try:
        code = proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        print(f"  timeout after {timeout:.0f}s; terminating", file=sys.stderr)
        proc.terminate()
        try:
            code = proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            proc.kill()
            code = proc.wait()
    print(
        f"  exited code={code} after {time.monotonic() - started:.1f}s",
        file=sys.stderr,
    )
    return code


def _split_child(argv: list[str]) -> tuple[list[str], list[str]]:
    """Split our own flags from the child's, at the first ``--``.

    Everything after the separator belongs to the program being run, so it is
    never seen by our option table (the child's ``-n 2`` must not collide with
    our flags).
    """
    if "--" in argv:
        i = argv.index("--")
        return argv[:i], argv[i + 1 :]
    return argv, []


def _self_reexec_elevated(argv: list[str]) -> int:
    """Relaunch this script through a UAC prompt and return its exit code.

    ``netsh advfirewall`` writes fail without elevation, so the reusable entry
    point offers one instead of failing. ``ShellExecuteExW`` with ``runas``
    gives the child a console of its own; its exit code is harvested from the
    process handle. The relaunch carries ``--no-elevate`` so that if UAC is
    declined the child reports the failure instead of prompting forever.
    """
    if not _is_admin():
        print("requesting elevation (UAC prompt)...", file=sys.stderr)
        sys.stderr.flush()

    class SHELLEXECUTEINFO(ctypes.Structure):
        _fields_ = [
            ("cbSize", ctypes.c_ulong),
            ("fMask", ctypes.c_ulong),
            ("hwnd", ctypes.c_void_p),
            ("lpVerb", ctypes.c_wchar_p),
            ("lpFile", ctypes.c_wchar_p),
            ("lpParameters", ctypes.c_wchar_p),
            ("lpDirectory", ctypes.c_wchar_p),
            ("nShow", ctypes.c_int),
            ("hInstApp", ctypes.c_void_p),
            ("lpIDList", ctypes.c_void_p),
            ("lpClass", ctypes.c_wchar_p),
            ("hkeyClass", ctypes.c_void_p),
            ("dwHotKey", ctypes.c_ulong),
            ("hIcon", ctypes.c_void_p),
            ("hProcess", ctypes.c_void_p),
        ]

    SEE_MASK_NOCLOSEPROCESS = 0x00000040
    see = ["--no-elevate"] if "--no-elevate" not in argv else []
    our_flags, child = _split_child(argv)
    # --no-elevate goes at the end of our flags, before the child's "--", so it
    # can never be mistaken for one of the program's arguments.
    params = subprocess.list2cmdline([*our_flags, *see, *(["--", *child] if child else [])])
    info = SHELLEXECUTEINFO()
    info.cbSize = ctypes.sizeof(SHELLEXECUTEINFO)
    info.fMask = SEE_MASK_NOCLOSEPROCESS
    info.lpVerb = "runas"
    info.lpFile = sys.executable
    info.lpParameters = params
    info.lpDirectory = os.getcwd()
    info.nShow = 1  # SW_SHOWNORMAL
    print(
        f"  relaunching elevated: {sys.executable} -m gta6 net-offline {params}",
        file=sys.stderr,
    )
    sys.stderr.flush()
    if not ctypes.windll.shell32.ShellExecuteExW(ctypes.byref(info)):
        err = ctypes.GetLastError()
        # 1223 = ERROR_CANCELLED, i.e. the user pressed No at the UAC prompt.
        if err == 1223:
            print("elevation was declined at the UAC prompt.", file=sys.stderr)
        else:
            print(
                f"elevation failed (ShellExecuteExW error {err}); "
                "run from an Administrator shell instead.",
                file=sys.stderr,
            )
        return 1
    if not info.hProcess:
        print(
            "elevated child started but no process handle was returned, "
            "so its exit code is unknown.",
            file=sys.stderr,
        )
        return 1
    try:
        ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_void_p(info.hProcess), 0xFFFFFFFF)
        code = ctypes.c_ulong()
        ctypes.windll.kernel32.GetExitCodeProcess(
            ctypes.c_void_p(info.hProcess), ctypes.byref(code)
        )
        return int(code.value)
    finally:
        ctypes.windll.kernel32.CloseHandle(ctypes.c_void_p(info.hProcess))


def _split_child(argv: list[str]) -> tuple[list[str], list[str]]:
    """Split our own flags from the child's, at the first ``--``.

    Everything after the separator belongs to the program being run, so it is
    never seen by our option table (the child's ``-n 2`` must not collide with
    our flags).
    """
    if "--" in argv:
        i = argv.index("--")
        return argv[:i], argv[i + 1 :]
    return argv, []


def main(argv: list[str] | None = None) -> int:
    own_argv = list(sys.argv[1:] if argv is None else argv)
    our_flags, child = _split_child(own_argv)
    ap = argparse.ArgumentParser(
        description="Block all outbound network traffic for one exe, run it, wait for exit."
    )
    ap.add_argument(
        "--block-only", action="store_true", help="add rules, do not run"
    )
    ap.add_argument("--exe", type=Path, default=None, help="program to block and run")
    ap.add_argument("--unblock-only", action="store_true", help="remove rules, do not run")
    ap.add_argument(
        "--keep",
        action="store_true",
        help="leave the block rules in place after the program exits",
    )
    ap.add_argument(
        "--timeout",
        type=float,
        default=None,
        help="kill the program after this many seconds (default: wait forever)",
    )
    ap.add_argument(
        "--no-elevate",
        action="store_true",
        help="do not relaunch through UAC when not already elevated",
    )
    args = ap.parse_args(our_flags)
    if args.exe is not None:
            child = [str(args.exe), *child]
    exe = child[0] if child else None
    prog_args = child[1:]

    if not sys.platform.startswith("win"):
        print("Windows only: uses netsh advfirewall.", file=sys.stderr)
        return 2
    if not _is_admin() and not args.no_elevate:
        # --no-elevate is what the relaunch passes, so a UAC decline cannot loop.
        return _self_reexec_elevated(own_argv)
    if not _is_admin():
        print(
            "not elevated and --no-elevate was given, so netsh will refuse to "
            "write the rules. Re-run without --no-elevate to get a UAC prompt.",
            file=sys.stderr,
        )

    if args.unblock_only:
        res = unblock()
        # Nothing to remove is a success, not a failure.
        return 0 if all(r.ok for r in res) else 1

    if not exe:
        exe_path = default_game_exe()
        if exe_path is None:
            print(
                "need a program path, or set GTA6_GAME_EXE (or run from the "
                "game root) -- or use --unblock-only",
                file=sys.stderr,
            )
            return 2
        exe = str(exe_path)
        print(f"  using {exe}", file=sys.stderr)
    exe = str(exe)

    added = block(exe)
    if not all(r.ok for r in added):
        print("could not install the block rules; nothing launched.", file=sys.stderr)
        unblock()
        return 1
    if args.block_only:
        print(f"blocked {exe}; remove later with --unblock-only", file=sys.stderr)
        return 0

    try:
        return run_blocked(exe, prog_args, timeout=args.timeout)
    finally:
        if args.keep:
            print("  --keep: leaving the block rules in place", file=sys.stderr)
        else:
            unblock()


if __name__ == "__main__":
    raise SystemExit(main())
