//! Block all outbound network traffic for one process, run it, and wait for it to exit.
//!
//! The point is the experiment behind `docs/notes/2026-11-23-exe-networking.md`: the exe
//! links WinHTTP, Winsock and libHttpClient, so the only reliable way to prove what
//! happens offline is to deny the *process* every outbound flow, launch it, and watch.
//!
//! The block is a set of Windows Firewall rules scoped by application path, which is what
//! makes the block follow the game no matter which child process ends up owning the
//! sockets. `netsh advfirewall` is driven directly rather than the `NetSecurity` cmdlets,
//! which are slow or unavailable on some builds. Writing the rules needs elevation, so
//! when not already elevated the process re-launches itself through a UAC prompt
//! (`ShellExecuteExW` with `runas`) and harvests the child's exit code.
//!
//! This is the native port of the Python `gta6/net_offline.py`.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Reserved group name (netsh on the target build rejects `group=` in `add rule`).
pub const GROUP: &str = "gta6-net-offline";
const RULE_TCP: &str = "gta6 offline (block outbound TCP)";
const RULE_UDP: &str = "gta6 offline (block outbound UDP)";
const RULE_ICMP4: &str = "gta6 offline (block outbound ICMPv4)";
const RULE_ICMP6: &str = "gta6 offline (block outbound ICMPv6)";

/// TCP + UDP alone still lets `ping.exe` through, because ICMP is its own protocol number
/// in the WFP filter rather than a transport port. (Caveat found by test: on the target
/// build an ICMPv4 rule scoped by *program* is listed by netsh yet does not drop
/// `ping.exe`'s traffic, whereas the same TCP rule does block `curl.exe`. ICMP is therefore
/// best-effort; the TCP/UDP pair is what the game experiment actually depends on.)
const RULES: [(&str, &str); 4] = [
    ("TCP", RULE_TCP),
    ("UDP", RULE_UDP),
    ("ICMPv4", RULE_ICMP4),
    ("ICMPv6", RULE_ICMP6),
];

/// Where the exe lives when the command line does not say.
const GAME_EXE_NAMES: [&str; 1] = ["game_scarlett_master.exe"];

/// Outcome of one `netsh` invocation.
pub struct NetshResult {
    pub argv: Vec<String>,
    pub code: i32,
    pub out: String,
}

impl NetshResult {
    pub fn ok(&self) -> bool {
        self.code == 0
    }
}

/// Resolve the game executable from the environment, or `None`.
///
/// `GTA6_GAME_EXE` wins; otherwise fall back to the known name inside `GTA6_GAME_ROOT`.
pub fn default_game_exe() -> Option<PathBuf> {
    if let Ok(raw) = std::env::var("GTA6_GAME_EXE") {
        let raw = raw.trim();
        if !raw.is_empty() {
            return Some(PathBuf::from(raw));
        }
    }
    let root = std::env::var("GTA6_GAME_ROOT").ok()?;
    GAME_EXE_NAMES
        .iter()
        .map(|name| Path::new(&root).join(name))
        .find(|c| c.is_file())
}

/// Whether the current process is elevated. Always false off Windows.
pub fn is_admin() -> bool {
    #[cfg(windows)]
    {
        // SAFETY: IsUserAnAdmin has no preconditions and only reads the token.
        unsafe { windows::Win32::UI::Shell::IsUserAnAdmin().as_bool() }
    }
    #[cfg(not(windows))]
    {
        false
    }
}

fn run(argv: &[&str]) -> NetshResult {
    let output = Command::new(argv[0])
        .args(&argv[1..])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output();
    match output {
        Ok(o) => {
            let mut out = String::from_utf8_lossy(&o.stdout).into_owned();
            out.push_str(&String::from_utf8_lossy(&o.stderr));
            NetshResult {
                argv: argv.iter().map(|s| s.to_string()).collect(),
                code: o.status.code().unwrap_or(-1),
                out: out.trim().to_string(),
            }
        }
        Err(e) => NetshResult {
            argv: argv.iter().map(|s| s.to_string()).collect(),
            code: -1,
            out: e.to_string(),
        },
    }
}

fn rule_exists(name: &str) -> bool {
    let res = run(&[
        "netsh",
        "advfirewall",
        "firewall",
        "show",
        "rule",
        &format!("name={name}"),
    ]);
    res.ok() && !res.out.contains("No rules match")
}

fn unblock_argv(rule: &str) -> Vec<String> {
    vec![
        "netsh".into(),
        "advfirewall".into(),
        "firewall".into(),
        "delete".into(),
        "rule".into(),
        format!("name={rule}"),
    ]
}

/// Add outbound block rules for `exe`. Idempotent: existing rules are replaced.
pub fn block(exe: &str, verbose: bool) -> Vec<NetshResult> {
    let mut results = Vec::new();
    for (proto, rule) in RULES {
        if rule_exists(rule) {
            let del = unblock_argv(rule);
            results.push(run(&del.iter().map(String::as_str).collect::<Vec<_>>()));
        }
        let name = format!("name={rule}");
        let program = format!("program={exe}");
        let protocol = format!("protocol={proto}");
        let res = run(&[
            "netsh",
            "advfirewall",
            "firewall",
            "add",
            "rule",
            &name,
            "dir=out",
            "action=block",
            "enable=yes",
            &protocol,
            &program,
            "description=Added by `rpfkit net-offline`.",
        ]);
        if verbose {
            let flag = if res.ok() {
                "ok".to_string()
            } else {
                format!("FAILED rc={}", res.code)
            };
            eprintln!("  block {proto:<3} {exe}  [{flag}]");
            if !res.ok() {
                eprintln!("    {}", res.out);
            }
        }
        results.push(res);
    }
    results
}

/// Remove the rules this helper adds. Safe to call when they are absent.
pub fn unblock(verbose: bool) -> Vec<NetshResult> {
    let mut results = Vec::new();
    for (_, rule) in RULES {
        if !rule_exists(rule) {
            if verbose {
                eprintln!("  no rule to remove: {rule}");
            }
            continue;
        }
        let del = unblock_argv(rule);
        let res = run(&del.iter().map(String::as_str).collect::<Vec<_>>());
        if verbose {
            let flag = if res.ok() {
                "ok".to_string()
            } else {
                format!("FAILED rc={}", res.code)
            };
            eprintln!("  unblock {rule}  [{flag}]");
        }
        results.push(res);
    }
    results
}

/// Launch `exe` with `args` and wait for it to exit. Returns its exit code.
///
/// stdout/stderr are inherited so the program's own output is visible, but that also means
/// a GUI exe with no console shows nothing — rely on the exit code and on whatever log
/// files it writes next to itself.
pub fn run_blocked(exe: &str, args: &[String], timeout: Option<Duration>) -> i32 {
    eprintln!(
        "  launching: {}",
        shell_join(std::iter::once(exe).chain(args.iter().map(String::as_str)))
    );
    let started = Instant::now();
    let mut child = match Command::new(exe).args(args).spawn() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("  failed to launch {exe}: {e}");
            return 1;
        }
    };
    let code = match timeout {
        None => child.wait().map(|s| s.code().unwrap_or(-1)).unwrap_or(-1),
        Some(dur) => match wait_timeout(&mut child, dur) {
            Some(code) => code,
            None => {
                eprintln!("  timeout after {}s; terminating", dur.as_secs());
                let _ = child.kill();
                child.wait().map(|s| s.code().unwrap_or(-1)).unwrap_or(-1)
            }
        },
    };
    eprintln!(
        "  exited code={code} after {:.1}s",
        started.elapsed().as_secs_f64()
    );
    code
}

/// Wait for `child` up to `dur`; `None` on timeout.
fn wait_timeout(child: &mut std::process::Child, dur: Duration) -> Option<i32> {
    // std has no timed wait; poll in small slices. The child is a game process, so a
    // ~50 ms poll granularity is invisible next to its own startup time.
    let deadline = Instant::now() + dur;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status.code().unwrap_or(-1)),
            Ok(None) => {}
            Err(_) => return Some(-1),
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Join argv for a human-readable echo (not a faithful Windows quoting round-trip).
fn shell_join<'a, I: Iterator<Item = &'a str>>(it: I) -> String {
    it.collect::<Vec<_>>().join(" ")
}

/// Relaunch this process elevated through a UAC prompt and return its exit code.
///
/// `netsh advfirewall` writes fail without elevation, so the reusable entry point offers a
/// UAC prompt instead of failing. `ShellExecuteExW` with `runas` gives the child a console
/// of its own; its exit code is harvested from the returned process handle. The relaunch
/// carries `--no-elevate` so that if UAC is declined the child reports the failure instead
/// of prompting forever.
pub fn self_reexec_elevated(argv: &[String]) -> i32 {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows::Win32::Foundation::{CloseHandle, GetLastError, WAIT_FAILED};
        use windows::Win32::System::Threading::{
            GetExitCodeProcess, INFINITE, WaitForSingleObject,
        };
        use windows::Win32::UI::Shell::{
            SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW,
        };

        if !is_admin() {
            eprintln!("requesting elevation (UAC prompt)...");
        }

        // --no-elevate goes at the end of our flags so it can never be mistaken for one of
        // the program's arguments.
        let mut params: Vec<String> = argv.to_vec();
        if !params.iter().any(|a| a == "--no-elevate") {
            params.push("--no-elevate".to_string());
        }
        let params = params.join(" ");

        let exe = std::env::current_exe().unwrap_or_default();
        let exe = exe.to_string_lossy().into_owned();
        let cwd = std::env::current_dir().unwrap_or_default();
        let cwd = cwd.to_string_lossy().into_owned();

        // SHELLEXECUTEINFOW holds PCWSTR (NUL-terminated) pointers, so the buffers must
        // outlive the call. `encode_wide` yields already-NUL-terminated OsStr wide strings.
        let verb: Vec<u16> = "runas".encode_utf16().chain(std::iter::once(0)).collect();
        let file_w: Vec<u16> = std::ffi::OsStr::new(&exe)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let params_w: Vec<u16> = params.encode_utf16().chain(std::iter::once(0)).collect();
        let dir_w: Vec<u16> = std::ffi::OsStr::new(&cwd)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let mut info = SHELLEXECUTEINFOW {
            cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
            fMask: SEE_MASK_NOCLOSEPROCESS,
            lpVerb: windows::core::PCWSTR(verb.as_ptr()),
            lpFile: windows::core::PCWSTR(file_w.as_ptr()),
            lpParameters: windows::core::PCWSTR(params_w.as_ptr()),
            lpDirectory: windows::core::PCWSTR(dir_w.as_ptr()),
            nShow: 1, // SW_SHOWNORMAL
            ..Default::default()
        };

        eprintln!("  relaunching elevated: {exe} {params}");
        // SAFETY: `info` is a valid, correctly-sized SHELLEXECUTEINFO whose string fields
        // outlive the call; SEE_MASK_NOCLOSEPROCESS makes the API hand back a real handle.
        if unsafe { ShellExecuteExW(&mut info) }.is_err() {
            let err = unsafe { GetLastError() };
            // 1223 = ERROR_CANCELLED, i.e. the user pressed No at the UAC prompt.
            if err.0 == 1223 {
                eprintln!("elevation was declined at the UAC prompt.");
            } else {
                eprintln!(
                    "elevation failed (ShellExecuteExW error {}); \
                     run from an Administrator shell instead.",
                    err.0
                );
            }
            return 1;
        }
        let handle = info.hProcess;
        if handle.is_invalid() {
            eprintln!(
                "elevated child started but no process handle was returned, \
                 so its exit code is unknown."
            );
            return 1;
        }
        // SAFETY: `handle` is a valid process handle from ShellExecuteExW; the wait and
        // exit-code read only use it, and it is closed exactly once below.
        unsafe {
            let wait = WaitForSingleObject(handle, INFINITE);
            if wait == WAIT_FAILED {
                CloseHandle(handle).ok();
                return 1;
            }
            let mut code = 0u32;
            if GetExitCodeProcess(handle, &mut code).is_err() {
                CloseHandle(handle).ok();
                return 1;
            }
            CloseHandle(handle).ok();
            code as i32
        }
    }
    #[cfg(not(windows))]
    {
        let _ = argv;
        eprintln!("elevation is a Windows-only concept; run from an Administrator shell.");
        1
    }
}
