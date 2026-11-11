<p align="center"><img src="assets/lrb-logo.svg" alt="LRB — LegendaryRustBucket rainbow rust bucket" width="300" /></p>
<h1 align="center">LRB — LegendaryRustBucket</h1>
<p align="center">A native <strong>Rust</strong> Epic Games launcher project focused on Rocket League for Windows and Linux.</p>

> **Development status — not a production-ready Rocket League replacement.** All active launcher source code is Rust. There is **no Python code, Python interpreter, or Legendary executable dependency**. Epic sign-in and native HTTP requests are implemented, but native BuildPatch install/update/repair are implemented but **not yet validated with authenticated live Epic downloads**; newer encrypted BuildPatch manifests/chunks are implemented but unverified live, and full Rocket League online-launch compatibility is not proven. No claims of increased FPS, reduced ping, or improved launch time have been measured.

## Rust-only architecture

This project is a from-scratch Rust implementation inspired by [Legendary](https://github.com/legendary-gl/legendary), not a Python wrapper. It preserves the upstream GPL-3.0-or-later license and attribution. You do not need to install Python or `legendary-gl` to build or run LRB.

The new Rust code covers CLI argument handling, configuration and secure local session storage, Epic OAuth authorization-code/refresh-token exchange over HTTPS, Epic library requests, local game registration, installation executable checks, and direct process spawning with Wine selection on Linux. It does not patch game files, spoof anti-cheat, or rewrite network traffic.

## Build

Install the [Rust toolchain](https://rustup.rs) on **Windows or Linux** and run:

```bash
cargo build --release
cargo test
cargo run -- help
cargo run -- doctor
```

The resulting binary is `target/release/lrb` (Linux) or `target/release/lrb.exe` (Windows). Dependencies are Rust crates from crates.io, not the Python Legendary launcher.

## Native Rocket League install, update, verify, repair (v0.6.0, experimental)

With an authenticated Epic account, LRB now requests the Windows Rocket League assets
and a signed BuildPatch manifest, validates its SHA-1, parses supported JSON/binary and AES-256-GCM encrypted
manifests, retrieves chunk files in Rust, checks integrity, assembles game files, and
registers them only after completion. **No Python or Legendary executable is used.**

```bat
lrb auth
lrb auth --code YOUR_CODE
lrb install --dry-run
lrb install --dir D:\Games\RocketLeague --workers 4
lrb verify --full
lrb update
lrb repair
```

The default installation folder is the operating system user-local data directory under
`LegendaryRustBucket/Games/RocketLeague`. Use `--dir` to choose a drive.
An interrupted install keeps verified chunks for resumable retries, and the downloader
reuses unchanged files based on their SHA-1 hashes. New/updated files are assembled
to temporary files, verified, and then installed. It does not delete files that
are absent from a new manifest. The chunk cache is removed after success.

**Known limitations:** AES-256-GCM encrypted BuildPatch manifests and chunks are supported using Epic-provided keys in memory; unknown or unauthenticated formats are rejected (rather than
silently corrupted); installation API responses and Rocket League gameplay still
require real-account end-to-end testing. Selective install tags, prerequisite installers,
file-deletion patch optimizations, anti-cheat initialization and Epic ownership-token
flows are not complete. It is an experimental installer, not a production replacement.

## Epic sign-in and library (experimental)

```bash
lrb auth
# Open the official Epic URL printed by LRB and retrieve the authorization code.
lrb auth --code YOUR_AUTHORIZATION_CODE
lrb auth status
lrb library
```

The browser sign-in uses Epic's normal webpage. Enter the authorization code locally; **never share it, your refresh token, or your saved session file**. Tokens are stored in your user configuration directory (`LRB_HOME` overrides the directory), with owner-only permissions on Unix. To remove the saved token, run `lrb auth logout`. Epic may update its OAuth flow or require additional account actions. Live authentication has **not** been tested with a real account in this milestone.

## Import an existing Rocket League installation (native Rust)

LRB can now read Epic Games Launcher's local `.item` installation manifest and automatically
discover Rocket League's app ID, namespace, install location, and executable. No Python
code or Legendary executable is involved; this does not install or update the game.

```bash
lrb import-egl
lrb import-egl --manifest /path/to/manifest.item
lrb import-egl --manifest /path/to/manifest.item --path /path/to/RocketLeague
lrb import-egl --manifest /path/to/manifest.item --replace
```

On Windows, the default search uses `%PROGRAMDATA%/Epic/EpicGamesLauncher/Data/Manifests`.
On Linux it uses `$WINEPREFIX/drive_c/ProgramData/Epic/EpicGamesLauncher/Data/Manifests`
(or `~/.wine` when WINEPREFIX is unset). Pass `--path` for relocated installations or
non-C: Wine drives. The importer refuses incomplete installs, traversal paths and
unverified executables. Only Rocket League manifests are considered.

## Register an existing Rocket League installation manually (experimental)

LRB does not download or update the game yet. For an **existing, legitimately installed game**, register the app with its actual Epic `appName` and namespace (from your own authorized Epic account/metadata), and its installed executable:

```bash
lrb register --app YOUR_EPIC_APP_NAME --title "Rocket League" \
  --path "/path/to/RocketLeague" --exe "Binaries/Win64/RocketLeague.exe" \
  --namespace YOUR_EPIC_NAMESPACE

lrb list
lrb verify --app "Rocket League"
lrb launch --app "Rocket League" --dry-run
lrb launch --app "Rocket League"
```

On Windows, use a Windows directory path for `--path`. On Linux, the native launcher will attempt to spawn Windows executables via the `wine` binary in `PATH`; set `LRB_WINE` or use `--wine /path/to/wine` to choose the runtime. File paths and executable names vary by installation. `verify` only checks the executable exists; it **is not** a content-integrity check.

The launch command requests an Epic exchange code and supplies standard Epic launch parameters. When present, the Epic manifest sidecar deployment ID is also passed to the game. It does not touch game binaries or anti-cheat. **Whether Rocket League successfully connects online through this flow remains untested**, particularly in Wine/Proton environments.

## Check Rocket League online-launch prerequisites (experimental)

The native Rust `online-check` command validates the existing executable and game metadata,
refreshes your Epic session, verifies the account with Epic's OAuth endpoint, and requests
a short-lived game exchange code. It never prints your private token. **Passing this check
does not establish that Rocket League starts, EAC initializes, or online matchmaking works.**

```bash
lrb import-egl
lrb online-check --app "Rocket League"
lrb launch --app "Rocket League"
```

To establish online gameplay compatibility, test a real account and properly installed
Rocket League on Windows and Linux: confirm EAC stays enabled, the game starts, a private
or casual online match joins, and input/network behavior is correct. Record OS, Wine/Proton
version, game build, error messages and your own measured in-game ping. Never provide
your access/refresh token or saved session file in an issue.

Official support: [EAC required for online PC play](https://www.rocketleague.com/news/easy-anti-cheat-comes-to-rocket-league-on-pc-today);
[Linux support](https://www.epicgames.com/help/c-37599050/c-42869540/steam-deck-linux-macos-a13980741).

## Diagnose network latency without making false ping claims

`net-probe` measures TCP connection setup to a host you choose, with median, p95,
consecutive sample variation, and failure count. It runs directly in Rust without
shelling out to system `ping` or modifying traffic. TCP latency to a web host is
**not equivalent to Rocket League's UDP game-server ping**.

```bash
lrb net-probe --host example.com --port 443 --samples 10
lrb net-probe --host example.com --samples 10 --json
```

To test a lower-ping hypothesis, record multiple actual in-game matches before and
after changing one approved setting: the matchmaking server region, wired vs Wi-Fi,
or background downloads. Compare medians, p95 and packet-loss indicators using the
same region and comparable times of day. LRB cannot guarantee lower ping, force
game-server routes, or manipulate matchmaking traffic.

Official guide: [Rocket League connection diagnostics](https://www.epicgames.com/help/c-37599050/c-39065013/a18083748).

## Current capabilities

| Subsystem | Status |
| --- | --- |
| New `lrb` binary written entirely in Rust | Implemented; CI build/tests run on Linux and Windows |
| Python source and Python workflows | Removed from active repository |
| Epic account authorization and token refresh (Rust HTTPS) | Implemented; account integration requires live testing |
| Epic library API query (Rust HTTPS) | Implemented; live response requires validation |
| Local game registration, executable safety checks, diagnostics | Implemented; unit tested |
| Epic `.item` install import for Rocket League | Implemented; parser unit tests added, real install still untested |
| Native Epic online preflight (OAuth verify and exchange-code issuance) | Implemented; live account testing required |
| Rust TCP network diagnostics (median, p95, variations and failures) | Implemented; not game-server ping |
| Local game process spawning with Epic token and Wine option | Implemented; real Rocket League play not validated |
| Game manifest retrieval and JSON/binary parser | Implemented; synthetic tests; live Epic not yet tested |
| Parallel chunk download, SHA-1 verification, install, update and repair | Implemented; live Epic downloads not yet tested |
| FPS/frame-time and ping optimizations | Not benchmarked; no performance claim |

## Benchmark policy and Rocket League anti-cheat

The goal is an efficient, cross-platform native launcher with reliable installation and sensible opt-in launch profiles, not misleading claims that a launcher automatically improves Rocket League's FPS or network routing. We will measure launcher cold startup, memory/CPU usage, install throughput, and game frame-time behavior in controlled comparisons before claiming improvements. Network diagnostics can measure latency/jitter but cannot guarantee lower in-game ping. Easy Anti-Cheat must remain intact.

## Project origin

Forked from [legendary-gl/legendary](https://github.com/legendary-gl/legendary), whose original project is licensed under the GPL-3.0-or-later. New LRB code is also GPL-3.0-or-later. LRB is not endorsed by Epic Games, Psyonix, or the Legendary team.
