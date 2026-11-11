<p align="center">
  <img src="assets/lrb-logo.svg" alt="LRB — LegendaryRustBucket rainbow rust bucket logo" width="360">
</p>

<h1 align="center">LRB — LegendaryRustBucket</h1>
<p align="center"><strong>A Rocket League-focused, Linux + Windows launcher project based on Legendary.</strong></p>

> **Project status: early development.** This fork currently contains the upstream Python Legendary launcher plus an **experimental Rust command-line front-end**. It is **not** yet a complete Rust port, and no FPS, frame-time, startup-time, or ping improvement has been demonstrated.

## Goals

- Create a fast, efficient Rocket League launcher for **Linux and Windows** while retaining Epic account compatibility.
- Incrementally port appropriate launcher components (configuration, manifests, downloads, game launching, authentication) from Python to **native Rust** with measured benchmarks and parity tests.
- Provide sensible, **opt-in** per-platform launch settings and performance diagnostics without touching anti-cheat, game binaries, or competitive networking traffic.
- Reduce launcher resource usage; measure cold launch time, working-set memory, and CPU usage before making performance claims.

## Try the early Rust front-end

**Prerequisites:** Rust/Cargo, and the upstream [`legendary`](https://github.com/legendary-gl/legendary) executable already installed and authenticated (`legendary auth`). On Linux, a compatible Wine/Proton environment is needed to run the Windows game. The current Rust front-end delegates authentication and launches to Legendary, rather than duplicating the Epic login flow.

```bash
# From this repository's root:
cargo run --manifest-path rust/lrb/Cargo.toml -- help
cargo run --manifest-path rust/lrb/Cargo.toml -- doctor
cargo run --manifest-path rust/lrb/Cargo.toml -- list
cargo run --manifest-path rust/lrb/Cargo.toml -- launch --dry-run
cargo run --manifest-path rust/lrb/Cargo.toml -- launch
```

The default app selector is `Rocket League`. If your Epic library reports a different application name, pass `--app "ACTUAL APP NAME"` after `launch`, `install`, or `verify`. Use `--legendary /path/to/legendary` (or `LRB_LEGENDARY`) if Legendary is not on `PATH`.

Run `cargo run --manifest-path rust/lrb/Cargo.toml -- auth` to use Legendary's regular authentication flow. Pass additional Legendary options after `--`, for example `launch -- --wine /path/to/wine` on Linux. `--dry-run` is **LRB's command preview**, not an executable benchmark.

## Rocket League compatibility and anti-cheat

As of April 2026, Rocket League requires Easy Anti-Cheat for online play on PC; the developer [states Linux/Steam Deck is supported](https://www.rocketleague.com/news/easy-anti-cheat-comes-to-rocket-league-on-pc-today). LRB does not disable or work around EAC, alter game traffic, or promise compatibility for every Wine/Proton installation. Always use the supported online launch path.

## Performance philosophy

Running a Rust front-end does not itself make the **game** render faster or lower your matchmaking ping. Launcher CPU/RAM and launch overhead can be improved and measured; in-game FPS depends primarily on Rocket League, graphics drivers, Proton/Wine configuration, GPU/CPU, and OS behavior. Network latency depends on selected servers and routing. We will only publish optimizations with repeatable before/after measurements and no anti-cheat compromise.

## Milestones

| Milestone | State |
| --- | --- |
| LRB branding and logo | Added |
| Rust CLI front-end for existing Legendary | Initial implementation |
| Linux + Windows CI smoke tests | Workflow added; verify Actions results |
| Native Rust Epic authentication/manifest/downloader | Not implemented |
| Benchmark-driven launch improvements | Not yet measured |
| Safe launch profiles, diagnostics, and UI | Planned |

## Heritage and license

LRB is an independent fork of [Legendary](https://github.com/legendary-gl/legendary), originally authored by the Legendary contributors. The existing Python implementation is retained during the transition, under its **GPL-3.0-or-later** license (see [`LICENSE`](LICENSE)). This project is not affiliated with Epic Games, Psyonix, or the Legendary upstream team. For the upstream CLI usage and configuration reference, see [Legendary's README](https://github.com/legendary-gl/legendary#readme).
