//! LRB's initial Rust command-line interface. Epic authentication and game
//! launch semantics are delegated to the upstream Legendary CLI for now.
use std::env;
use std::ffi::{OsStr, OsString};
use std::process::{Command, ExitCode};

const DEFAULT_GAME: &str = "Rocket League";
const HELP: &str = "\
LRB - LegendaryRustBucket (early Rust launcher)

Usage:
  lrb doctor [--legendary PATH]
  lrb auth [--legendary PATH] [-- LEGENDARY_ARGS...]
  lrb list [--legendary PATH]
  lrb launch [--app NAME] [--legendary PATH] [--dry-run] [-- LEGENDARY_ARGS...]
  lrb install [--app NAME] [--legendary PATH] [--dry-run] [-- LEGENDARY_ARGS...]
  lrb verify [--app NAME] [--legendary PATH] [--dry-run]

Options:
  --app NAME        Game name/alias (default: Rocket League)
  --legendary PATH  Path to the upstream Legendary executable
  --dry-run         Preview the invoked CLI command; do not run it
  --               Forward remaining arguments to Legendary

Environment:
  LRB_LEGENDARY     Alternative to --legendary

This initial release is a Rust *front-end*, not yet a native port of the
Epic authentication, manifest, download, or game launching implementations.
It does not modify game memory, traffic, or anti-cheat settings.
";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Action {
    Help,
    Doctor,
    Auth,
    List,
    Launch,
    Install,
    Verify,
}

#[derive(Debug)]
struct Invocation {
    action: Action,
    legendary: OsString,
    game: OsString,
    dry_run: bool,
    forwarded: Vec<OsString>,
}

fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Invocation, String> {
    let mut args = args.into_iter();
    let command = args.next().unwrap_or_else(|| OsString::from("help"));
    let action = match command.to_str() {
        Some("help" | "-h" | "--help") => Action::Help,
        Some("doctor") => Action::Doctor,
        Some("auth") => Action::Auth,
        Some("list") => Action::List,
        Some("launch") => Action::Launch,
        Some("install") => Action::Install,
        Some("verify") => Action::Verify,
        _ => return Err(format!("Unknown command: {command:?}")),
    };
    let mut legendary = env::var_os("LRB_LEGENDARY").unwrap_or_else(|| {
        OsString::from(if cfg!(windows) {
            "legendary.exe"
        } else {
            "legendary"
        })
    });
    let mut game = OsString::from(DEFAULT_GAME);
    let mut dry_run = false;
    let mut forwarded = Vec::new();
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("--legendary") => {
                legendary = args.next().ok_or("--legendary needs a path")?;
            }
            Some("--app") => {
                game = args.next().ok_or("--app needs a game name")?;
            }
            Some("--dry-run") => dry_run = true,
            Some("--") => {
                forwarded.extend(args);
                break;
            }
            _ => return Err(format!("Unexpected argument {arg:?}. Use -- to forward arguments.")),
        }
    }
    if legendary.is_empty() || game.is_empty() {
        return Err("--legendary and --app must not be empty".to_owned());
    }
    if !forwarded.is_empty() && !matches!(action, Action::Auth | Action::Launch | Action::Install) {
        return Err("This subcommand does not accept forwarded arguments".to_owned());
    }
    if dry_run && !matches!(action, Action::Auth | Action::List | Action::Launch | Action::Install | Action::Verify) {
        return Err("--dry-run applies only to Legendary commands".to_owned());
    }
    Ok(Invocation {
        action,
        legendary,
        game,
        dry_run,
        forwarded,
    })
}

fn legendary_args(options: &Invocation) -> Vec<OsString> {
    let mut args: Vec<OsString> = match options.action {
        Action::Auth => vec!["auth".into()],
        Action::List => vec!["list-installed".into()],
        Action::Launch => vec!["launch".into(), options.game.clone()],
        Action::Install => vec!["install".into(), options.game.clone()],
        Action::Verify => vec!["verify".into(), options.game.clone()],
        _ => Vec::new(),
    };
    args.extend(options.forwarded.iter().cloned());
    args
}

fn execute(program: &OsStr, args: &[OsString]) -> Result<ExitCode, String> {
    let status = Command::new(program)
        .args(args)
        .status()
        .map_err(|err| format!("Unable to run {program:?}: {err}. Install Legendary or pass --legendary PATH."))?;
    Ok(ExitCode::from(status.code().unwrap_or(1).clamp(0, 255) as u8))
}

fn run(options: Invocation) -> Result<ExitCode, String> {
    match options.action {
        Action::Help => {
            print!("{HELP}");
            Ok(ExitCode::SUCCESS)
        }
        Action::Doctor => {
            let output = Command::new(&options.legendary)
                .arg("--version")
                .output()
                .map_err(|err| format!("Legendary not available at {:?}: {err}", options.legendary))?;
            if !output.status.success() {
                return Err(format!("Legendary --version exited with {}", output.status));
            }
            println!("Legendary executable: {:?}", options.legendary);
            print!("{}", String::from_utf8_lossy(&output.stdout));
            eprint!("{}", String::from_utf8_lossy(&output.stderr));
            println!("LRB Rust front-end is available. Native Epic backend: not yet implemented.");
            Ok(ExitCode::SUCCESS)
        }
        _ => {
            let args = legendary_args(&options);
            if options.dry_run {
                println!("Preview only: {:?} {:?}", options.legendary, args);
                Ok(ExitCode::SUCCESS)
            } else {
                execute(&options.legendary, &args)
            }
        }
    }
}

fn main() -> ExitCode {
    match parse(env::args_os().skip(1)).and_then(run) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("LRB error: {err}\nTry: lrb help");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(args: &[&str]) -> Invocation {
        parse(args.iter().map(OsString::from)).expect("valid CLI")
    }

    #[test]
    fn defaults_to_rocket_league() {
        let options = parsed(&["launch"]);
        assert_eq!(options.action, Action::Launch);
        assert_eq!(options.game, OsString::from(DEFAULT_GAME));
        assert_eq!(legendary_args(&options), ["launch", "Rocket League"]);
    }

    #[test]
    fn forwards_arguments_without_shell_interpolation() {
        let options = parsed(&["launch", "--app", "Custom App", "--", "--wine", "Proton Custom"]);
        assert_eq!(legendary_args(&options), ["launch", "Custom App", "--wine", "Proton Custom"]);
    }

    #[test]
    fn accepts_custom_legendary_path_and_dry_run() {
        let options = parsed(&["install", "--legendary", "custom-legendary", "--dry-run"]);
        assert_eq!(options.legendary, OsString::from("custom-legendary"));
        assert!(options.dry_run);
        assert_eq!(legendary_args(&options), ["install", "Rocket League"]);
    }

    #[test]
    fn rejects_bad_flags() {
        assert!(parse([OsString::from("launch"), OsString::from("--unknown")]).is_err());
        assert!(parse([OsString::from("launch"), OsString::from("--app")]).is_err());
    }

    #[test]
    fn list_is_installed_games() {
        assert_eq!(legendary_args(&parsed(&["list"])), ["list-installed"]);
    }
}
