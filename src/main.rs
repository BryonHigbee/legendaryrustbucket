//! LRB: Rust-native launcher foundation. Never starts Python or Legendary.
mod epic;
mod egl;
mod installer;
mod manifest;
mod network;
mod store;

use std::env;
use std::path::PathBuf;
use std::process::{Command, ExitCode};
use store::InstalledGame;

const HELP: &str = "\
LRB — LegendaryRustBucket v0.5.0 (100% Rust launcher foundation)

Usage:
  lrb help
  lrb doctor
  lrb auth                         Show Epic login URL
  lrb auth --code CODE             Exchange Epic authorization code
  lrb auth --exchange-code CODE    Exchange a single-use Epic exchange code
  lrb auth status                  Show saved session identity (offline check)
  lrb auth logout                  Remove saved session
  lrb library                      Read Epic library through native Rust HTTPS
  lrb list                         List locally registered installs
  lrb import-egl [--manifest FILE | --dir DIR] [--path DIR] [--replace]
                                   Import an existing Epic installation
  lrb register --app ID --title NAME --path DIR --exe RELATIVE_EXE --namespace ID [--platform Windows|Linux]
  lrb launch [--app ID_OR_TITLE] [--wine WINE_PATH] [--dry-run]
  lrb verify [--app ID_OR_TITLE]   Check registered executable (not full file verification)
  lrb online-check [--app ID_OR_TITLE]  Validate local install, Epic OAuth and launch-token issuance
  lrb net-probe --host HOST [--port 443] [--samples 8] [--timeout-ms 1250] [--json]
                                   Probe TCP connect RTT; NOT in-game ping
  lrb install [--app ID] [--dir DIR] [--workers 1..16] [--dry-run]
                                   Download/install Rocket League via native Rust Epic BuildPatch
  lrb update [--app ID] [--workers 1..16] [--dry-run]
                                   Fetch newest manifest; update changed files
  lrb repair [--app ID] [--workers 1..16] [--dry-run]
                                   Re-download files failing SHA-1 verification
  lrb verify --full [--app ID]     Hash-check every game file against saved install manifest

Environment:
  LRB_HOME                         Override user config directory
  LRB_WINE                         Optional Wine binary (Linux)
  LRB_EPIC_CLIENT_ID               Override Epic OAuth public client ID
  LRB_EPIC_CLIENT_SECRET           Override Epic OAuth public client secret

Notes:
  --app defaults to Rocket League. LRB doesn't patch game files, EAC, or network traffic.
  Epic HTTP integration requires a live authorized account to validate in practice.
";

fn get_flag(args: &[String], flag: &str) -> Result<Option<String>, String> {
    let mut result = None;
    let mut i = 0;
    while i < args.len() {
        if args[i] == flag {
            let val = args.get(i + 1).ok_or_else(|| format!("{flag} requires a value"))?;
            if val.starts_with("--") || val.is_empty() { return Err(format!("{flag} requires a value")); }
            if result.is_some() { return Err(format!("Repeated {flag}")); }
            result = Some(val.clone());
            i += 2;
        } else { i += 1; }
    }
    Ok(result)
}

fn allowed_flags(args: &[String], flags: &[&str], switches: &[&str]) -> Result<(), String> {
    let mut i = 0;
    while i < args.len() {
        if flags.contains(&args[i].as_str()) {
            if args.get(i + 1).is_none_or(|s| s.is_empty() || s.starts_with("--")) {
                return Err(format!("{} requires a value", args[i]));
            }
            i += 2;
        } else if switches.contains(&args[i].as_str()) {
            i += 1;
        } else {
            return Err(format!("Unrecognized argument: {}", args[i]));
        }
    }
    Ok(())
}

fn required(args: &[String], flag: &str) -> Result<String, String> {
    get_flag(args, flag)?.ok_or_else(|| format!("Missing {flag}"))
}

fn select_game(args: &[String]) -> Result<InstalledGame, String> {
    let name = get_flag(args, "--app")?.unwrap_or_else(|| "Rocket League".into());
    Ok(store::find_game(&store::load_installed()?, &name)?.clone())
}

fn register(args: &[String]) -> Result<(), String> {
    if args.iter().any(|arg| arg == "--help") {
        println!("Use: lrb register --app ID --title NAME --path DIRECTORY --exe RELATIVE_EXE --namespace ID [--platform Windows|Linux]");
        return Ok(());
    }
    allowed_flags(args, &["--app", "--title", "--path", "--exe", "--namespace", "--platform"], &[])?;
    let game = InstalledGame {
        app_name: required(args, "--app")?,
        title: required(args, "--title")?,
        install_path: PathBuf::from(required(args, "--path")?),
        executable: PathBuf::from(required(args, "--exe")?),
        namespace: required(args, "--namespace")?,
        platform: get_flag(args, "--platform")?.unwrap_or_else(|| "Windows".into()),
    };
    if !matches!(game.platform.as_str(), "Windows" | "Linux") {
        return Err("Platform must be Windows or Linux".into());
    }
    store::register(game)?;
    println!("Registration saved. Run 'lrb list' or 'lrb launch --dry-run'.");
    Ok(())
}

fn import_egl(args: &[String]) -> Result<(), String> {
    if args.iter().any(|s| s == "--help") {
        println!("Use: lrb import-egl [--manifest FILE | --dir DIR] [--path DIR] [--replace]");
        println!("By default, scans Epic's .item manifests in PROGRAMDATA (Windows) or WINEPREFIX (Linux).");
        return Ok(());
    }
    allowed_flags(args, &["--manifest", "--dir", "--path"], &["--replace"])?;
    let manifest = get_flag(args, "--manifest")?.map(PathBuf::from);
    let dir = get_flag(args, "--dir")?.map(PathBuf::from);
    let path = get_flag(args, "--path")?.map(PathBuf::from);
    let replace = args.iter().any(|s| s == "--replace");
    let game = egl::import(manifest.as_deref(), dir.as_deref(), path.as_deref(), replace)?;
    println!("Imported: {} | {} | {}", game.title, game.app_name, game.install_path.display());
    println!("Next: lrb verify --app \"{}\"; lrb launch --dry-run", game.title);
    Ok(())
}

fn install_options(args: &[String], existing: bool) -> Result<installer::InstallOptions, String> {
    if args.iter().any(|arg| arg == "--help") {
        println!("Use: lrb {} [--app NAME] {} [--workers 1..16] [--dry-run]",if existing {"update/repair"} else {"install"},
            if existing {""} else {"[--dir DIR]"});
        return Err("help requested".into());
    }
    allowed_flags(args, if existing {&["--app","--workers"]} else {&["--app","--dir","--workers"]}, &["--dry-run"])?;
    let app=get_flag(args,"--app")?.unwrap_or_else(||"Rocket League".into());
    let workers=get_flag(args,"--workers")?.unwrap_or_else(||"4".into())
        .parse::<usize>().map_err(|_|"--workers must be an integer from 1 to 16")?;
    let dir=if existing {
        let games=store::load_installed()?;
        let game=store::find_game(&games,&app)?;
        Some(game.install_path.clone())
    } else {
        get_flag(args,"--dir")?.map(PathBuf::from)
    };
    Ok(installer::InstallOptions{app,dir,workers,dry_run:args.iter().any(|v|v=="--dry-run")})
}

fn run_install(args: &[String],existing:bool)->Result<(),String>{
    if args.iter().any(|arg| arg == "--help") {
        println!("Use: lrb {} [--app NAME] {} [--workers 1..16] [--dry-run]",
            if existing {"update/repair"} else {"install"},
            if existing {""} else {"[--dir DIR]"});
        return Ok(());
    }
    installer::install(install_options(args,existing)?)
}

fn online_check(args: &[String]) -> Result<(), String> {
    if args.iter().any(|arg| arg == "--help") {
        println!("Use: lrb online-check [--app ID_OR_TITLE]");
        println!("Checks the local game executable, Epic OAuth session and exchange-code endpoint.");
        println!("Does not prove matchmaking, EAC runtime status or network latency.");
        return Ok(());
    }
    allowed_flags(args, &["--app"], &[])?;
    let game = select_game(args)?;
    let exe = store::executable_path(&game)?;
    println!("Local game executable: {}", exe.display());
    println!("Epic app: {} | namespace: {}", game.app_name, game.namespace);
    epic::online_preflight()?;
    println!("LRB preflight passed. NOT YET TESTED: Rocket League EAC startup, online matchmaking or gameplay.");
    Ok(())
}

fn net_probe(args: &[String]) -> Result<(), String> {
    if args.iter().any(|arg| arg == "--help") {
        println!("Use: lrb net-probe --host HOST [--port 443] [--samples 8] [--timeout-ms 1250] [--json]");
        println!("TCP connect timing to a host of your choice. Not Rocket League match ping.");
        return Ok(());
    }
    allowed_flags(args, &["--host", "--port", "--samples", "--timeout-ms"], &["--json"])?;
    let host = required(args, "--host")?;
    let parse_number = |flag: &str, default: &str| -> Result<u64, String> {
        get_flag(args, flag)?
            .unwrap_or_else(|| default.into())
            .parse::<u64>()
            .map_err(|_| format!("{flag} must be an unsigned integer"))
    };
    let port = u16::try_from(parse_number("--port", "443")?)
        .map_err(|_| "--port is outside 1..65535".to_string())?;
    let samples = u8::try_from(parse_number("--samples", "8")?)
        .map_err(|_| "--samples is outside 1..30".to_string())?;
    let timeout_ms = parse_number("--timeout-ms", "1250")?;
    network::probe(&host, port, samples, timeout_ms, args.iter().any(|s| s == "--json"))
}

fn launch(args: &[String]) -> Result<(), String> {
    allowed_flags(args, &["--app", "--wine"], &["--dry-run"])?;
    let game = select_game(args)?;
    let path = store::executable_path(&game)?;
    let dry_run = args.iter().any(|arg| arg == "--dry-run");
    let wine = get_flag(args, "--wine")?.or_else(|| env::var("LRB_WINE").ok()).unwrap_or_else(|| "wine".into());
    let uses_wine = cfg!(not(windows)) && game.platform == "Windows";
    let mut command = if uses_wine {
        let mut cmd = Command::new(&wine);
        cmd.arg(&path);
        cmd
    } else {
        Command::new(&path)
    };
    command.current_dir(path.parent().ok_or("Cannot determine game working directory")?);
    // During dry-run, no credentials or network requests are made, and secrets are redacted.
    if dry_run {
        println!("Launch preview: {}{}", if uses_wine { format!("{wine} ") } else { String::new() }, path.display());
        println!("Epic portal parameters: -AUTH_PASSWORD=<REDACTED> -epicapp={} -epicsandboxid={}", game.app_name, game.namespace);
        println!("No game was launched. No online authentication was attempted.");
        return Ok(());
    }
    let session = epic::refreshed_session()?;
    let code = epic::game_exchange_token(&session)?;
    let (user_id, display_name) = epic::session_identity(&session);
    command.args([
        "-AUTH_LOGIN=unused".to_string(),
        format!("-AUTH_PASSWORD={code}"),
        "-AUTH_TYPE=exchangecode".to_string(),
        format!("-epicapp={}", game.app_name),
        "-epicenv=Prod".to_string(),
        "-EpicPortal".to_string(),
        format!("-epicusername={display_name}"),
        format!("-epicuserid={user_id}"),
        "-epiclocale=en".to_string(),
        format!("-epicsandboxid={}", game.namespace),
    ]);
    let child = command.spawn().map_err(|err| format!("Unable to launch game: {err}"))?;
    println!("Game process started (PID {}). Launcher exiting.", child.id());
    Ok(())
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    let (command, rest) = match args.split_first() {
        Some((first, rest)) => (first.as_str(), rest),
        None => ("help", &[][..]),
    };
    match command {
        "help" | "--help" | "-h" => { println!("{HELP}"); Ok(()) }
        "doctor" => {
            allowed_flags(rest, &[], &[])?;
            println!("LRB v0.5.0 / OS {} / Rust-native: yes", std::env::consts::OS);
            println!("Data: {}", store::data_dir()?.display());
            println!("Registered games: {}", store::load_installed()?.len());
            println!("Epic online login present: {}", epic::load_session().is_ok());
            println!("Native BuildPatch installer/update/repair: implemented (encrypted payloads not yet supported). Online gameplay: not validated.");
            Ok(())
        }
        "auth" => match rest {
            [] => { println!("Open this Epic login URL, then run lrb auth --code YOUR_CODE:\n{}", epic::login_url()?); Ok(()) }
            [one] if one == "status" => epic::auth_status(),
            [one] if one == "logout" => epic::logout(),
            [flag, code] if flag == "--code" => epic::authorize(code, false),
            [flag, code] if flag == "--exchange-code" => epic::authorize(code, true),
            _ => Err("Use: lrb auth [--code CODE | --exchange-code CODE | status | logout]".into()),
        },
        "library" => { allowed_flags(rest, &[], &[])?; epic::list_library() }
        "list" => {
            allowed_flags(rest, &[], &[])?;
            let games = store::load_installed()?;
            for game in &games { println!("{} | {} | {}", game.app_name, game.title, game.install_path.display()); }
            println!("{} game(s) registered", games.len());
            Ok(())
        }
        "register" => register(rest),
        "import-egl" => import_egl(rest),
        "online-check" => online_check(rest),
        "net-probe" => net_probe(rest),
        "launch" => launch(rest),
        "verify" => {
            allowed_flags(rest, &["--app"], &["--full"])?;
            let game = select_game(rest)?;
            if rest.iter().any(|a|a=="--full") {
                installer::verify(&game)
            } else {
                let path = store::executable_path(&game)?;
                println!("Registered executable exists: {}", path.display());
                println!("For full file-hash/manifest verification, use: lrb verify --full");
                Ok(())
            }
        }
        "install" => run_install(rest,false),
        "update" | "repair" => run_install(rest,true),
        _ => Err(format!("Unknown subcommand '{command}'. Use 'lrb help'.")),
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => { eprintln!("LRB: {err}"); ExitCode::FAILURE }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_rejects_unknown_options() {
        assert!(allowed_flags(&["--unknown".into()], &["--app"], &[]).is_err());
    }

    #[test]
    fn cli_rejects_missing_values() {
        assert!(allowed_flags(&["--app".into()], &["--app"], &[]).is_err());
        assert!(get_flag(&["--app".into()], "--app").is_err());
    }

    #[test]
    fn cli_accepts_game_name_and_dry_run() {
        assert!(allowed_flags(&["--app".into(), "Rocket League".into(), "--dry-run".into()], &["--app"], &["--dry-run"]).is_ok());
    }
}
