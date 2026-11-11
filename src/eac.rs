//! Official Rocket League Easy Anti-Cheat (EOS) installation and diagnostics.
//!
//! This module launches only the game's bundled EAC service setup on an
//! explicit user request. It never patches, bypasses, injects or disables EAC.
use crate::store::InstalledGame;
use std::fs;
use std::path::{Path, PathBuf};
#[cfg(windows)]
use std::process::Command;

/// Rocket League ProductId from Epic's public EAC installation instructions.
/// https://www.epicgames.com/help/c-37599050/a18535670
const ROCKET_LEAGUE_PRODUCT_ID: &str = "e6bcca5b37d0457ca881aec508205542";

fn is_rocket_league(game: &InstalledGame) -> bool {
    game.app_name.eq_ignore_ascii_case("Sugar")
        || game.title.eq_ignore_ascii_case("Rocket League")
}

fn is_protected_entrypoint(game: &InstalledGame) -> bool {
    let name = game.executable.file_name().and_then(|name| name.to_str()).unwrap_or("");
    ["Launcher.exe", "RocketLeague_EAC.exe", "start_protected_game.exe"]
        .iter()
        .any(|allowed| name.eq_ignore_ascii_case(allowed))
}

fn eac_candidates(root: &Path) -> [(PathBuf, PathBuf); 2] {
    ["EasyAntiCheat", "EasyAntiCheat_EOS"].map(|folder| {
        let dir = root.join("Binaries").join("Win64").join(folder);
        (
            dir.join("EasyAntiCheat_EOS_Setup.exe"),
            dir.join("Settings.json"),
        )
    })
}

fn inspect(root: &Path) -> Result<(PathBuf, PathBuf), String> {
    // The game folder must be a real directory. Do not follow any symlink /
    // junction that escapes it when launching a privileged setup binary.
    let root = root
        .canonicalize()
        .map_err(|err| format!("Cannot locate game installation: {err}"))?;
    let mut saw_setup = false;
    let mut saw_settings = false;
    for (setup, settings) in eac_candidates(&root) {
        let setup_found = setup.is_file();
        let settings_found = settings.is_file();
        saw_setup |= setup_found;
        saw_settings |= settings_found;
        if !(setup_found && settings_found) {
            continue;
        }
        let resolved = setup.canonicalize().map_err(|err| err.to_string())?;
        if !resolved.starts_with(&root) {
            return Err("EAC installer resolves outside the game directory".into());
        }
        let resolved_settings = settings.canonicalize().map_err(|err| err.to_string())?;
        if !resolved_settings.starts_with(&root) {
            return Err("EAC settings resolve outside the game directory".into());
        }
        let bytes = fs::read(&resolved_settings)
            .map_err(|err| format!("Cannot read EAC settings: {err}"))?;
        if bytes.len() > 128 * 1024 {
            return Err("EAC settings file is unusually large".into());
        }
        validate_settings(&bytes)?;
        return Ok((resolved, resolved_settings));
    }
    if !saw_setup {
        return Err(
            "Bundled EasyAntiCheat_EOS_Setup.exe not found. Run 'lrb verify --full' \
             and 'lrb repair' before trying to play online."
                .into(),
        );
    }
    if !saw_settings {
        return Err(
            "EAC Settings.json is missing. Run 'lrb verify --full' and 'lrb repair'.".into(),
        );
    }
    Err("EAC setup and settings were found in different directories; repair the game files".into())
}

fn validate_settings(bytes: &[u8]) -> Result<(), String> {
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|err| format!("EAC Settings.json is invalid JSON: {err}"))?;
    let id = value
        .get("productid")
        .or_else(|| value.get("ProductId"))
        .or_else(|| value.get("productId"))
        .and_then(serde_json::Value::as_str)
        .ok_or("EAC Settings.json has no ProductId")?;
    if !id.eq_ignore_ascii_case(ROCKET_LEAGUE_PRODUCT_ID) {
        return Err(format!(
            "EAC ProductId {id:?} is not the official Rocket League ProductId; refusing service installation"
        ));
    }
    Ok(())
}

/// Query Windows' actual EAC service registration. A STOPPED service still
/// counts as installed; it normally runs only while an EAC game is active.
#[cfg(windows)]
fn service_installed() -> Result<bool, String> {
    let result = Command::new("sc.exe")
        .args(["query", "EasyAntiCheat_EOS"])
        .output()
        .map_err(|err| format!("Cannot query Windows EAC service using sc.exe: {err}"))?;
    Ok(result.status.success())
}

pub fn status(game: &InstalledGame) -> Result<(), String> {
    if !is_rocket_league(game) {
        return Err("EAC status is currently supported for Rocket League only".into());
    }
    if !is_protected_entrypoint(game) {
        return Err("The registered game executable does not appear to be the official EAC bootstrapper. Use the Epic manifest launcher (typically Binaries/Win64/Launcher.exe) rather than RocketLeague.exe for online play.".into());
    }
    match inspect(&game.install_path) {
        Ok((exe, settings)) => {
            println!("Rocket League EAC setup: {}", exe.display());
            println!("EAC product settings: {} (Rocket League ProductId verified)", settings.display());
        }
        Err(err) => {
            println!("Rocket League EAC game files: NOT READY — {err}");
            return Err("EAC prerequisites missing; cannot claim online compatibility".into());
        }
    }
    #[cfg(windows)]
    match service_installed() {
        Ok(true) => println!("Windows EasyAntiCheat_EOS service: registered (not proof of a successful online match)"),
        Ok(false) => {
            println!("Windows EasyAntiCheat_EOS service: NOT registered");
            return Err(
                "Install the official service from an Administrator Command Prompt using: lrb eac install".into(),
            );
        }
        Err(err) => return Err(err),
    }
    #[cfg(not(windows))]
    println!("Windows EAC service: not applicable on this OS; Wine/Proton online status unverified");
    Ok(())
}

/// Perform a user-explicit, official EOS service setup invocation.
/// Requires an elevated Windows terminal (administrator); no UAC or
/// security/anti-cheat protections are bypassed.
pub fn install(game: &InstalledGame) -> Result<(), String> {
    if !is_rocket_league(game) {
        return Err("Only Rocket League EAC installation is supported".into());
    }
    #[cfg(not(windows))]
    {
        let _ = game;
        Err("EAC Windows service installation must be performed on Windows. \
             Linux/Proton EAC setup differs and is not implemented."
            .into())
    }
    #[cfg(windows)]
    {
        let (exe, _settings) = inspect(&game.install_path)?;
        println!("Launching the official Rocket League EAC setup from:");
        println!("  {}", exe.display());
        println!("Service installation may require administrator permission.");
        let result = Command::new(&exe)
            .args(["install", ROCKET_LEAGUE_PRODUCT_ID])
            .current_dir(exe.parent().ok_or("Cannot find EAC setup directory")?)
            .status()
            .map_err(|err| format!("Cannot start EAC setup: {err}. Open Command Prompt as Administrator"))?;
        if !result.success() {
            return Err(format!(
                "Official EAC installer failed with status {result}; \
                 retry from an Administrator Command Prompt"
            ));
        }
        match service_installed()? {
            true => {
                println!("EAC service registered. Run 'lrb eac status', then 'lrb launch'.");
                println!("A successful online match is still required to validate online compatibility.");
                Ok(())
            }
            false => Err(
                "The setup process returned success but the EAC Windows service is not registered. \
                 Retry as Administrator, then consult Epic's official EAC instructions.".into(),
            ),
        }
    }
}

/// Called only for a real Windows Rocket League launch, never for --dry-run.
/// Does not install system services implicitly.
pub fn require_for_online_launch(game: &InstalledGame) -> Result<(), String> {
    if !is_rocket_league(game) || !cfg!(windows) || game.platform != "Windows" {
        return Ok(());
    }
    // Launch protected games through an anti-cheat bootstrapper, not the
    // unprotected game binary. The official game manifest currently uses
    // Binaries/Win64/Launcher.exe on Epic.
    if !is_protected_entrypoint(game) {
        return Err("Online Rocket League must use its official EAC bootstrapper. The registered executable appears to be a direct game executable; import or reinstall the current Epic game manifest.".into());
    }
    inspect(&game.install_path)?;
    #[cfg(windows)]
    if !service_installed()? {
        return Err(
            "Easy Anti-Cheat is not installed as a Windows service. Open an \
             Administrator Command Prompt and run 'lrb eac install'; then retry 'lrb launch'."
                .into(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rocket_league_product_id_is_checked() {
        let good = format!(r#"{{"ProductId":"{}"}}"#, ROCKET_LEAGUE_PRODUCT_ID);
        assert!(validate_settings(good.as_bytes()).is_ok());
        assert!(validate_settings(br#"{"ProductId":"other-game"}"#).is_err());
        assert!(validate_settings(br#"{"SomethingElse":"x"}"#).is_err());
        assert!(validate_settings(b"not-json").is_err());
    }
    #[test]
    fn eac_paths_only_under_game_install() {
        let root = Path::new("D:/Games/RocketLeague");
        let all = eac_candidates(root);
        assert_eq!(
            all[0].0,
            root.join("Binaries/Win64/EasyAntiCheat/EasyAntiCheat_EOS_Setup.exe")
        );
        assert_eq!(
            all[1].1,
            root.join("Binaries/Win64/EasyAntiCheat_EOS/Settings.json")
        );
    }
    #[test]
    fn checks_correct_game_only() {
        let mut game = InstalledGame {
            app_name: "Sugar".into(),
            title: "Rocket League".into(),
            install_path: PathBuf::new(),
            executable: "Binaries/Win64/Launcher.exe".into(),
            namespace: "epic".into(),
            deployment_id: None,
            platform: "Windows".into(),
        };
        assert!(is_rocket_league(&game));
        game.app_name = "Other".into();
        game.title = "Other Game".into();
        assert!(!is_rocket_league(&game));
        assert!(is_protected_entrypoint(&game));
        game.executable = "Binaries/Win64/RocketLeague.exe".into();
        assert!(!is_protected_entrypoint(&game));
    }
}
