//! Import existing Rocket League installations from Epic Games Launcher's .item JSON.
use crate::store::{self, InstalledGame};
use serde::Deserialize;
use std::env;
use std::fs;
use std::path::{Component, Path, PathBuf};

const MAX_MANIFEST_SIZE: u64 = 8 * 1024 * 1024;

#[derive(Deserialize)]
struct EpicInstallManifest {
    #[serde(rename = "AppName")]
    app_name: String,
    #[serde(rename = "DisplayName", default)]
    display_name: String,
    #[serde(rename = "CatalogNamespace")]
    namespace: String,
    #[serde(rename = "InstallLocation")]
    install_location: String,
    #[serde(rename = "LaunchExecutable")]
    launch_executable: String,
    #[serde(rename = "bIsIncompleteInstall", default)]
    incomplete: bool,
    #[serde(rename = "bNeedsValidation", default)]
    needs_validation: bool,
}

fn wine_prefix() -> Result<PathBuf, String> {
    env::var_os("WINEPREFIX")
        .map(PathBuf::from)
        .or_else(|| dirs::home_dir().map(|home| home.join(".wine")))
        .ok_or_else(|| "Cannot locate a Wine prefix; set WINEPREFIX or pass --path".into())
}

fn installation_path(raw: &str) -> Result<PathBuf, String> {
    if raw.trim().is_empty() {
        return Err("Epic manifest does not include InstallLocation".into());
    }
    #[cfg(windows)]
    {
        Ok(PathBuf::from(raw))
    }
    #[cfg(not(windows))]
    {
        let bytes = raw.as_bytes();
        if bytes.len() >= 3 && bytes[0].eq_ignore_ascii_case(&b'c') && bytes[1] == b':' &&
            (bytes[2] == b'/' || bytes[2] == b'\\')
        {
            let rest = raw[3..].replace('\\', "/");
            if rest.split('/').any(|part| part == "..") {
                return Err("Epic InstallLocation contains a parent-directory traversal".into());
            }
            return Ok(wine_prefix()?.join("drive_c").join(rest));
        }
        if bytes.len() >= 2 && bytes[1] == b':' {
            return Err("Only Wine C: drive paths auto-map on Linux; pass --path for other drives".into());
        }
        Ok(PathBuf::from(raw))
    }
}

fn decode_manifest(data: &[u8], path_override: Option<&Path>) -> Result<Option<InstalledGame>, String> {
    let manifest: EpicInstallManifest =
        serde_json::from_slice(data).map_err(|e| format!("Invalid Epic manifest JSON: {e}"))?;
    let is_rocket_league = manifest.app_name.eq_ignore_ascii_case("Sugar")
        || manifest.display_name.to_ascii_lowercase().contains("rocket league");
    if !is_rocket_league {
        return Ok(None);
    }
    if manifest.incomplete || manifest.needs_validation {
        return Err("Epic marks this installation incomplete or needing validation; repair it before importing".into());
    }
    if manifest.app_name.trim().is_empty() || manifest.namespace.trim().is_empty() {
        return Err("Rocket League manifest is missing AppName or CatalogNamespace".into());
    }
    let executable = PathBuf::from(manifest.launch_executable.replace('\\', "/"));
    if executable.as_os_str().is_empty()
        || executable.is_absolute()
        || executable.components().any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err("Epic LaunchExecutable must be a safe relative path inside the installation".into());
    }
    let install_path = if let Some(path) = path_override {
        path.to_path_buf()
    } else {
        installation_path(&manifest.install_location)?
    };
    Ok(Some(InstalledGame {
        app_name: manifest.app_name,
        title: if manifest.display_name.trim().is_empty() {
            "Rocket League".into()
        } else {
            manifest.display_name
        },
        install_path,
        executable,
        namespace: manifest.namespace,
        platform: "Windows".into(),
    }))
}

fn read_candidate(path: &Path, path_override: Option<&Path>) -> Result<Option<InstalledGame>, String> {
    let metadata = fs::metadata(path).map_err(|e| format!("Cannot stat {}: {e}", path.display()))?;
    if !metadata.is_file() || metadata.len() > MAX_MANIFEST_SIZE {
        return Err(format!("Manifest is not a regular file or exceeds {MAX_MANIFEST_SIZE} bytes"));
    }
    let data = fs::read(path).map_err(|e| format!("Cannot read {}: {e}", path.display()))?;
    decode_manifest(&data, path_override)
}

pub fn default_manifest_dir() -> Result<PathBuf, String> {
    #[cfg(windows)]
    {
        let program_data = env::var_os("PROGRAMDATA")
            .ok_or_else(|| "PROGRAMDATA is unset; supply --dir or --manifest".to_string())?;
        Ok(PathBuf::from(program_data).join("Epic/EpicGamesLauncher/Data/Manifests"))
    }
    #[cfg(not(windows))]
    {
        Ok(wine_prefix()?.join("drive_c/ProgramData/Epic/EpicGamesLauncher/Data/Manifests"))
    }
}

fn candidate_from_dir(dir: &Path) -> Result<InstalledGame, String> {
    let entries = fs::read_dir(dir)
        .map_err(|e| format!("Cannot read Epic manifest directory {}: {e}", dir.display()))?;
    let mut matches = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| format!("Cannot list Epic manifests: {e}"))?;
        let path = entry.path();
        if !path.extension().and_then(|e| e.to_str()).is_some_and(|e| e.eq_ignore_ascii_case("item")) {
            continue;
        }
        if let Ok(Some(game)) = read_candidate(&path, None) {
            matches.push(game);
        }
    }
    match matches.len() {
        0 => Err(format!("No complete Rocket League .item manifest found in {}. Use --manifest FILE --path DIR to select one.", dir.display())),
        1 => Ok(matches.remove(0)),
        n => Err(format!("Found {n} Rocket League manifests; select one with --manifest FILE")),
    }
}

pub fn import(
    manifest_file: Option<&Path>,
    manifest_dir: Option<&Path>,
    path_override: Option<&Path>,
    replace: bool,
) -> Result<InstalledGame, String> {
    if manifest_file.is_some() && manifest_dir.is_some() {
        return Err("Use --manifest or --dir, not both".into());
    }
    if path_override.is_some() && manifest_file.is_none() {
        return Err("--path requires --manifest (for a relocated or Wine game directory)".into());
    }
    let game = if let Some(manifest) = manifest_file {
        read_candidate(manifest, path_override)?
            .ok_or_else(|| "The selected Epic manifest is not Rocket League".to_string())?
    } else {
        let dir = if let Some(dir) = manifest_dir {
            dir.to_path_buf()
        } else {
            default_manifest_dir()?
        };
        candidate_from_dir(&dir)?
    };
    if !replace && store::load_installed()?.iter().any(|existing|
        existing.app_name.eq_ignore_ascii_case(&game.app_name))
    {
        return Err("This game is already registered; pass --replace to update it".into());
    }
    store::executable_path(&game)?;
    store::register(game.clone())?;
    Ok(game)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str, executable: &str, incomplete: bool) -> Vec<u8> {
        serde_json::json!({
            "AppName": "Sugar",
            "DisplayName": name,
            "CatalogNamespace": "example-namespace",
            "InstallLocation": "/tmp/example",
            "LaunchExecutable": executable,
            "bIsIncompleteInstall": incomplete,
            "bNeedsValidation": false
        }).to_string().into_bytes()
    }

    #[test]
    fn decodes_rocket_league_and_normalizes_windows_relative_executable() {
        let data = fixture("Rocket League", r"Binaries\Win64\RocketLeague.exe", false);
        let game = decode_manifest(&data, Some(Path::new("/tmp/rocket")))
            .unwrap().unwrap();
        assert_eq!(game.app_name, "Sugar");
        assert_eq!(game.namespace, "example-namespace");
        assert_eq!(game.executable, PathBuf::from("Binaries/Win64/RocketLeague.exe"));
        assert_eq!(game.install_path, PathBuf::from("/tmp/rocket"));
    }

    #[test]
    fn rejects_incomplete_and_path_traversal() {
        assert!(decode_manifest(&fixture("Rocket League", "Game.exe", true), None).is_err());
        assert!(decode_manifest(&fixture("Rocket League", "../outside.exe", false), None).is_err());
    }

    #[test]
    fn ignores_unrelated_titles() {
        let data = br#"{"AppName":"DifferentGame","DisplayName":"Other Game","CatalogNamespace":"ns","InstallLocation":"/tmp","LaunchExecutable":"Game.exe"}"#;
        assert!(decode_manifest(data, None).unwrap().is_none());
    }

    #[test]
    fn enforces_manifest_and_path_exclusivity() {
        assert!(import(None, None, Some(Path::new("/tmp")), false).is_err());
        assert!(import(Some(Path::new("one.item")), Some(Path::new(".")), None, false).is_err());
    }

    #[cfg(not(windows))]
    #[test]
    fn refuses_non_c_wine_drives_without_override() {
        assert!(installation_path(r"D:\Games\RocketLeague").is_err());
    }
}
