use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InstalledGame {
    pub app_name: String,
    pub title: String,
    pub install_path: PathBuf,
    pub executable: PathBuf,
    pub namespace: String,
    #[serde(default)]
    pub deployment_id: Option<String>,
    #[serde(default = "default_platform")]
    pub platform: String,
}

fn default_platform() -> String {
    "Windows".into()
}

pub fn data_dir() -> Result<PathBuf, String> {
    if let Some(dir) = std::env::var_os("LRB_HOME") {
        if dir.is_empty() {
            return Err("LRB_HOME cannot be empty".into());
        }
        return Ok(PathBuf::from(dir));
    }
    dirs::config_dir()
        .map(|path| path.join("LegendaryRustBucket"))
        .ok_or_else(|| "Cannot find user config directory; set LRB_HOME".into())
}

pub fn load_installed_from(dir: &Path) -> Result<Vec<InstalledGame>, String> {
    let path = dir.join("installed.json");
    let data = match fs::read(&path) {
        Ok(data) => data,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(format!("Cannot read {}: {err}", path.display())),
    };
    serde_json::from_slice(&data).map_err(|err| format!("Invalid {}: {err}", path.display()))
}

pub fn load_installed() -> Result<Vec<InstalledGame>, String> {
    load_installed_from(&data_dir()?)
}

pub fn save_json<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| format!("Creating {}: {err}", parent.display()))?;
    }
    let json = serde_json::to_vec_pretty(value).map_err(|err| err.to_string())?;
    let mut options = OpenOptions::new();
    options.create(true).write(true).truncate(true);
    // Restrict credential files to the current user on Unix; Windows uses the user's ACL.
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|err| format!("Opening {}: {err}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|err| format!("Protecting {}: {err}", path.display()))?;
    }
    file.write_all(&json).map_err(|err| format!("Saving {}: {err}", path.display()))?;
    file.sync_all().map_err(|err| format!("Syncing {}: {err}", path.display()))
}

pub fn register(game: InstalledGame) -> Result<(), String> {
    let dir = data_dir()?;
    let mut games = load_installed_from(&dir)?;
    if game.app_name.is_empty() || game.namespace.is_empty() || game.title.is_empty() {
        return Err("App name, title and namespace must be supplied".into());
    }
    let _ = executable_path(&game)?;
    games.retain(|other| !other.app_name.eq_ignore_ascii_case(&game.app_name));
    games.push(game);
    save_json(&dir.join("installed.json"), &games)
}

pub fn find_game<'a>(games: &'a [InstalledGame], selector: &str) -> Result<&'a InstalledGame, String> {
    games
        .iter()
        .find(|game| game.app_name.eq_ignore_ascii_case(selector) || game.title.eq_ignore_ascii_case(selector))
        .ok_or_else(|| format!("Game '{selector}' not registered. Use: lrb list and lrb register --help"))
}

pub fn executable_path(game: &InstalledGame) -> Result<PathBuf, String> {
    use std::path::Component;
    if game.executable.is_absolute() || game.executable.components().any(|component| !matches!(component, Component::Normal(_))) {
        return Err("Executable must be a relative path without '..' components".into());
    }
    let root = game.install_path.canonicalize()
        .map_err(|err| format!("Cannot access installation {}: {err}", game.install_path.display()))?;
    let path = root.join(&game.executable).canonicalize()
        .map_err(|err| format!("Executable missing under installation: {err}"))?;
    if !path.starts_with(&root) || !path.is_file() {
        return Err("Executable does not point to a file within the installation".into());
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn game_matching_is_case_insensitive() {
        let game = InstalledGame { app_name: "Sugar".into(), title: "Rocket League".into(), install_path: "/tmp".into(), executable: "file.exe".into(), namespace: "ns".into(), platform: "Windows".into(), deployment_id: None };
        let games = [game];
        assert!(find_game(&games, "rocket league").is_ok());
        assert!(find_game(&games, "sugar").is_ok());
        assert!(find_game(&games, "another").is_err());
    }

    #[test]
    fn missing_registry_is_empty() {
        let path = std::env::temp_dir().join(format!("lrb-nonexistent-{}-{}", std::process::id(), "installed"));
        assert!(load_installed_from(&path).expect("load").is_empty());
    }

    #[test]
    fn rejects_relative_traversal_before_touching_disk() {
        let game = InstalledGame { app_name: "x".into(), title: "x".into(), install_path: "/this/must/not/exist".into(), executable: "../private.exe".into(), namespace: "ns".into(), platform: "Windows".into(), deployment_id: None };
        assert!(executable_path(&game).is_err());
    }
}
