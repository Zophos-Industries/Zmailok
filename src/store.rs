use std::io::{ErrorKind, Write};
use std::path::PathBuf;

use zmailok::types::AppError;

fn storage_err(e: impl std::fmt::Display) -> AppError {
    AppError::Storage(e.to_string())
}

fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name).filter(|v| !v.is_empty()).map(PathBuf::from)
}

/// `ZMAILOK_CONFIG_DIR`, else `<config dir>/zmailok` (`%APPDATA%` on Windows, `$XDG_CONFIG_HOME` or `~/.config` elsewhere).
fn config_dir() -> Result<PathBuf, AppError> {
    if let Some(dir) = env_path("ZMAILOK_CONFIG_DIR") {
        return Ok(dir);
    }
    let base = if cfg!(windows) { env_path("APPDATA") } else { env_path("XDG_CONFIG_HOME") }
        .or_else(|| env_path("HOME").or_else(|| env_path("USERPROFILE")).map(|h| h.join(".config")))
        .ok_or_else(|| storage_err("no config directory found, set ZMAILOK_CONFIG_DIR"))?;
    Ok(base.join("zmailok"))
}

pub fn token_path() -> Result<PathBuf, AppError> {
    Ok(config_dir()?.join("token"))
}

/// The saved login token. `ZMAILOK_TOKEN` overrides the file (handy on servers and in CI).
pub fn load() -> Result<Option<String>, AppError> {
    if let Some(token) = std::env::var("ZMAILOK_TOKEN").ok().map(|t| t.trim().to_string()).filter(|t| !t.is_empty()) {
        return Ok(Some(token));
    }
    match std::fs::read_to_string(token_path()?) {
        Ok(text) => Ok(Some(text.trim().to_string()).filter(|t| !t.is_empty())),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(storage_err(e)),
    }
}

/// Writes the token readable by the current user only (mode 600 on Unix).
pub fn save(token: &str) -> Result<PathBuf, AppError> {
    let path = token_path()?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(storage_err)?;
    }
    let _ = std::fs::remove_file(&path); // so the new file is always created with the strict mode
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(&path).map_err(storage_err)?.write_all(token.as_bytes()).map_err(storage_err)?;
    Ok(path)
}

pub fn delete() -> Result<(), AppError> {
    match std::fs::remove_file(token_path()?) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
        Err(e) => Err(storage_err(e)),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn token_roundtrip_with_strict_permissions() {
        let dir = std::env::temp_dir().join(format!("zmailok-test-{}", std::process::id()));
        std::env::set_var("ZMAILOK_CONFIG_DIR", &dir);
        std::env::remove_var("ZMAILOK_TOKEN");
        assert_eq!(super::load().unwrap(), None);
        let path = super::save("secret-token\n").unwrap();
        assert_eq!(super::load().unwrap().as_deref(), Some("secret-token"));
        #[cfg(unix)]
        assert_eq!(std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(&path).unwrap().permissions()) & 0o777, 0o600);
        super::save("second").unwrap(); // overwriting works
        assert_eq!(super::load().unwrap().as_deref(), Some("second"));
        std::env::set_var("ZMAILOK_TOKEN", " from-env ");
        assert_eq!(super::load().unwrap().as_deref(), Some("from-env"), "the environment variable wins");
        std::env::remove_var("ZMAILOK_TOKEN");
        super::delete().unwrap();
        super::delete().unwrap(); // deleting twice is fine
        assert_eq!(super::load().unwrap(), None);
        let _ = std::fs::remove_dir_all(dir);
    }
}
