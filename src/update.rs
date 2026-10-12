use std::process::Command;

use colored::Colorize;
use zmailok::types::AppError;

const CRATE_API: &str = "https://crates.io/api/v1/crates/zmailok";

/// "0.10.1" -> (0, 10, 1). Anything after the numbers (like "-beta") is ignored.
fn parse_version(v: &str) -> Option<(u64, u64, u64)> {
    let mut parts = v.trim().split(['.', '-', '+']).map(|p| p.parse::<u64>().ok());
    Some((parts.next()??, parts.next()??, parts.next()??))
}

pub fn is_newer(latest: &str, current: &str) -> bool {
    matches!((parse_version(latest), parse_version(current)), (Some(l), Some(c)) if l > c)
}

/// `zmailok update`: asks crates.io for the newest version and reinstalls it with cargo if there is one.
pub async fn run() -> Result<(), AppError> {
    let current = env!("CARGO_PKG_VERSION");
    let http = reqwest::Client::builder()
        .user_agent(concat!("zmailok-cli/", env!("CARGO_PKG_VERSION")))
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .map_err(|e| AppError::Api(e.to_string()))?;
    let body: serde_json::Value = http
        .get(CRATE_API)
        .send().await.map_err(|e| AppError::Api(format!("cannot reach crates.io: {}", e.without_url())))?
        .json().await.map_err(|e| AppError::Api(e.to_string()))?;
    let latest = body["crate"]["max_version"].as_str().ok_or_else(|| AppError::Api("crates.io gave no version".into()))?;

    if !is_newer(latest, current) {
        println!("{} zmailok {current} is up to date.", "✓".green());
        return Ok(());
    }
    println!("zmailok {current} is installed, {latest} is available. Installing it with cargo...\n");
    let status = Command::new("cargo")
        .args(["install", "zmailok", "--locked", "--force"])
        .status()
        .map_err(|e| AppError::Api(format!("cannot run cargo ({e}). Install Rust from https://rustup.rs, then run: cargo install zmailok --force")))?;
    if status.success() {
        println!("\n{} zmailok {latest} installed.", "✓".green());
        Ok(())
    } else {
        Err(AppError::Api("cargo install failed, see the output above".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compares_versions_numerically() {
        assert!(is_newer("0.2.0", "0.1.0"));
        assert!(is_newer("0.10.0", "0.9.9"), "10 is newer than 9, not a string comparison");
        assert!(!is_newer("0.1.0", "0.1.0"));
        assert!(!is_newer("0.1.0", "0.2.0"));
        assert!(!is_newer("garbage", "0.1.0"), "an unreadable version is never 'newer'");
    }
}
