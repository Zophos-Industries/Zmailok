use std::time::{Duration, Instant};

use colored::Colorize;
use serde::Deserialize;
use serde_json::Value;
use zmailok::types::AppError;

use crate::{api::Api, browser, store};

/// Public identifier of the zmailok GitHub app (like every OAuth client id, not a secret).
const GITHUB_CLIENT_ID: &str = "Ov23liad3YSHZ6YtUHAx";
const DEVICE_CODE_URL: &str = "https://github.com/login/device/code";
const ACCESS_TOKEN_URL: &str = "https://github.com/login/oauth/access_token";

#[derive(Deserialize)]
struct DeviceCode {
    device_code: String,
    user_code: String,
    verification_uri: String,
    expires_in: u64,
    interval: Option<u64>,
}

#[derive(Debug, PartialEq)]
enum Poll {
    Token(String),
    Wait,
    SlowDown,
    Fail(String),
}

fn github_err(e: reqwest::Error) -> AppError {
    AppError::Api(format!("cannot reach GitHub: {}", e.without_url()))
}

/// Reads GitHub's answer to one poll of the device flow.
fn poll_step(answer: &Value) -> Poll {
    if let Some(token) = answer["access_token"].as_str() {
        return Poll::Token(token.to_string());
    }
    match answer["error"].as_str() {
        Some("authorization_pending") => Poll::Wait,
        Some("slow_down") => Poll::SlowDown,
        Some("expired_token") => Poll::Fail("the code expired. Run: zmailok login".into()),
        Some("access_denied") => Poll::Fail("the login was cancelled on GitHub".into()),
        Some(other) => Poll::Fail(format!("GitHub said: {other}")),
        None => Poll::Fail("unexpected answer from GitHub".into()),
    }
}

/// GitHub device flow: the terminal shows a code, the user approves it on github.com, no redirect needed.
pub async fn run(api: &Api) -> Result<(), AppError> {
    let client_id = std::env::var("ZMAILOK_GITHUB_CLIENT_ID").unwrap_or_else(|_| GITHUB_CLIENT_ID.to_string());
    let http = reqwest::Client::builder().timeout(Duration::from_secs(20)).build().map_err(github_err)?;

    let started: Value = http
        .post(DEVICE_CODE_URL)
        .header("Accept", "application/json")
        .form(&[("client_id", client_id.as_str()), ("scope", "read:user user:email")])
        .send().await.map_err(github_err)?
        .json().await.map_err(github_err)?;
    if let Some(err) = started["error"].as_str() {
        return Err(AppError::Api(format!("GitHub refused to start the login: {err}")));
    }
    let code: DeviceCode = serde_json::from_value(started).map_err(|e| AppError::Api(format!("unexpected answer from GitHub: {e}")))?;

    println!("To log in, open {} and enter this code:\n\n    {}\n", code.verification_uri.bold(), code.user_code.bold().green());
    if browser::open(&code.verification_uri) {
        println!("(opened it in your browser)");
    }
    println!("Waiting for you to approve it...");

    let deadline = Instant::now() + Duration::from_secs(code.expires_in);
    let mut interval = code.interval.unwrap_or(5).max(1);
    let github_token = loop {
        tokio::time::sleep(Duration::from_secs(interval)).await;
        if Instant::now() > deadline {
            return Err(AppError::Api("the code expired. Run: zmailok login".into()));
        }
        let answer: Value = http
            .post(ACCESS_TOKEN_URL)
            .header("Accept", "application/json")
            .form(&[
                ("client_id", client_id.as_str()),
                ("device_code", code.device_code.as_str()),
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ])
            .send().await.map_err(github_err)?
            .json().await.map_err(github_err)?;
        match poll_step(&answer) {
            Poll::Token(t) => break t,
            Poll::Wait => {}
            Poll::SlowDown => interval += 5,
            Poll::Fail(why) => return Err(AppError::Api(why)),
        }
    };

    let session = api.device_login(&github_token).await?;
    let path = store::save(&session)?;
    println!("{} Logged in. Your login is saved in {}", "✓".green(), path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn reads_every_answer_github_can_give() {
        assert_eq!(poll_step(&json!({"access_token": "gho_x", "token_type": "bearer"})), Poll::Token("gho_x".into()));
        assert_eq!(poll_step(&json!({"error": "authorization_pending"})), Poll::Wait);
        assert_eq!(poll_step(&json!({"error": "slow_down", "interval": 10})), Poll::SlowDown);
        assert!(matches!(poll_step(&json!({"error": "expired_token"})), Poll::Fail(m) if m.contains("expired")));
        assert!(matches!(poll_step(&json!({"error": "access_denied"})), Poll::Fail(m) if m.contains("cancelled")));
        assert!(matches!(poll_step(&json!({"error": "device_flow_disabled"})), Poll::Fail(m) if m.contains("device_flow_disabled")));
        assert!(matches!(poll_step(&json!({})), Poll::Fail(_)));
    }
}
