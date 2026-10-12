use std::time::Duration;

use serde::Deserialize;
use serde_json::{json, Value};
use zmailok::types::AppError;

const DEFAULT_BASE: &str = "https://api.zmailok.com";

#[derive(Deserialize)]
pub struct DomainRow {
    pub domain: String,
    pub last_score: Option<i32>,
    pub last_checked: Option<String>,
}

#[derive(Deserialize)]
pub struct CheckedRow {
    pub name: String,
    pub passed: bool,
}

/// The answer to "check now": the score the monitor would compute, for one domain, right away.
#[derive(Deserialize)]
pub struct CheckNow {
    pub domain: String,
    pub score: u8,
    pub checks: Vec<CheckedRow>,
    pub fixes: Vec<String>,
    pub note: Option<String>,
}

/// Client for the hosted zmailok service (login and monitoring). `zmailok check` never uses it.
pub struct Api {
    base: String,
    http: reqwest::Client,
    token: Option<String>,
}

fn network_err(e: reqwest::Error) -> AppError {
    AppError::Api(format!("cannot reach the zmailok service: {}", e.without_url()))
}

/// The login token is only ever sent over HTTPS (plain http is allowed for localhost development).
fn check_base(base: &str) -> Result<(), AppError> {
    let local = ["http://localhost", "http://127.0.0.1"]
        .iter()
        .any(|p| base.strip_prefix(p).is_some_and(|rest| rest.is_empty() || rest.starts_with(':') || rest.starts_with('/')));
    if base.starts_with("https://") || local { Ok(()) } else { Err(AppError::Api(format!("ZMAILOK_API must be an https:// address, got {base}"))) }
}

/// Turns an error response into a message that tells the user what to do next.
fn explain(status: u16, body: &str) -> AppError {
    let short: String = body.chars().take(100).collect();
    match status {
        401 => AppError::NotLoggedIn,
        402 => AppError::Api("monitoring needs a subscription ($5/month, 5 domains). Run: zmailok upgrade".into()),
        403 => AppError::Api("domain limit reached (5 domains per account). Remove one first: zmailok monitor remove <domain>".into()),
        409 => AppError::Api("you are already subscribed".into()),
        404 => AppError::Api("that domain is not in your monitored list. Add it first: zmailok monitor add <domain>".into()),
        429 => AppError::Api("too many requests: a domain can be re-checked once a minute, try again shortly".into()),
        400 => AppError::Api(format!("the service rejected the request: {short}")),
        s if s >= 500 => AppError::Api(format!("the zmailok service has a problem (HTTP {s}), try again later")),
        s => AppError::Api(format!("unexpected answer from the service (HTTP {s}): {short}")),
    }
}

impl Api {
    pub fn new(token: Option<String>) -> Result<Api, AppError> {
        let base = std::env::var("ZMAILOK_API").unwrap_or_else(|_| DEFAULT_BASE.to_string()).trim_end_matches('/').to_string();
        check_base(&base)?;
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .user_agent(concat!("zmailok-cli/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(network_err)?;
        Ok(Api { base, http, token })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    async fn send(&self, req: reqwest::RequestBuilder, logged_in: bool) -> Result<reqwest::Response, AppError> {
        let req = match (&self.token, logged_in) {
            (Some(t), true) => req.bearer_auth(t),
            (None, true) => return Err(AppError::NotLoggedIn),
            _ => req,
        };
        let resp = req.send().await.map_err(network_err)?;
        let status = resp.status();
        if status.is_success() {
            return Ok(resp);
        }
        Err(explain(status.as_u16(), &resp.text().await.unwrap_or_default()))
    }

    /// Sends the agent's latest check to the dashboard (paying accounts only).
    pub async fn agent_report(&self, report: &serde_json::Value) -> Result<(), AppError> {
        self.send(self.http.post(self.url("/api/agent/report")).json(report), true).await.map(drop)
    }

    pub async fn account(&self) -> Result<Account, AppError> {
        self.send(self.http.get(self.url("/api/me")), true).await?.json().await.map_err(network_err)
    }

    /// Exchanges the GitHub token from the device flow for a zmailok session token.
    pub async fn device_login(&self, github_token: &str) -> Result<String, AppError> {
        let req = self.http.post(self.url("/auth/github/device")).json(&json!({ "access_token": github_token }));
        let body: Value = self.send(req, false).await?.json().await.map_err(network_err)?;
        body["token"].as_str().map(String::from).ok_or_else(|| AppError::Api("the login answer had no token".into()))
    }

    pub async fn domains(&self) -> Result<Vec<DomainRow>, AppError> {
        self.send(self.http.get(self.url("/api/domains")), true).await?.json().await.map_err(network_err)
    }

    pub async fn add_domain(&self, domain: &str) -> Result<(), AppError> {
        self.send(self.http.post(self.url("/api/domains")).json(&json!({ "domain": domain })), true).await.map(drop)
    }

    /// `domain` must already be normalized (letters, digits, dots, hyphens only).
    pub async fn remove_domain(&self, domain: &str) -> Result<(), AppError> {
        self.send(self.http.delete(self.url(&format!("/api/domains/{domain}"))), true).await.map(drop)
    }

    /// Returns the Stripe Checkout link for the monthly plan.
    pub async fn checkout(&self) -> Result<String, AppError> {
        let body: Value = self.send(self.http.post(self.url("/api/checkout")), true).await?.json().await.map_err(network_err)?;
        body["url"].as_str().map(String::from).ok_or_else(|| AppError::Api("the service returned no checkout link".into()))
    }

    /// Runs a check on the service right now for one of your monitored domains and stores the score.
    pub async fn check_now(&self, domain: &str) -> Result<CheckNow, AppError> {
        self.send(self.http.post(self.url(&format!("/api/domains/{domain}/check"))), true).await?.json().await.map_err(network_err)
    }

    pub async fn logout(&self) -> Result<(), AppError> {
        self.send(self.http.post(self.url("/auth/logout")), true).await.map(drop)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_https_or_local_http_is_accepted() {
        for ok in ["https://api.zmailok.com", "https://example.org:8443", "http://localhost", "http://localhost:8080", "http://127.0.0.1:8080/x"] {
            assert!(check_base(ok).is_ok(), "{ok}");
        }
        for bad in ["http://api.zmailok.com", "http://localhost.evil.com", "http://127.0.0.1.evil.com", "ftp://x", "api.zmailok.com", ""] {
            assert!(check_base(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn errors_tell_the_user_what_to_do() {
        assert!(matches!(explain(401, ""), AppError::NotLoggedIn));
        assert!(explain(402, "").to_string().contains("zmailok upgrade"));
        assert!(explain(403, "").to_string().contains("5 domains"));
        assert!(explain(409, "").to_string().contains("already subscribed"));
        assert!(explain(404, "").to_string().contains("monitor add"));
        assert!(explain(429, "").to_string().contains("once a minute"));
        assert!(explain(503, "x").to_string().contains("HTTP 503"));
        assert!(explain(418, &"y".repeat(500)).to_string().len() < 200);
    }
}

#[derive(Deserialize)]
pub struct Account {
    pub active: bool,
    pub domains: u32,
    pub limit: u32,
}
