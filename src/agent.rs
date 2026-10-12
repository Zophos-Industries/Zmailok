//! `zmailok agent`: a daemon for a mail server you run yourself. Every interval it checks the server's
//! IP against blacklists, reads the mail log for bounces and complaints, re-checks the domain's score,
//! and posts to a webhook (Slack or Discord) when something got worse since the last run.

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use colored::Colorize;
use serde::{Deserialize, Serialize};
use zmailok::types::AppError;
use zmailok::{dns, score, verify};

use crate::agent_log::{self, Tally};

const MIN_VOLUME: u64 = 20;
const BOUNCE_ALERT: f64 = 0.05;
const COMPLAINT_ALERT: f64 = 0.001;
const SCORE_DROP_ALERT: i32 = 10;

#[derive(Deserialize)]
struct Config {
    ip: Ipv4Addr,
    domain: String,
    /// A log file path, or "journalctl" to read postfix from the journal.
    mta_log: String,
    #[serde(default = "one_hour")]
    interval: String,
    /// Slack or Discord incoming-webhook URL.
    webhook: Option<String>,
}

fn one_hour() -> String {
    "1h".into()
}

/// What is remembered between runs (`~/.zmailok/agent-state.json`).
#[derive(Serialize, Deserialize, Default)]
struct State {
    last_run: i64,
    offset: Option<u64>,
    blacklisted: Option<bool>,
    config_score: Option<i32>,
}

/// "90", "30m", "1h", "1d". At least one minute.
fn parse_interval(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    let (num, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len()));
    let n: u64 = num.parse().map_err(|_| format!("interval '{s}' must be a number with an optional unit (s, m, h, d)"))?;
    let secs = match unit {
        "" | "s" => n,
        "m" => n * 60,
        "h" => n * 3600,
        "d" => n * 86400,
        other => return Err(format!("unknown interval unit '{other}' (use s, m, h or d)")),
    };
    if secs < 60 {
        return Err("interval must be at least 1m".into());
    }
    Ok(Duration::from_secs(secs))
}

fn state_path() -> PathBuf {
    let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")).unwrap_or_else(|| ".".into());
    PathBuf::from(home).join(".zmailok").join("agent-state.json")
}

fn load_state(path: &Path) -> State {
    std::fs::read_to_string(path).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default()
}

fn save_state(path: &Path, state: &State) -> anyhow::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(path, serde_json::to_string_pretty(state)?)?;
    Ok(())
}

fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn rate(part: u64, total: u64) -> f64 {
    if total == 0 { 0.0 } else { part as f64 / total as f64 }
}

/// Reads the log since the last run and updates the saved offset. None if it could not be read.
async fn read_log(cfg: &Config, state: &mut State) -> Option<Tally> {
    if cfg.mta_log == "journalctl" {
        let since = if state.last_run > 0 { state.last_run } else { now() - 86_400 };
        return match tokio::task::spawn_blocking(move || agent_log::read_journal(since)).await.ok()? {
            Ok(lines) => Some(agent_log::tally(lines.iter().map(String::as_str))),
            Err(e) => {
                eprintln!("{} cannot read the postfix journal: {e}", "warning:".yellow());
                None
            }
        };
    }
    let (path, offset) = (PathBuf::from(&cfg.mta_log), state.offset);
    match tokio::task::spawn_blocking(move || agent_log::read_file(&path, offset)).await.ok()? {
        Ok((lines, next)) => {
            state.offset = Some(next);
            Some(agent_log::tally(lines.iter().map(String::as_str)))
        }
        Err(e) => {
            eprintln!("{} cannot read {}: {e}", "warning:".yellow(), cfg.mta_log);
            None
        }
    }
}

/// One full cycle. Returns true if everything is OK.
async fn cycle(cfg: &Config, state: &mut State) -> anyhow::Result<bool> {
    let mut alerts: Vec<String> = Vec::new();
    let mut rows: Vec<(bool, &str, String)> = Vec::new();

    // Blacklist: the mail server's own IP, on three lists.
    let listed = match dns::ip_blacklisted(cfg.ip).await {
        Ok(l) => Some(l),
        Err(AppError::DnsTimeout) => None,
        Err(e) => return Err(e.into()),
    };
    match listed {
        Some(true) => {
            if state.blacklisted != Some(true) {
                alerts.push(format!("{} is now listed on a blacklist", cfg.ip));
            }
            rows.push((false, "Blacklist", format!("LISTED ({})", cfg.ip)));
        }
        Some(false) => rows.push((true, "Blacklist", "not listed (Spamhaus, Barracuda, SORBS)".into())),
        None => rows.push((false, "Blacklist", "could not be checked (DNS timed out)".into())),
    }
    state.blacklisted = listed.or(state.blacklisted);

    // Mail log: only the part since the last run.
    match read_log(cfg, state).await {
        Some(t) => {
            let volume = t.total();
            let enough = volume >= MIN_VOLUME;
            let (bounce, complaint) = (rate(t.bounced, volume), rate(t.complaints, volume));
            let bounce_ok = !enough || bounce <= BOUNCE_ALERT;
            let complaint_ok = !enough || complaint <= COMPLAINT_ALERT;
            if !bounce_ok {
                alerts.push(format!("bounce rate {:.1}% is above {:.0}%", bounce * 100.0, BOUNCE_ALERT * 100.0));
            }
            if !complaint_ok {
                alerts.push(format!("complaint rate {:.2}% is above {:.1}%", complaint * 100.0, COMPLAINT_ALERT * 100.0));
            }
            rows.push((bounce_ok, "Bounce", format!("{:.1}% ({}/{} since last run)", bounce * 100.0, t.bounced, volume)));
            let note = if t.complaints == 0 { " (postfix does not log complaints by default)" } else { "" };
            rows.push((complaint_ok, "Complaint", format!("{} in the log{note}", t.complaints)));
            rows.push((true, "Volume", format!("{volume} delivered since last run, {} deferred", t.deferred)));
        }
        None => rows.push((false, "Mail log", "could not be read, bounces and complaints not checked".into())),
    }

    // Config score of the domain, checked by the second calculation before it is used.
    let results = dns::check(&cfg.domain).await?;
    let scored = score::compute(&results);
    verify::verify(&results, &scored).map_err(|e| anyhow::anyhow!("score consistency check failed: {e}"))?;
    if results.unverified.is_empty() {
        let total = i32::from(scored.total);
        let dropped = state.config_score.is_some_and(|prev| total < prev - SCORE_DROP_ALERT);
        if dropped {
            alerts.push(format!("config score dropped from {} to {total}", state.config_score.unwrap_or(0)));
        }
        let detail = scored.fixes.first().cloned().unwrap_or_else(|| "all checks pass".into());
        rows.push((!dropped, "Config", format!("{total}/100 ({detail})")));
        state.config_score = Some(total);
    } else {
        rows.push((false, "Config", format!("could not verify {}", results.unverified.join(", "))));
    }

    let all_ok = alerts.is_empty() && rows.iter().all(|(ok, _, _)| *ok);
    print_report(cfg, &rows, all_ok);
    if !alerts.is_empty() {
        post_webhook(cfg, &alerts).await;
    }
    Ok(all_ok)
}

fn print_report(cfg: &Config, rows: &[(bool, &str, String)], all_ok: bool) {
    println!("\nIP: {}   domain: {}\n", cfg.ip, cfg.domain);
    for (ok, name, detail) in rows {
        println!("  {}   {:<11}{detail}", if *ok { "✓".green() } else { "✗".red() }, name);
    }
    println!("\n  {}", if all_ok { "Status: OK".green().bold() } else { "Status: NOT OK".red().bold() });
}

/// Slack and Discord read different fields, so both are sent. Telegram needs its own format.
async fn post_webhook(cfg: &Config, alerts: &[String]) {
    let Some(url) = &cfg.webhook else { return };
    let text = format!("zmailok alert for {} ({}): {}", cfg.domain, cfg.ip, alerts.join("; "));
    let body = serde_json::json!({ "text": text, "content": text });
    match reqwest::Client::new().post(url).json(&body).send().await {
        Ok(r) if r.status().is_success() => {}
        Ok(r) => eprintln!("{} webhook answered {}", "warning:".yellow(), r.status()),
        Err(e) => eprintln!("{} webhook failed: {}", "warning:".yellow(), e.without_url()),
    }
}

/// `zmailok agent`. With `once`, runs one cycle and returns (true = OK). Otherwise runs until stopped.
pub async fn run(config_path: &Path, once: bool) -> anyhow::Result<bool> {
    let cfg: Config = serde_yaml::from_str(&std::fs::read_to_string(config_path)?)?;
    let interval = parse_interval(&cfg.interval).map_err(|e| anyhow::anyhow!(e))?;
    let state_file = state_path();
    let mut state = load_state(&state_file);
    loop {
        let ok = match cycle(&cfg, &mut state).await {
            Ok(ok) => ok,
            Err(e) => {
                println!("{} {e:#}", "cycle failed, retrying next interval:".red());
                false
            }
        };
        state.last_run = now();
        save_state(&state_file, &state)?;
        if once {
            return Ok(ok);
        }
        tokio::time::sleep(interval).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intervals() {
        assert_eq!(parse_interval("1h").unwrap(), Duration::from_secs(3600));
        assert_eq!(parse_interval("30m").unwrap(), Duration::from_secs(1800));
        assert_eq!(parse_interval("1d").unwrap(), Duration::from_secs(86400));
        assert_eq!(parse_interval("120").unwrap(), Duration::from_secs(120));
        assert!(parse_interval("soon").is_err());
        assert!(parse_interval("5x").is_err());
        assert!(parse_interval("10s").is_err(), "below one minute is refused");
    }

    #[test]
    fn rates_do_not_divide_by_zero() {
        assert_eq!(rate(5, 0), 0.0);
        assert!((rate(1, 4) - 0.25).abs() < 1e-9);
    }

    #[test]
    fn config_reads_the_documented_fields() {
        let cfg: Config = serde_yaml::from_str("ip: 203.0.113.42\ndomain: example.com\nmta_log: journalctl\nwebhook: https://hooks.example/x\n").unwrap();
        assert_eq!(cfg.ip, "203.0.113.42".parse::<Ipv4Addr>().unwrap());
        assert_eq!(cfg.interval, "1h", "default interval");
        assert_eq!(cfg.mta_log, "journalctl");
        assert!(serde_yaml::from_str::<Config>("ip: not-an-ip\ndomain: x.com\nmta_log: x\n").is_err());
    }
}
