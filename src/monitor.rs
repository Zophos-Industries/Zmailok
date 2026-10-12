use colored::Colorize;
use zmailok::{dns, domain, output::PASS_SCORE, score, types::AppError};

use crate::{api::Api, browser};

pub async fn list(api: &Api) -> Result<(), AppError> {
    let rows = api.domains().await?;
    if rows.is_empty() {
        println!("No domains are monitored yet. Add one with: zmailok monitor add example.com");
        return Ok(());
    }
    println!("{:<34}{:>6}   {}", "DOMAIN", "SCORE", "LAST CHECKED");
    for row in rows {
        let score = match row.last_score {
            Some(s) if s >= i32::from(PASS_SCORE) => format!("{s:>6}").green(),
            Some(s) if s >= 50 => format!("{s:>6}").yellow(),
            Some(s) => format!("{s:>6}").red(),
            None => format!("{:>6}", "-").dimmed(),
        };
        println!("{:<34}{}   {}", row.domain, score, row.last_checked.as_deref().unwrap_or("not checked yet"));
    }
    Ok(())
}

pub async fn add(api: &Api, raw: &str) -> Result<(), AppError> {
    let domain = domain::normalize(raw)?;
    api.add_domain(&domain).await?;
    println!("{} Now monitoring {domain}. It is checked every 6 hours, and you get an email if its score drops by more than 10 points.", "✓".green());
    // The service's first check can be hours away, so show where the domain stands right now.
    // Best effort: a failed local check must not make a successful add look like a failure.
    match dns::check(&domain).await {
        Ok(results) => println!("  Current score: {}/100 (details: zmailok check {domain})", score::compute(&results).total),
        Err(e) => println!("  (could not run a check right now: {e})"),
    }
    Ok(())
}

pub async fn remove(api: &Api, raw: &str) -> Result<(), AppError> {
    let domain = domain::normalize(raw)?;
    api.remove_domain(&domain).await?;
    println!("{} Stopped monitoring {domain}.", "✓".green());
    Ok(())
}

pub async fn upgrade(api: &Api) -> Result<(), AppError> {
    let url = api.checkout().await?;
    println!("Open this link to subscribe ($5/month, up to 5 monitored domains):\n\n  {url}\n");
    if browser::open(&url) {
        println!("(opened it in your browser)");
    }
    Ok(())
}

/// "Check now" for a monitored domain. Returns whether the score passes (for the exit code).
pub async fn check(api: &Api, raw: &str) -> Result<bool, AppError> {
    let domain = domain::normalize(raw)?;
    let r = api.check_now(&domain).await?;
    println!("{} — {}/100  (checked just now, the stored score is updated)\n", r.domain, r.score);
    for c in &r.checks {
        println!("  {}   {}", if c.passed { "✓".green() } else { "✗".red() }, c.name);
    }
    if let Some(note) = &r.note {
        println!("\n  {}", note.dimmed());
    }
    let passed = r.score >= PASS_SCORE;
    let n = r.fixes.len();
    println!("\n  {} {}/100 — {} — {} {} found", "Score:".bold(), r.score, if passed { "OK" } else { "NOT OK" }, n, if n == 1 { "issue" } else { "issues" });
    if !r.fixes.is_empty() {
        println!("\n  {}", "Fixes:".bold());
        for (i, fix) in r.fixes.iter().enumerate() {
            println!("  {}. {fix}", i + 1);
        }
    }
    Ok(passed)
}

/// `zmailok account`: whether the subscription is active and how many domains are monitored.
pub async fn account(api: &Api) -> Result<(), AppError> {
    let a = api.account().await?;
    println!("{}", "Account".bold());
    println!("  Plan:     {}", if a.active { "monitoring (subscribed)".green() } else { "free (no subscription)".yellow() });
    println!("  Domains:  {} of {} monitored", a.domains, a.limit);
    if !a.active {
        println!("\n  Subscribe with: zmailok upgrade");
    }
    Ok(())
}
