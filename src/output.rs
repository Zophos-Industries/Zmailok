use colored::Colorize;

use crate::types::{DnsResults, Score};

pub const PASS_SCORE: u8 = 80;

pub fn print_report(domain: &str, results: &DnsResults, score: &Score) {
    println!("{} — {}/100\n", domain, score.total);
    if !results.senders.is_empty() {
        println!("  Also sends through: {}\n", results.senders.join(", "));
    }

    for check in &score.checks {
        let mark = if check.passed { "✓".green() } else { "✗".red() };
        let detail = check.detail.clone().unwrap_or_else(|| detail_for(&check.name, results));
        println!("  {}   {:<13}{}", mark, check.name, detail);
    }
    if let Some(note) = &score.note {
        println!("\n  {}", note.dimmed());
    }

    let status = if score.total >= PASS_SCORE { "OK" } else { "NOT OK" };
    let n = score.fixes.len();
    println!("\n  {} {}/100 — {} — {} {} found", "Score:".bold(), score.total, status, n, if n == 1 { "issue" } else { "issues" });

    if !score.fixes.is_empty() {
        println!("\n  {}", "Fixes:".bold());
        for (i, fix) in score.fixes.iter().enumerate() {
            println!("  {}. {}", i + 1, fix.replace("<domain>", domain));
        }
    }
}

fn detail_for(name: &str, r: &DnsResults) -> String {
    match name {
        "SPF" => r.spf.as_ref().map(|s| s.raw.clone()),
        "DKIM" => r.dkim.as_ref().map(|d| format!("selector {}", d.selector)),
        "DMARC" => r.dmarc.as_ref().map(|d| format!("p={} pct={}", d.policy, d.pct)),
        "DMARC policy" => r.dmarc.as_ref().map(|d| d.policy.clone()),
        "PTR" => r.ptr.as_ref().map(|p| p.hostname.clone()),
        "rDNS" => r.rdns.clone(),
        "MX" => r.mx.as_ref().map(|m| format!("{} (priority {})", m.host, m.priority)),
        "Blacklist" => Some(if r.blacklisted { "listed" } else { "clean" }.to_string()),
        _ => None,
    }
    .unwrap_or_else(|| "not found".to_string())
}
