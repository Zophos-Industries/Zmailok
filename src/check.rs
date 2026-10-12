use std::process::ExitCode;

use zmailok::output::{print_report, PASS_SCORE};
use zmailok::types::CheckOptions;
use zmailok::{dns, domain, score, verify};

/// Runs entirely on this machine: DNS lookups, scoring and printing. Exit code 0 if the score passes, else 1.
pub async fn run(raw_domain: &str, options: CheckOptions, json: bool) -> anyhow::Result<ExitCode> {
    let domain = domain::normalize(raw_domain)?;
    let results = dns::check_with(&domain, &options).await?;
    let mut scored = score::compute(&results);
    // A second, independent calculation must agree before any score is shown.
    verify::verify(&results, &scored).map_err(|why| anyhow::anyhow!("internal consistency check failed: {why}. This is a bug, please report it"))?;
    scored.fixes = scored.fixes.iter().map(|f| f.replace("<domain>", &domain)).collect();

    if json {
        let out = serde_json::json!({ "domain": domain, "results": results, "score": scored });
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        print_report(&domain, &results, &scored);
    }
    Ok(if scored.total >= PASS_SCORE { ExitCode::SUCCESS } else { ExitCode::from(1) })
}
