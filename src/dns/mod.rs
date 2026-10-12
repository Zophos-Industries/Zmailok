mod checks;
mod combine;
mod lookup;
mod parse;
mod resolver;
mod senders;

use trust_dns_resolver::TokioAsyncResolver;

use crate::types::{AppError, CheckOptions, DnsResults};

const IP_CHECKS: [&str; 3] = ["PTR", "rDNS", "Blacklist"];

pub async fn check(domain: &str) -> anyhow::Result<DnsResults> {
    check_with(domain, &CheckOptions::default()).await
}

/// A check whose lookups timed out is not a failed check: it is recorded as unverified instead, and
/// the score leaves it out.
fn settle<T>(res: Result<Option<T>, AppError>, name: &str, unverified: &mut Vec<String>) -> Result<Option<T>, AppError> {
    match res {
        Err(AppError::DnsTimeout) => {
            unverified.push(name.to_string());
            Ok(None)
        }
        other => other,
    }
}

/// `options.ip` is the address of the mail server, for the PTR, rDNS and blacklist checks. Without it
/// those checks look at the domain's own A record, but only when that makes sense: if the SPF record
/// shows the domain sends through Google, SendGrid and the like, the A record is just the website and
/// the checks are skipped (pass `--ip` to run them on your own server anyway).
pub async fn check_with(domain: &str, options: &CheckOptions) -> anyhow::Result<DnsResults> {
    let r = resolver::system_resolver().await?;
    check_using(&r, domain, options).await
}

async fn check_using(r: &TokioAsyncResolver, domain: &str, options: &CheckOptions) -> anyhow::Result<DnsResults> {
    let selector = options.dkim_selector.as_deref();
    let (resolved, spf, dkim, dmarc, mx) = tokio::join!(
        lookup::resolve_domain(r, domain),
        checks::check_spf(r, domain),
        checks::check_dkim(r, domain, selector),
        checks::check_dmarc(r, domain),
        checks::check_mx(r, domain),
    );
    let mut unverified = Vec::new();
    let (found_ip, nxdomain, ip_unknown) = match resolved {
        Ok((ip, nx)) => (ip, nx, false),
        Err(AppError::DnsTimeout) => (None, false, true),
        Err(e) => return Err(e.into()),
    };
    if nxdomain {
        return Err(AppError::DomainNotFound.into());
    }
    let spf = settle(spf, "SPF", &mut unverified)?;
    let dkim = settle(dkim, "DKIM", &mut unverified)?;
    let dmarc = settle(dmarc, "DMARC", &mut unverified)?;
    let mx = settle(mx, "MX", &mut unverified)?;

    let senders = spf.as_ref().map(|s| senders::detect(&s.raw)).unwrap_or_default();
    let spf_unknown = unverified.iter().any(|n| n == "SPF");
    // Without --ip, the checks run on the A record only when we know the domain sends from its own server.
    let ip_checked = match options.ip {
        Some(ip) => Some(ip),
        None if senders.is_empty() && !spf_unknown => found_ip,
        None => None,
    };
    if options.ip.is_none() && (spf_unknown || (senders.is_empty() && ip_unknown)) {
        unverified.extend(IP_CHECKS.map(String::from)); // could not tell whether, or on which IP, to check
    }
    // One address for all three checks, so round-robin DNS cannot make them look at different servers.
    let (ptr, rdns, bl) = match ip_checked {
        Some(ip) => tokio::join!(checks::check_ptr(r, ip), checks::check_rdns(r, ip), checks::check_blacklists(r, ip)),
        None => (Ok(None), Ok(None), Ok(false)),
    };
    let ptr = settle(ptr, "PTR", &mut unverified)?;
    let rdns = settle(rdns, "rDNS", &mut unverified)?;
    let blacklisted = settle(bl.map(Some), "Blacklist", &mut unverified)?.unwrap_or(false);
    unverified.dedup();
    Ok(DnsResults { spf, dkim, dmarc, mx, ptr, rdns, blacklisted, senders, ip_checked, unverified })
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::time::Duration;

    use trust_dns_resolver::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts};

    use super::*;
    use crate::{score, verify};

    /// Points the resolver at 192.0.2.1 (TEST-NET-1, a range nothing answers on), so every lookup times
    /// out. Run it with `cargo test -- --ignored`. It needs a network that drops those packets silently,
    /// which is the norm; on a network that answers "unreachable" instead it fails with a lookup error.
    #[tokio::test]
    #[ignore = "waits for real DNS timeouts (about 30 seconds)"]
    async fn when_nothing_answers_every_check_is_unverified_not_failed() {
        let mut opts = ResolverOpts::default();
        opts.timeout = Duration::from_millis(500);
        opts.attempts = 1;
        let servers = NameServerConfigGroup::from_ips_clear(&["192.0.2.1".parse::<IpAddr>().unwrap()], 53, true);
        let resolver = TokioAsyncResolver::tokio(ResolverConfig::from_parts(None, vec![], servers), opts);

        let results = check_using(&resolver, "example.com", &CheckOptions::default()).await.unwrap();
        for name in ["SPF", "DKIM", "DMARC", "MX", "PTR", "rDNS", "Blacklist"] {
            assert!(results.unverified.contains(&name.to_string()), "{name} should be unverified: {:?}", results.unverified);
        }
        let scored = score::compute(&results);
        assert_eq!((scored.total, scored.checks.len(), scored.fixes.len()), (0, 0, 0), "nothing was verified, so nothing failed");
        assert!(scored.note.as_deref().unwrap().contains("Could not verify"));
        verify::verify(&results, &scored).unwrap();
    }
}
