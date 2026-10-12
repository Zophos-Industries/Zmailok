mod parse;
mod resolver;

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use tokio::time::timeout;
use trust_dns_resolver::error::{ResolveError, ResolveErrorKind};
use trust_dns_resolver::proto::op::ResponseCode;
use trust_dns_resolver::TokioAsyncResolver;

use crate::types::{AppError, CheckOptions, DkimRecord, DmarcRecord, DnsResults, MxRecord, PtrRecord, SpfRecord};

const SELECTORS: [&str; 8] = ["s1", "s2", "default", "google", "k1", "selector1", "selector2", "_domainkey"];
const BLACKLISTS: [&str; 3] = ["zen.spamhaus.org", "b.barracudacentral.org", "dnsbl.sorbs.net"];
const MAX_SPF_HOPS: usize = 10;
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);

pub async fn check(domain: &str) -> anyhow::Result<DnsResults> {
    check_with(domain, &CheckOptions::default()).await
}

/// `options.ip` is the sending server's address for the PTR, rDNS and blacklist checks. By default it is
/// the domain's own A record, which is wrong for domains whose website and mail server differ.
pub async fn check_with(domain: &str, options: &CheckOptions) -> anyhow::Result<DnsResults> {
    let (ip, selector) = (options.ip, options.dkim_selector.as_deref());
    let r = resolver::system_resolver().await?;
    let (resolved, spf, dkim, dmarc, mx) = tokio::join!(
        resolve_domain(&r, domain),
        check_spf(&r, domain),
        check_dkim(&r, domain, selector),
        check_dmarc(&r, domain),
        check_mx(&r, domain),
    );
    let (found_ip, nxdomain) = resolved?;
    if nxdomain {
        return Err(AppError::DomainNotFound.into());
    }
    // One address for all three checks, so round-robin DNS cannot make them look at different servers.
    let (ptr, rdns, bl) = match ip.or(found_ip) {
        Some(ip) => tokio::join!(check_ptr(&r, ip), check_rdns(&r, ip), check_blacklists(&r, ip)),
        None => (Ok(None), Ok(None), Ok(None)),
    };
    Ok(DnsResults { spf: spf?, dkim: dkim?, dmarc: dmarc?, mx: mx?, ptr: ptr?, rdns: rdns?, blacklisted: bl?.unwrap_or(false) })
}

/// Runs the lookup with a 5s timeout and retries once if it timed out. None = timed out twice.
async fn attempt<T, F, Fut>(mut make: F) -> Option<Result<T, ResolveError>>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, ResolveError>>,
{
    for _ in 0..2 {
        if let Ok(res) = timeout(LOOKUP_TIMEOUT, make()).await {
            return Some(res);
        }
    }
    None
}

/// Timeout and "no records" both become `None`; any other resolver error is an error.
async fn lookup<T, F, Fut>(make: F) -> Result<Option<T>, AppError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, ResolveError>>,
{
    match attempt(make).await {
        None => Ok(None),
        Some(Ok(v)) => Ok(Some(v)),
        Some(Err(e)) => match e.kind() {
            ResolveErrorKind::NoRecordsFound { .. } => Ok(None),
            _ => Err(AppError::LookupFailed(e.to_string())),
        },
    }
}

/// The domain's first IPv4 address, and whether the domain does not exist at all (NXDOMAIN).
async fn resolve_domain(r: &TokioAsyncResolver, domain: &str) -> Result<(Option<Ipv4Addr>, bool), AppError> {
    match attempt(|| r.lookup_ip(domain)).await {
        None => Ok((None, false)),
        Some(Ok(l)) => Ok((l.iter().find_map(|ip| if let IpAddr::V4(v4) = ip { Some(v4) } else { None }), false)),
        Some(Err(e)) => match e.kind() {
            ResolveErrorKind::NoRecordsFound { response_code, .. } => Ok((None, *response_code == ResponseCode::NXDomain)),
            _ => Err(AppError::LookupFailed(e.to_string())),
        },
    }
}

async fn txt_records(r: &TokioAsyncResolver, name: &str) -> Result<Vec<String>, AppError> {
    let found = lookup(|| r.txt_lookup(name)).await?;
    Ok(found
        .map(|l| l.iter().map(|t| t.txt_data().iter().map(|b| String::from_utf8_lossy(b)).collect()).collect())
        .unwrap_or_default())
}

async fn ptr_name(r: &TokioAsyncResolver, ip: Ipv4Addr) -> Result<Option<String>, AppError> {
    let found = lookup(|| r.reverse_lookup(IpAddr::V4(ip))).await?;
    Ok(found.and_then(|l| l.iter().next().map(|n| n.to_string().trim_end_matches('.').to_string())))
}

pub async fn check_spf(r: &TokioAsyncResolver, domain: &str) -> Result<Option<SpfRecord>, AppError> {
    let find = |recs: Vec<String>| recs.into_iter().find(|t| parse::is_spf(t));
    let Some(raw) = find(txt_records(r, domain).await?) else {
        return Ok(None);
    };
    let mut mechanisms = parse::spf_terms(&raw);
    let mut queue = parse::spf_includes(&mechanisms);
    let mut seen: Vec<String> = Vec::new();
    while seen.len() < MAX_SPF_HOPS && !queue.is_empty() {
        let target = queue.remove(0);
        if seen.contains(&target) {
            continue;
        }
        seen.push(target.clone());
        // An include that cannot be looked up (odd name, lookup error) is skipped: one bad include
        // in somebody's SPF record must not make the whole check fail.
        if let Some(rec) = find(txt_records(r, &target).await.unwrap_or_default()) {
            // an included record's own "all" is not this domain's policy
            let inner: Vec<String> = parse::spf_terms(&rec).into_iter().filter(|t| !parse::is_all(t)).collect();
            queue.extend(parse::spf_includes(&inner));
            mechanisms.extend(inner);
        }
    }
    Ok(Some(SpfRecord { raw, mechanisms }))
}

/// Tries the built-in selectors, plus `custom` first if given. The first hit in that order wins.
pub async fn check_dkim(r: &TokioAsyncResolver, domain: &str, custom: Option<&str>) -> Result<Option<DkimRecord>, AppError> {
    let query = |s: &str| {
        let name = format!("{s}._domainkey.{domain}");
        async move { txt_records(r, &name).await }
    };
    let extra = async {
        match custom {
            Some(s) => query(s).await,
            None => Ok(Vec::new()),
        }
    };
    let (first, s0, s1, s2, s3, s4, s5, s6, s7) = tokio::join!(
        extra, query(SELECTORS[0]), query(SELECTORS[1]), query(SELECTORS[2]), query(SELECTORS[3]),
        query(SELECTORS[4]), query(SELECTORS[5]), query(SELECTORS[6]), query(SELECTORS[7]),
    );
    if let (Some(selector), Some(raw)) = (custom, first?.into_iter().next()) {
        return Ok(Some(DkimRecord { selector: selector.to_string(), raw }));
    }
    for (selector, res) in SELECTORS.into_iter().zip([s0, s1, s2, s3, s4, s5, s6, s7]) {
        if let Some(raw) = res?.into_iter().next() {
            return Ok(Some(DkimRecord { selector: selector.to_string(), raw }));
        }
    }
    Ok(None)
}

pub async fn check_dmarc(r: &TokioAsyncResolver, domain: &str) -> Result<Option<DmarcRecord>, AppError> {
    let recs = txt_records(r, &format!("_dmarc.{domain}")).await?;
    Ok(recs.iter().find_map(|t| parse::parse_dmarc(t)))
}

pub async fn check_mx(r: &TokioAsyncResolver, domain: &str) -> Result<Option<MxRecord>, AppError> {
    let found = lookup(|| r.mx_lookup(domain)).await?;
    Ok(found.and_then(|l| {
        let best = l.iter().min_by_key(|m| m.preference())?;
        let host = best.exchange().to_string().trim_end_matches('.').to_string();
        // a lone "0 ." is a null MX: the domain says it receives no mail
        (!host.is_empty()).then(|| MxRecord { host, priority: best.preference() })
    }))
}

pub async fn check_ptr(r: &TokioAsyncResolver, ip: Ipv4Addr) -> Result<Option<PtrRecord>, AppError> {
    Ok(ptr_name(r, ip).await?.map(|hostname| PtrRecord { hostname }))
}

/// Returns the PTR hostname only if it resolves back to the same IP.
pub async fn check_rdns(r: &TokioAsyncResolver, ip: Ipv4Addr) -> Result<Option<String>, AppError> {
    let Some(host) = ptr_name(r, ip).await? else {
        return Ok(None);
    };
    let forward = lookup(|| r.lookup_ip(host.as_str())).await?;
    let matches = forward.is_some_and(|l| l.iter().any(|a| a == IpAddr::V4(ip)));
    Ok(matches.then_some(host))
}

pub async fn check_blacklists(r: &TokioAsyncResolver, ip: Ipv4Addr) -> Result<Option<bool>, AppError> {
    let [a, b, c, d] = ip.octets();
    let query = |bl: &str| {
        let name = format!("{d}.{c}.{b}.{a}.{bl}");
        async move { lookup(|| r.lookup_ip(name.as_str())).await }
    };
    let (z, bc, so) = tokio::join!(query(BLACKLISTS[0]), query(BLACKLISTS[1]), query(BLACKLISTS[2]));
    let listed = [z?, bc?, so?].into_iter().flatten().any(|l| l.iter().any(parse::is_listing));
    Ok(Some(listed))
}
