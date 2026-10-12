//! One function per check. Each returns `Err(AppError::DnsTimeout)` when it could not get an answer.

use std::net::{IpAddr, Ipv4Addr};

use trust_dns_resolver::TokioAsyncResolver;

use super::lookup::{lookup, ptr_name, txt_records};
use super::{combine, parse};
use crate::types::{AppError, DkimRecord, DmarcRecord, MxRecord, PtrRecord, SpfRecord};

const SELECTORS: [&str; 8] = ["s1", "s2", "default", "google", "k1", "selector1", "selector2", "_domainkey"];
const BLACKLISTS: [&str; 3] = ["zen.spamhaus.org", "b.barracudacentral.org", "dnsbl.sorbs.net"];
const MAX_SPF_HOPS: usize = 10;

pub(super) async fn check_spf(r: &TokioAsyncResolver, domain: &str) -> Result<Option<SpfRecord>, AppError> {
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
pub(super) async fn check_dkim(r: &TokioAsyncResolver, domain: &str, custom: Option<&str>) -> Result<Option<DkimRecord>, AppError> {
    let query = |s: &str| {
        let (name, selector) = (format!("{s}._domainkey.{domain}"), s.to_string());
        async move { txt_records(r, &name).await.map(|recs| recs.into_iter().next().map(|raw| DkimRecord { selector, raw })) }
    };
    let extra = async {
        match custom {
            Some(s) => query(s).await,
            None => Ok(None),
        }
    };
    let (first, s0, s1, s2, s3, s4, s5, s6, s7) = tokio::join!(
        extra, query(SELECTORS[0]), query(SELECTORS[1]), query(SELECTORS[2]), query(SELECTORS[3]),
        query(SELECTORS[4]), query(SELECTORS[5]), query(SELECTORS[6]), query(SELECTORS[7]),
    );
    combine::first_hit(vec![first, s0, s1, s2, s3, s4, s5, s6, s7])
}

pub(super) async fn check_dmarc(r: &TokioAsyncResolver, domain: &str) -> Result<Option<DmarcRecord>, AppError> {
    let recs = txt_records(r, &format!("_dmarc.{domain}")).await?;
    Ok(recs.iter().find_map(|t| parse::parse_dmarc(t)))
}

pub(super) async fn check_mx(r: &TokioAsyncResolver, domain: &str) -> Result<Option<MxRecord>, AppError> {
    let found = lookup(|| r.mx_lookup(domain)).await?;
    Ok(found.and_then(|l| {
        let best = l.iter().min_by_key(|m| m.preference())?;
        let host = best.exchange().to_string().trim_end_matches('.').to_string();
        // a lone "0 ." is a null MX: the domain says it receives no mail
        (!host.is_empty()).then(|| MxRecord { host, priority: best.preference() })
    }))
}

pub(super) async fn check_ptr(r: &TokioAsyncResolver, ip: Ipv4Addr) -> Result<Option<PtrRecord>, AppError> {
    Ok(ptr_name(r, ip).await?.map(|hostname| PtrRecord { hostname }))
}

/// Returns the PTR hostname only if it resolves back to the same IP.
pub(super) async fn check_rdns(r: &TokioAsyncResolver, ip: Ipv4Addr) -> Result<Option<String>, AppError> {
    let Some(host) = ptr_name(r, ip).await? else {
        return Ok(None);
    };
    let forward = lookup(|| r.lookup_ip(host.as_str())).await?;
    let matches = forward.is_some_and(|l| l.iter().any(|a| a == IpAddr::V4(ip)));
    Ok(matches.then_some(host))
}

/// True if any list has the IP. "Not listed" needs every list to have answered.
pub(super) async fn check_blacklists(r: &TokioAsyncResolver, ip: Ipv4Addr) -> Result<bool, AppError> {
    let [a, b, c, d] = ip.octets();
    let query = |bl: &str| {
        let name = format!("{d}.{c}.{b}.{a}.{bl}");
        async move { lookup(|| r.lookup_ip(name.as_str())).await.map(|found| found.is_some_and(|l| l.iter().any(parse::is_listing))) }
    };
    let (z, bc, so) = tokio::join!(query(BLACKLISTS[0]), query(BLACKLISTS[1]), query(BLACKLISTS[2]));
    combine::any_true(vec![z, bc, so])
}
