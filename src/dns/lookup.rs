//! The individual DNS lookups, with the 5 second limit. A lookup that times out twice is
//! `Err(AppError::DnsTimeout)`: the caller must not read it as "no such record".

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use tokio::time::timeout;
use trust_dns_resolver::error::{ResolveError, ResolveErrorKind};
use trust_dns_resolver::proto::op::ResponseCode;
use trust_dns_resolver::TokioAsyncResolver;

use crate::types::AppError;

const LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);

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

/// `None` = the answer was "no records". A timeout is an error, and so is any other resolver failure.
pub(super) async fn lookup<T, F, Fut>(make: F) -> Result<Option<T>, AppError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, ResolveError>>,
{
    match attempt(make).await {
        None => Err(AppError::DnsTimeout),
        Some(Ok(v)) => Ok(Some(v)),
        Some(Err(e)) => match e.kind() {
            ResolveErrorKind::NoRecordsFound { .. } => Ok(None),
            // the resolver gave up on its own (no server answered): that is "could not ask", not "no"
            ResolveErrorKind::Timeout | ResolveErrorKind::NoConnections => Err(AppError::DnsTimeout),
            _ => Err(AppError::LookupFailed(e.to_string())),
        },
    }
}

/// The domain's first IPv4 address, and whether the domain does not exist at all (NXDOMAIN).
pub(super) async fn resolve_domain(r: &TokioAsyncResolver, domain: &str) -> Result<(Option<Ipv4Addr>, bool), AppError> {
    match attempt(|| r.lookup_ip(domain)).await {
        None => Err(AppError::DnsTimeout),
        Some(Ok(l)) => Ok((l.iter().find_map(|ip| if let IpAddr::V4(v4) = ip { Some(v4) } else { None }), false)),
        Some(Err(e)) => match e.kind() {
            ResolveErrorKind::NoRecordsFound { response_code, .. } => Ok((None, *response_code == ResponseCode::NXDomain)),
            ResolveErrorKind::Timeout | ResolveErrorKind::NoConnections => Err(AppError::DnsTimeout),
            _ => Err(AppError::LookupFailed(e.to_string())),
        },
    }
}

pub(super) async fn txt_records(r: &TokioAsyncResolver, name: &str) -> Result<Vec<String>, AppError> {
    let found = lookup(|| r.txt_lookup(name)).await?;
    Ok(found
        .map(|l| l.iter().map(|t| t.txt_data().iter().map(|b| String::from_utf8_lossy(b)).collect()).collect())
        .unwrap_or_default())
}

pub(super) async fn ptr_name(r: &TokioAsyncResolver, ip: Ipv4Addr) -> Result<Option<String>, AppError> {
    let found = lookup(|| r.reverse_lookup(IpAddr::V4(ip))).await?;
    Ok(found.and_then(|l| l.iter().next().map(|n| n.to_string().trim_end_matches('.').to_string())))
}
