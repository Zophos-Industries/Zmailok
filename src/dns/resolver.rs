//! Builds the DNS resolver from the system settings, minus servers that do not answer.
//!
//! Why: the resolver reads the DNS servers of every network adapter and starts each lookup with a
//! random one. A single dead server (for example the static DNS of a disconnected Ethernet adapter)
//! made a check take 20 seconds and randomly report records as "not found".

use std::net::SocketAddr;
use std::time::Duration;

use tokio::task::JoinSet;
use tokio::time::{timeout, timeout_at, Instant};
use trust_dns_resolver::config::{NameServerConfig, NameServerConfigGroup, ResolverConfig, ResolverOpts};
use trust_dns_resolver::error::ResolveError;
use trust_dns_resolver::proto::rr::RecordType;
use trust_dns_resolver::system_conf::read_system_conf;
use trust_dns_resolver::TokioAsyncResolver;

use super::parse;

/// How long a server gets to answer the probe.
const PROBE_WINDOW: Duration = Duration::from_millis(1500);
/// How long one query attempt waits before the resolver sends it again.
const PER_ATTEMPT: Duration = Duration::from_millis(1200);
/// Once one server answered, how much longer the others get.
const PROBE_GRACE: Duration = Duration::from_millis(250);

pub async fn system_resolver() -> Result<TokioAsyncResolver, ResolveError> {
    let (config, mut opts) = read_system_conf()?;
    // A lost UDP packet used to cost the default 5s wait. Retry sooner; 3 x 1.2s still fits in the
    // 5s limit that dns/mod.rs puts on every lookup.
    opts.timeout = PER_ATTEMPT;
    opts.attempts = 3;
    let mut addrs: Vec<SocketAddr> = Vec::new();
    for ns in config.name_servers() {
        // site-local IPv6 (fec0::/10) is a deprecated range that Windows lists but nothing answers on
        if !parse::is_site_local(ns.socket_addr.ip()) && !addrs.contains(&ns.socket_addr) {
            addrs.push(ns.socket_addr);
        }
    }
    let live = live_servers(&config, &opts, &addrs).await;
    let kept: Vec<NameServerConfig> = config.name_servers().iter().filter(|ns| live.contains(&ns.socket_addr)).cloned().collect();
    // If nothing answered the probe, the network may simply be slow: use the full list as it is.
    let config = if kept.is_empty() {
        config
    } else {
        ResolverConfig::from_parts(config.domain().cloned(), config.search().to_vec(), NameServerConfigGroup::from(kept))
    };
    Ok(TokioAsyncResolver::tokio(config, opts))
}

/// Asks every server one tiny question (the root NS records) at the same time. Only a server that
/// returns real records counts as alive: silence, network errors and error answers do not (a broken
/// resolver that answers errors for everything is as useless as a dead one).
async fn live_servers(config: &ResolverConfig, opts: &ResolverOpts, addrs: &[SocketAddr]) -> Vec<SocketAddr> {
    let mut probes = JoinSet::new();
    for addr in addrs {
        let entries: Vec<NameServerConfig> = config.name_servers().iter().filter(|ns| ns.socket_addr == *addr).cloned().collect();
        let (one, opts, addr) = (ResolverConfig::from_parts(None, vec![], NameServerConfigGroup::from(entries)), opts.clone(), *addr);
        probes.spawn(async move {
            let r = TokioAsyncResolver::tokio(one, opts);
            let alive = match timeout(PROBE_WINDOW, r.lookup(".", RecordType::NS)).await {
                Ok(Ok(_)) => true,
                _ => false,
            };
            (addr, alive)
        });
    }
    let mut live = Vec::new();
    let mut deadline = Instant::now() + PROBE_WINDOW;
    while let Ok(Some(done)) = timeout_at(deadline, probes.join_next()).await {
        if let Ok((addr, true)) = done {
            if live.is_empty() {
                deadline = deadline.min(Instant::now() + PROBE_GRACE);
            }
            live.push(addr);
        }
    }
    live
}
