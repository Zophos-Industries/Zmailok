use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Optional inputs for a check. The defaults give the plain `zmailok check example.com`.
#[derive(Debug, Clone, Default)]
pub struct CheckOptions {
    /// Sending server address for the PTR, rDNS and blacklist checks (default: the domain's A record).
    pub ip: Option<Ipv4Addr>,
    /// A DKIM selector to try first, in addition to the built-in list.
    pub dkim_selector: Option<String>,
}

#[derive(Error, Debug)]
pub enum AppError {
    #[error("DNS lookup timed out")]
    DnsTimeout,
    #[error("DNS lookup failed: {0}")]
    LookupFailed(String),
    #[error("failed to parse record: {0}")]
    ParseError(String),
    #[error("blacklist API error: {0}")]
    BlacklistApi(String),
    #[error("not a valid domain name")]
    InvalidDomain,
    #[error("domain does not exist (NXDOMAIN)")]
    DomainNotFound,
    #[error("not logged in, run: zmailok login")]
    NotLoggedIn,
    #[error("{0}")]
    Api(String),
    #[error("cannot read or write the login token: {0}")]
    Storage(String),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SpfRecord {
    pub raw: String,
    pub mechanisms: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DkimRecord {
    pub selector: String,
    pub raw: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DmarcRecord {
    pub policy: String,
    pub rua: Option<String>,
    pub pct: u8,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MxRecord {
    pub host: String,
    pub priority: u16,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PtrRecord {
    pub hostname: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DnsResults {
    pub spf: Option<SpfRecord>,
    pub dkim: Option<DkimRecord>,
    pub dmarc: Option<DmarcRecord>,
    pub mx: Option<MxRecord>,
    pub ptr: Option<PtrRecord>,
    pub rdns: Option<String>,
    pub blacklisted: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CheckResult {
    pub name: String,
    pub passed: bool,
    pub detail: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Score {
    pub total: u8,
    pub checks: Vec<CheckResult>,
    pub fixes: Vec<String>,
}
