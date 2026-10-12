//! Pure parsing of DNS record text. No network access here, so it is fully unit-tested.

use std::net::IpAddr;

use crate::types::DmarcRecord;

const QUALIFIERS: [char; 4] = ['+', '-', '~', '?'];

/// The SPF version tag is case-insensitive and must be the whole first word ("v=spf10" is not SPF).
pub fn is_spf(txt: &str) -> bool {
    txt.split_whitespace().next().is_some_and(|w| w.eq_ignore_ascii_case("v=spf1"))
}

/// Everything after the version tag: mechanisms and modifiers.
pub fn spf_terms(txt: &str) -> Vec<String> {
    txt.split_whitespace().skip(1).map(String::from).collect()
}

/// `include:` targets, with or without a qualifier (`include:x`, `~include:x`).
pub fn spf_includes(terms: &[String]) -> Vec<String> {
    terms
        .iter()
        .filter_map(|t| t.trim_start_matches(QUALIFIERS).strip_prefix("include:").map(String::from))
        .collect()
}

/// The `all` term (`-all`, `~all`, `?all`, `+all`, `all`), and nothing that merely ends in "all".
pub fn is_all(term: &str) -> bool {
    term.trim_start_matches(QUALIFIERS).eq_ignore_ascii_case("all")
}

/// None if the text is not a usable DMARC record: the first tag must be `v=DMARC1` and `p=` must be
/// present. An unusable `pct=` is ignored (treated as 100), as RFC 7489 says, instead of failing.
pub fn parse_dmarc(txt: &str) -> Option<DmarcRecord> {
    let mut tags = txt.split(';').filter_map(|p| p.trim().split_once('=')).map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim()));
    let (first, version) = tags.next()?;
    if first != "v" || version != "DMARC1" {
        return None;
    }
    let (mut policy, mut rua, mut pct) = (None, None, 100);
    for (key, val) in tags {
        match key.as_str() {
            "p" if !val.is_empty() => policy = Some(val.to_ascii_lowercase()),
            "rua" if !val.is_empty() => rua = Some(val.to_string()),
            "pct" => pct = val.parse::<u8>().ok().filter(|n| *n <= 100).unwrap_or(100),
            _ => {}
        }
    }
    Some(DmarcRecord { policy: policy?, rua, pct })
}

/// Deprecated site-local IPv6 range (fec0::/10). Windows lists dead DNS servers from it (fec0:0:0:ffff::1-3).
pub fn is_site_local(ip: IpAddr) -> bool {
    matches!(ip, IpAddr::V6(v6) if v6.segments()[0] & 0xffc0 == 0xfec0)
}

/// A DNS blacklist answer of 127.0.0.x means "listed". Spamhaus answers 127.255.255.x when it refuses
/// the query (for example from a public resolver), which says nothing about the IP.
pub fn is_listing(answer: IpAddr) -> bool {
    matches!(answer, IpAddr::V4(v) if v.octets()[..3] == [127, 0, 0])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spf_detection() {
        assert!(is_spf("v=spf1 include:_spf.google.com ~all"));
        assert!(is_spf("V=SPF1 -all"));
        assert!(is_spf("v=spf1"));
        assert!(!is_spf("v=spf10 -all"));
        assert!(!is_spf("google-site-verification=abc"));
        assert!(!is_spf(""));
    }

    #[test]
    fn spf_includes_with_and_without_qualifier() {
        let terms = spf_terms("v=spf1 ip4:1.2.3.4 include:a.example ~include:b.example -include:c.example mx ~all");
        assert_eq!(spf_includes(&terms), ["a.example", "b.example", "c.example"]);
    }

    #[test]
    fn all_term_is_exact() {
        for yes in ["all", "-all", "~all", "?all", "+all", "~ALL"] { assert!(is_all(yes), "{yes}"); }
        for no in ["include:smtp.small", "mall", "include:all.example", "a:all.example"] { assert!(!is_all(no), "{no}"); }
    }

    #[test]
    fn dmarc_typical_record() {
        let d = parse_dmarc("v=DMARC1; p=Reject; rua=mailto:a@x.com; pct=50").unwrap();
        assert_eq!((d.policy.as_str(), d.rua.as_deref(), d.pct), ("reject", Some("mailto:a@x.com"), 50));
        let d = parse_dmarc("v=DMARC1;p=none").unwrap();
        assert_eq!((d.policy.as_str(), d.rua, d.pct), ("none", None, 100));
    }

    #[test]
    fn dmarc_odd_but_valid_records() {
        assert_eq!(parse_dmarc(" v=DMARC1 ; P=quarantine ; PCT=20 ").unwrap().pct, 20);
        assert_eq!(parse_dmarc("v=DMARC1; p=none; pct=abc").unwrap().pct, 100);
        assert_eq!(parse_dmarc("v=DMARC1; p=none; pct=250").unwrap().pct, 100);
        assert_eq!(parse_dmarc("v=DMARC1; p=none; pct=-1").unwrap().pct, 100);
        assert_eq!(parse_dmarc("v=DMARC1; p=none; sp=reject; fo=1").unwrap().policy, "none");
    }

    #[test]
    fn dmarc_invalid_records() {
        for bad in ["", "v=DMARC1", "v=DMARC1; p=", "v=DMARC1; rua=mailto:a@x.com", "p=none; v=DMARC1", "v=dmarc2; p=none", "hello"] {
            assert!(parse_dmarc(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn dead_site_local_dns_servers_are_recognised() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        for dead in ["fec0:0:0:ffff::1", "fec0:0:0:ffff::3", "feff::1"] { assert!(is_site_local(ip(dead)), "{dead}"); }
        for fine in ["2001:4860:4860::8888", "fe80::1", "fd00::1", "8.8.8.8", "192.168.1.1"] { assert!(!is_site_local(ip(fine)), "{fine}"); }
    }

    #[test]
    fn blacklist_answers() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert!(is_listing(ip("127.0.0.2")));
        assert!(is_listing(ip("127.0.0.10")));
        assert!(!is_listing(ip("127.255.255.254")));
        assert!(!is_listing(ip("8.8.8.8")));
        assert!(!is_listing(ip("::1")));
    }
}
