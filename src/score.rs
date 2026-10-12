use crate::types::{CheckResult, DnsResults, Score};

/// The checks that look at one server's IP address. They are left out when there is no mail server IP
/// to look at (see `DnsResults::ip_checked`).
const IP_CHECKS: [&str; 3] = ["PTR", "rDNS", "Blacklist"];

/// Weights: SPF 15, DKIM 20, DMARC 15, DMARC policy 10, PTR 10, rDNS 10, MX 10, blacklist 10 (100 in
/// total). Checks that do not apply, or that could not be verified because their DNS lookups timed out,
/// are left out of both sides, so a domain that passes everything that was checked scores 100.
/// Every score is re-computed independently by `verify::verify` before it is used.
pub fn compute(results: &DnsResults) -> Score {
    let policy_enforced = results
        .dmarc
        .as_ref()
        .is_some_and(|d| !d.policy.eq_ignore_ascii_case("none"));
    let ip_applies = results.ip_checked.is_some();
    let unverified = |name: &str| results.unverified.iter().any(|u| u == name);

    // (name, passed, points, fix shown when failed)
    let checks: [(&str, bool, u32, &str); 8] = [
        ("SPF", results.spf.is_some(), 15,
         "Add SPF: publish a TXT record on <domain> starting with \"v=spf1\" that lists your sending servers and ends with ~all or -all"),
        ("DKIM", results.dkim.is_some(), 20,
         "Add DKIM: generate a key pair and publish the public key at s1._domainkey.<domain>"),
        ("DMARC", results.dmarc.is_some(), 15,
         "Add DMARC: publish a TXT record at _dmarc.<domain>, e.g. \"v=DMARC1; p=none; rua=mailto:dmarc@<domain>\""),
        ("DMARC policy", policy_enforced, 10,
         "Tighten DMARC: change p=none to p=quarantine or p=reject once your reports look clean"),
        ("PTR", results.ptr.is_some(), 10,
         "Add PTR: ask your hosting provider to set reverse DNS for your sending IP"),
        ("rDNS", results.rdns.is_some(), 10,
         "Fix rDNS: make the PTR hostname resolve back (A record) to the same sending IP"),
        ("MX", results.mx.is_some(), 10,
         "Add MX: publish at least one MX record on <domain> pointing to your mail server"),
        ("Blacklist", !results.blacklisted, 10,
         "Get delisted: your IP is on a blacklist (Spamhaus, Barracuda or SORBS). Find the cause and request removal"),
    ];

    let (mut earned, mut possible) = (0, 0);
    let mut check_results = Vec::new();
    let mut fixes = Vec::new();
    for (name, passed, points, fix) in checks {
        let left_out = (!ip_applies && IP_CHECKS.contains(&name))
            || unverified(name)
            || (name == "DMARC policy" && unverified("DMARC"));
        if left_out {
            continue;
        }
        possible += points;
        if passed {
            earned += points;
        } else {
            fixes.push(fix.to_string());
        }
        check_results.push(CheckResult { name: name.to_string(), passed, detail: None });
    }
    let total = if possible == 0 { 0 } else { ((earned * 100 + possible / 2) / possible) as u8 };
    Score { total, checks: check_results, fixes, note: note(results) }
}

/// Says what was left out of the score and why.
fn note(results: &DnsResults) -> Option<String> {
    let mut parts = Vec::new();
    let unverified_ip = IP_CHECKS.iter().all(|n| results.unverified.iter().any(|u| u == n));
    if results.ip_checked.is_none() && !unverified_ip {
        parts.push(if results.senders.is_empty() {
            "PTR, rDNS and blacklist were not checked: no IP address was found for this domain. Pass --ip <address> to check your mail server.".to_string()
        } else {
            "PTR, rDNS and blacklist were not checked: this domain also sends through third-party services, and those checks apply to a mail server's own IP. Pass --ip <address> to check yours.".to_string()
        });
    }
    if !results.unverified.is_empty() {
        parts.push(format!(
            "Could not verify {} because DNS lookups timed out. They are not counted in the score; run the check again.",
            results.unverified.join(", ")
        ));
    }
    (!parts.is_empty()).then(|| parts.join(" "))
}

#[cfg(test)]
mod tests {
    use super::compute;
    use crate::types::{DkimRecord, DmarcRecord, DnsResults, MxRecord, PtrRecord, SpfRecord};

    fn perfect() -> DnsResults {
        DnsResults {
            spf: Some(SpfRecord { raw: "v=spf1 -all".into(), mechanisms: vec![] }),
            dkim: Some(DkimRecord { selector: "s1".into(), raw: "v=DKIM1".into() }),
            dmarc: Some(DmarcRecord { policy: "reject".into(), rua: None, pct: 100 }),
            mx: Some(MxRecord { host: "mail.example.com".into(), priority: 10 }),
            ptr: Some(PtrRecord { hostname: "mail.example.com".into() }),
            rdns: Some("mail.example.com".into()),
            blacklisted: false,
            senders: vec![],
            unverified: vec![],
            ip_checked: Some("203.0.113.5".parse().unwrap()),
        }
    }

    fn empty() -> DnsResults {
        DnsResults { spf: None, dkim: None, dmarc: None, mx: None, ptr: None, rdns: None, blacklisted: false, senders: vec![], ip_checked: Some("203.0.113.5".parse().unwrap()), unverified: vec![] }
    }

    /// What a domain that sends through Google Workspace looks like: IP checks skipped.
    fn via_google(mut r: DnsResults) -> DnsResults {
        r.senders = vec!["Google Workspace".into()];
        r.ip_checked = None;
        (r.ptr, r.rdns, r.blacklisted) = (None, None, false);
        r
    }

    #[test]
    fn everything_in_place_scores_100_with_no_fixes() {
        let s = compute(&perfect());
        assert_eq!(s.total, 100);
        assert!(s.fixes.is_empty());
        assert_eq!(s.checks.len(), 8);
        assert!(s.checks.iter().all(|c| c.passed));
        assert!(s.note.is_none());
    }

    #[test]
    fn nothing_in_place_only_keeps_the_blacklist_points() {
        let s = compute(&empty());
        assert_eq!(s.total, 10);
        assert_eq!(s.fixes.len(), 7);
    }

    #[test]
    fn each_check_is_worth_what_the_rules_say() {
        let worth = |f: fn(&mut DnsResults)| { let mut r = perfect(); f(&mut r); 100 - compute(&r).total };
        assert_eq!(worth(|r| r.spf = None), 15);
        assert_eq!(worth(|r| r.dkim = None), 20);
        assert_eq!(worth(|r| r.dmarc = None), 25); // DMARC 15 + its policy 10
        assert_eq!(worth(|r| r.dmarc.as_mut().unwrap().policy = "none".into()), 10);
        assert_eq!(worth(|r| r.dmarc.as_mut().unwrap().policy = "NONE".into()), 10);
        assert_eq!(worth(|r| r.ptr = None), 10);
        assert_eq!(worth(|r| r.rdns = None), 10);
        assert_eq!(worth(|r| r.mx = None), 10);
        assert_eq!(worth(|r| r.blacklisted = true), 10);
    }

    #[test]
    fn one_fix_per_failed_check() {
        let mut r = perfect();
        r.dkim = None;
        r.blacklisted = true;
        let s = compute(&r);
        assert_eq!(s.fixes.len(), 2);
        assert!(s.fixes[0].contains("DKIM"));
    }

    #[test]
    fn skipped_ip_checks_do_not_cost_points() {
        let s = compute(&via_google(perfect()));
        assert_eq!(s.total, 100);
        assert!(s.fixes.is_empty());
        let names: Vec<&str> = s.checks.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, ["SPF", "DKIM", "DMARC", "DMARC policy", "MX"]);
        let note = s.note.unwrap();
        assert!(note.contains("third-party") && note.contains("--ip"), "{note}");
    }

    #[test]
    fn score_is_scaled_to_what_applies() {
        let mut r = via_google(perfect());
        r.dkim = None; // 50 of 70 applicable points = 71
        assert_eq!(compute(&r).total, 71);
        r.mx = None; // 40 of 70 = 57
        assert_eq!(compute(&r).total, 57);
        assert_eq!(compute(&via_google(empty())).total, 0);
    }

    #[test]
    fn no_ip_and_no_known_service_says_so() {
        let mut r = perfect();
        r.ip_checked = None;
        (r.ptr, r.rdns) = (None, None);
        let s = compute(&r);
        assert_eq!(s.total, 100);
        assert!(s.note.unwrap().contains("no IP address"));
    }

    #[test]
    fn passing_ip_forces_the_checks_even_for_third_party_senders() {
        let mut r = perfect();
        r.senders = vec!["SendGrid".into()]; // detected, but the user gave --ip so ip_checked is Some
        r.ptr = None;
        let s = compute(&r);
        assert_eq!((s.total, s.checks.len()), (90, 8));
        assert!(s.note.is_none());
    }
}
