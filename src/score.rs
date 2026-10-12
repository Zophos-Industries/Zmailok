use crate::types::{CheckResult, DnsResults, Score};

pub fn compute(results: &DnsResults) -> Score {
    let policy_enforced = results
        .dmarc
        .as_ref()
        .is_some_and(|d| !d.policy.eq_ignore_ascii_case("none"));

    // (name, passed, points, fix shown when failed)
    let checks: [(&str, bool, u8, &str); 8] = [
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

    let mut total = 0;
    let mut check_results = Vec::new();
    let mut fixes = Vec::new();
    for (name, passed, points, fix) in checks {
        if passed {
            total += points;
        } else {
            fixes.push(fix.to_string());
        }
        check_results.push(CheckResult { name: name.to_string(), passed, detail: None });
    }
    Score { total, checks: check_results, fixes }
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
        }
    }

    fn empty() -> DnsResults {
        DnsResults { spf: None, dkim: None, dmarc: None, mx: None, ptr: None, rdns: None, blacklisted: false }
    }

    #[test]
    fn everything_in_place_scores_100_with_no_fixes() {
        let s = compute(&perfect());
        assert_eq!(s.total, 100);
        assert!(s.fixes.is_empty());
        assert_eq!(s.checks.len(), 8);
        assert!(s.checks.iter().all(|c| c.passed));
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
}
