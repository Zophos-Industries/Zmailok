//! A second, independently written scoring pass. A score is checked against it before it is shown,
//! stored or alerted on. A disagreement means a bug and never becomes a score.
//!
//! It deliberately shares no code with `score.rs`: the rules are written out again here, and the total
//! is computed with a different formula.

use crate::types::{DnsResults, Score};

/// (check, points) in report order. SPF 15, DKIM 20, DMARC 15, DMARC policy 10, PTR 10, rDNS 10, MX 10,
/// blacklist 10.
const POINTS: [(&str, u32); 8] = [
    ("SPF", 15), ("DKIM", 20), ("DMARC", 15), ("DMARC policy", 10),
    ("PTR", 10), ("rDNS", 10), ("MX", 10), ("Blacklist", 10),
];

fn passed(check: &str, r: &DnsResults) -> bool {
    match check {
        "SPF" => r.spf.is_some(),
        "DKIM" => r.dkim.is_some(),
        "DMARC" => r.dmarc.is_some(),
        "DMARC policy" => r.dmarc.as_ref().is_some_and(|d| d.policy.to_ascii_lowercase() != "none"),
        "PTR" => r.ptr.is_some(),
        "rDNS" => r.rdns.is_some(),
        "MX" => r.mx.is_some(),
        "Blacklist" => !r.blacklisted,
        _ => false,
    }
}

/// Whether the check takes part in the score: it must apply, and its lookups must have been verified.
fn counts(check: &str, r: &DnsResults) -> bool {
    let unverified = |name: &str| r.unverified.iter().any(|u| u == name);
    match check {
        "PTR" | "rDNS" | "Blacklist" => r.ip_checked.is_some() && !unverified(check),
        "DMARC policy" => !unverified("DMARC"),
        other => !unverified(other),
    }
}

/// Recomputes the score from the results and compares everything: total, which checks appear, whether
/// each passed, and the number of fixes.
pub fn verify(results: &DnsResults, score: &Score) -> Result<(), String> {
    let counted: Vec<(&str, u32)> = POINTS.iter().copied().filter(|(name, _)| counts(name, results)).collect();
    let possible: u32 = counted.iter().map(|(_, points)| points).sum();
    let earned: u32 = counted.iter().filter(|(name, _)| passed(name, results)).map(|(_, points)| points).sum();
    let expected = if possible == 0 { 0 } else { (earned * 200 + possible) / (2 * possible) }; // nearest whole number

    if u32::from(score.total) != expected {
        return Err(format!("the total is {} but a second calculation gives {expected} ({earned} of {possible} points)", score.total));
    }
    let shown: Vec<&str> = score.checks.iter().map(|c| c.name.as_str()).collect();
    let expected_names: Vec<&str> = counted.iter().map(|(name, _)| *name).collect();
    if shown != expected_names {
        return Err(format!("the checks are {shown:?} but should be {expected_names:?}"));
    }
    if let Some(c) = score.checks.iter().find(|c| c.passed != passed(&c.name, results)) {
        return Err(format!("{} is shown as {} but the results say the opposite", c.name, if c.passed { "passed" } else { "failed" }));
    }
    let failed = counted.iter().filter(|(name, _)| !passed(name, results)).count();
    if score.fixes.len() != failed {
        return Err(format!("{} fixes for {failed} failed checks", score.fixes.len()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::score::compute;
    use crate::types::{CheckResult, DkimRecord, DmarcRecord, MxRecord, PtrRecord, SpfRecord};

    const NAMES: [&str; 7] = ["SPF", "DKIM", "DMARC", "MX", "PTR", "rDNS", "Blacklist"];

    fn build(bits: [bool; 5], dmarc: u8, blacklisted: bool, ip: bool, unverified_mask: u8) -> DnsResults {
        let [spf, dkim, mx, ptr, rdns] = bits;
        DnsResults {
            spf: spf.then(|| SpfRecord { raw: "v=spf1 -all".into(), mechanisms: vec![] }),
            dkim: dkim.then(|| DkimRecord { selector: "s1".into(), raw: "v=DKIM1".into() }),
            dmarc: match dmarc {
                0 => None,
                1 => Some(DmarcRecord { policy: "none".into(), rua: None, pct: 100 }),
                _ => Some(DmarcRecord { policy: "reject".into(), rua: None, pct: 100 }),
            },
            mx: mx.then(|| MxRecord { host: "mx.example.com".into(), priority: 10 }),
            ptr: ptr.then(|| PtrRecord { hostname: "mx.example.com".into() }),
            rdns: rdns.then(|| "mx.example.com".to_string()),
            blacklisted,
            senders: vec![],
            ip_checked: ip.then(|| "203.0.113.5".parse().unwrap()),
            unverified: NAMES.iter().enumerate().filter(|(i, _)| unverified_mask >> i & 1 == 1).map(|(_, n)| n.to_string()).collect(),
        }
    }

    /// Every combination of results: 2^5 presence flags x 3 DMARC states x blacklist x IP x 2^7 unverified sets.
    fn all_results() -> Vec<DnsResults> {
        let mut all = Vec::new();
        for flags in 0..32u8 {
            let bits = [0, 1, 2, 3, 4].map(|i| flags >> i & 1 == 1);
            for dmarc in 0..3 {
                for (blacklisted, ip) in [(false, false), (false, true), (true, false), (true, true)] {
                    for mask in 0..128u8 {
                        all.push(build(bits, dmarc, blacklisted, ip, mask));
                    }
                }
            }
        }
        all
    }

    #[test]
    fn compute_agrees_with_the_independent_calculation_for_every_input() {
        let all = all_results();
        assert_eq!(all.len(), 32 * 3 * 4 * 128);
        for r in &all {
            let s = compute(r);
            verify(r, &s).unwrap_or_else(|e| panic!("{e}\nresults: {r:?}\nscore: {s:?}"));
            assert!(s.total <= 100);
            assert_eq!(s.total == 100, s.fixes.is_empty() && !s.checks.is_empty(), "100 means nothing failed: {s:?}");
        }
    }

    #[test]
    fn passing_one_more_check_never_lowers_the_score() {
        for r in all_results() {
            let base = compute(&r).total;
            let better: [Box<dyn Fn(&mut DnsResults)>; 7] = [
                Box::new(|r| r.spf = Some(SpfRecord { raw: "v=spf1 -all".into(), mechanisms: vec![] })),
                Box::new(|r| r.dkim = Some(DkimRecord { selector: "s1".into(), raw: "x".into() })),
                Box::new(|r| r.dmarc = Some(DmarcRecord { policy: "reject".into(), rua: None, pct: 100 })),
                Box::new(|r| r.mx = Some(MxRecord { host: "m".into(), priority: 1 })),
                Box::new(|r| r.ptr = Some(PtrRecord { hostname: "h".into() })),
                Box::new(|r| r.rdns = Some("h".into())),
                Box::new(|r| r.blacklisted = false),
            ];
            for improve in &better {
                let mut r2 = r.clone();
                improve(&mut r2);
                assert!(compute(&r2).total >= base, "{r:?} got worse");
            }
        }
    }

    #[test]
    fn a_wrong_score_is_caught() {
        let r = build([true; 5], 2, false, true, 0);
        let good = compute(&r);
        assert_eq!(good.total, 100);
        verify(&r, &good).unwrap();

        let mut s = good.clone();
        s.total = 99;
        assert!(verify(&r, &s).unwrap_err().contains("total"));
        let mut s = good.clone();
        s.checks.pop();
        assert!(verify(&r, &s).unwrap_err().contains("checks"));
        let mut s = good.clone();
        s.checks[0] = CheckResult { name: "SPF".into(), passed: false, detail: None };
        assert!(verify(&r, &s).unwrap_err().contains("SPF"));
        let mut s = good.clone();
        s.fixes.push("a fix for nothing".into());
        assert!(verify(&r, &s).unwrap_err().contains("fixes"));
    }

    #[test]
    fn nothing_verified_means_no_score_and_no_crash() {
        let r = build([false; 5], 0, false, true, 127);
        let s = compute(&r);
        assert_eq!((s.total, s.checks.len(), s.fixes.len()), (0, 0, 0));
        assert!(s.note.as_deref().unwrap().contains("Could not verify"));
        verify(&r, &s).unwrap();
    }

    #[test]
    fn a_timed_out_check_is_left_out_not_failed() {
        // DKIM could not be looked up: the other four applicable-and-verified checks decide the score
        let r = build([true, false, true, false, false], 2, false, false, 0b10); // bit 1 = DKIM
        let s = compute(&r);
        assert!(!s.checks.iter().any(|c| c.name == "DKIM"));
        assert!(s.fixes.iter().all(|f| !f.contains("DKIM")), "no 'Add DKIM' fix for a lookup that never answered");
        assert_eq!(s.total, 100); // SPF 15 + DMARC 15 + policy 10 + MX 10 all pass
        assert!(s.note.unwrap().contains("DKIM"));
    }
}
