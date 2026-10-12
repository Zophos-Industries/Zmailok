use crate::types::AppError;

/// Lowercases and validates a domain name typed by a user. Accepts ASCII names only (write
/// internationalised names in their `xn--` form) and needs at least one dot.
pub fn normalize(raw: &str) -> Result<String, AppError> {
    let d = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    let label_ok = |l: &str| {
        (1..=63).contains(&l.len()) && !l.starts_with('-') && !l.ends_with('-') && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    };
    if d.len() <= 253 && d.contains('.') && d.split('.').all(label_ok) { Ok(d) } else { Err(AppError::InvalidDomain) }
}

#[cfg(test)]
mod tests {
    use super::normalize;

    #[test]
    fn accepts_and_cleans_up_normal_domains() {
        assert_eq!(normalize(" Example.COM. ").unwrap(), "example.com");
        assert_eq!(normalize("mail.sub-domain.example.co.uk").unwrap(), "mail.sub-domain.example.co.uk");
        assert_eq!(normalize("xn--bcher-kva.example").unwrap(), "xn--bcher-kva.example");
    }

    #[test]
    fn rejects_everything_else() {
        for bad in ["", "localhost", "a..b", "-a.com", "a-.com", "a b.com", "a.com/x", "a.com:80", "bücher.de", "http://a.com", "a_b.com", "user@a.com"] {
            assert!(normalize(bad).is_err(), "{bad} should be rejected");
        }
        assert!(normalize(&format!("{}.com", "a".repeat(64))).is_err());
        assert!(normalize(&format!("{}.com", vec!["a".repeat(60); 5].join("."))).is_err());
    }
}
