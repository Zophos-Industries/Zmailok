//! Combines several lookups into one answer without mistaking "could not ask" for "no".
//! A lookup that timed out is `Err(AppError::DnsTimeout)`. No network access here, so it is fully tested.

use crate::types::AppError;

/// The first lookup that found something wins. If none did, a timeout among them means "could not
/// verify" (`Err(DnsTimeout)`) and not "not found". Any other error is passed on.
pub fn first_hit<T>(results: Vec<Result<Option<T>, AppError>>) -> Result<Option<T>, AppError> {
    let mut timed_out = false;
    for res in results {
        match res {
            Ok(Some(hit)) => return Ok(Some(hit)),
            Ok(None) => {}
            Err(AppError::DnsTimeout) => timed_out = true,
            Err(other) => return Err(other),
        }
    }
    if timed_out { Err(AppError::DnsTimeout) } else { Ok(None) }
}

/// True if any lookup says yes. A "no" needs every lookup to have answered.
pub fn any_true(results: Vec<Result<bool, AppError>>) -> Result<bool, AppError> {
    first_hit(results.into_iter().map(|r| r.map(|yes| yes.then_some(()))).collect()).map(|hit| hit.is_some())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn timeout<T>() -> Result<Option<T>, AppError> {
        Err(AppError::DnsTimeout)
    }

    #[test]
    fn a_hit_wins_even_if_other_lookups_timed_out() {
        assert_eq!(first_hit(vec![timeout(), Ok(Some(2)), Ok(None)]).unwrap(), Some(2));
        assert_eq!(first_hit(vec![Ok(Some(1)), timeout(), Ok(Some(3))]).unwrap(), Some(1), "the first hit in order wins");
    }

    #[test]
    fn no_hit_and_no_timeout_is_a_real_no() {
        assert_eq!(first_hit::<u8>(vec![Ok(None), Ok(None)]).unwrap(), None);
        assert_eq!(first_hit::<u8>(vec![]).unwrap(), None);
    }

    #[test]
    fn no_hit_with_a_timeout_is_unverified_not_no() {
        assert!(matches!(first_hit::<u8>(vec![Ok(None), timeout(), Ok(None)]), Err(AppError::DnsTimeout)));
    }

    #[test]
    fn other_errors_are_passed_on() {
        let r = first_hit::<u8>(vec![Ok(None), Err(AppError::LookupFailed("servfail".into()))]);
        assert!(matches!(r, Err(AppError::LookupFailed(m)) if m == "servfail"));
    }

    #[test]
    fn any_true_needs_every_lookup_to_answer_for_a_no() {
        assert!(any_true(vec![Ok(false), Ok(true), Err(AppError::DnsTimeout)]).unwrap());
        assert!(!any_true(vec![Ok(false), Ok(false)]).unwrap());
        assert!(matches!(any_true(vec![Ok(false), Err(AppError::DnsTimeout)]), Err(AppError::DnsTimeout)));
    }
}
