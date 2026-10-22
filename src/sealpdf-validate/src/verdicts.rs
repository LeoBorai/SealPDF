use sealpdf_core::{ValidityError, Verdict, VerdictKind};

/// Turns the raised items into the document verdict list.
///
/// Repeated items are dropped, `KO` items move to the front (keeping their order), and
/// `SIGN_PROFILE_NOT_CHECKED` goes first when the only `KO` is `CERTIFICATE_EXPIRED`: an
/// expired certificate says little about a signature that carries long-term data. An empty
/// list is `[OK]`.
pub fn order(raised: Vec<Verdict>) -> Vec<Verdict> {
    let mut list: Vec<Verdict> = Vec::new();
    for item in raised {
        if list.contains(&item) {
            continue;
        }
        if item.verdict == VerdictKind::Ko {
            let at = list
                .iter()
                .position(|v| v.verdict != VerdictKind::Ko)
                .unwrap_or(list.len());
            list.insert(at, item);
        } else {
            list.push(item);
        }
    }

    let only_expired = list
        .iter()
        .filter(|v| v.verdict == VerdictKind::Ko)
        .all(|v| v.error == Some(ValidityError::CertificateExpired));
    let has_expired = list.contains(&Verdict::ko(ValidityError::CertificateExpired));
    if only_expired
        && has_expired
        && let Some(at) = list
            .iter()
            .position(|v| *v == Verdict::unknown(ValidityError::SignProfileNotChecked))
    {
        list.swap(0, at);
    }

    if list.is_empty() {
        list.push(Verdict::OK);
    }
    list
}

#[cfg(test)]
mod tests {
    use super::*;
    use ValidityError::*;

    #[test]
    fn nothing_raised_is_ok() {
        assert_eq!(order(vec![]), vec![Verdict::OK]);
    }

    #[test]
    fn repeated_items_appear_once() {
        let v = order(vec![Verdict::ko(NoMatchData), Verdict::ko(NoMatchData)]);
        assert_eq!(v, vec![Verdict::ko(NoMatchData)]);
    }

    #[test]
    fn ko_goes_before_unknown_in_arrival_order() {
        let v = order(vec![
            Verdict::unknown(ModifiedDocument),
            Verdict::ko(NoMatchData),
            Verdict::ko(CorruptedSign),
            Verdict::unknown(SignProfileNotChecked),
        ]);
        assert_eq!(
            v,
            vec![
                Verdict::ko(NoMatchData),
                Verdict::ko(CorruptedSign),
                Verdict::unknown(ModifiedDocument),
                Verdict::unknown(SignProfileNotChecked),
            ]
        );
    }

    #[test]
    fn expired_certificate_with_long_term_data_puts_the_profile_first() {
        let v = order(vec![
            Verdict::ko(CertificateExpired),
            Verdict::unknown(SignProfileNotChecked),
        ]);
        assert_eq!(
            v,
            vec![
                Verdict::unknown(SignProfileNotChecked),
                Verdict::ko(CertificateExpired),
            ]
        );
    }

    #[test]
    fn another_ko_keeps_the_ko_first() {
        let v = order(vec![
            Verdict::ko(CertificateExpired),
            Verdict::ko(NoMatchData),
            Verdict::unknown(SignProfileNotChecked),
        ]);
        assert_eq!(v[0], Verdict::ko(CertificateExpired));
        assert_eq!(v.len(), 3);
    }

    #[test]
    fn expired_alone_stays() {
        assert_eq!(
            order(vec![Verdict::ko(CertificateExpired)]),
            vec![Verdict::ko(CertificateExpired)]
        );
    }
}
