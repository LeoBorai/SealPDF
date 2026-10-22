use chrono::{FixedOffset, NaiveDate, SecondsFormat};

/// Reads a PDF date, `D:YYYYMMDDHHmmSSOHH'mm'` with everything after the year optional, and
/// returns it as RFC 3339.
pub(crate) fn pdf_date(text: &str) -> Option<String> {
    let rest = text.trim().strip_prefix("D:").unwrap_or(text.trim());
    let digits = |s: &str, n: usize| -> Option<(u32, usize)> {
        let part = s.get(..n)?;
        if !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        part.parse().ok().map(|v| (v, n))
    };

    let mut at = 0;
    let (year, n) = digits(rest, 4)?;
    at += n;
    let field = |default: u32, at: &mut usize| match digits(&rest[*at..], 2) {
        Some((v, n)) => {
            *at += n;
            v
        }
        None => default,
    };
    let month = field(1, &mut at);
    let day = field(1, &mut at);
    let hour = field(0, &mut at);
    let minute = field(0, &mut at);
    let second = field(0, &mut at);

    let offset_seconds = match rest[at..].chars().next() {
        None | Some('Z') => 0,
        Some(sign @ ('+' | '-')) => {
            let tail = rest[at + 1..].replace('\'', "");
            let (h, _) = digits(&tail, 2)?;
            let m = digits(tail.get(2..).unwrap_or(""), 2).map_or(0, |(m, _)| m);
            let secs = i32::try_from(h * 3600 + m * 60).ok()?;
            if sign == '-' { -secs } else { secs }
        }
        Some(_) => return None,
    };

    let offset = FixedOffset::east_opt(offset_seconds)?;
    NaiveDate::from_ymd_opt(i32::try_from(year).ok()?, month, day)?
        .and_hms_opt(hour, minute, second)?
        .and_local_timezone(offset)
        .single()
        .map(|t| t.to_rfc3339_opts(SecondsFormat::Secs, true))
}

#[cfg(test)]
mod tests {
    use super::pdf_date;

    #[test]
    fn reads_full_dates_with_offsets() {
        assert_eq!(
            pdf_date("D:20240517103000+00'00'").as_deref(),
            Some("2024-05-17T10:30:00Z")
        );
        assert_eq!(
            pdf_date("D:20240517103000+02'00'").as_deref(),
            Some("2024-05-17T10:30:00+02:00")
        );
        assert_eq!(
            pdf_date("D:20240517103000-05'30'").as_deref(),
            Some("2024-05-17T10:30:00-05:30")
        );
        assert_eq!(
            pdf_date("D:20240517103000Z").as_deref(),
            Some("2024-05-17T10:30:00Z")
        );
    }

    #[test]
    fn reads_partial_dates() {
        assert_eq!(pdf_date("D:2024").as_deref(), Some("2024-01-01T00:00:00Z"));
        assert_eq!(
            pdf_date("D:20240517").as_deref(),
            Some("2024-05-17T00:00:00Z")
        );
    }

    #[test]
    fn rejects_what_is_not_a_date() {
        for bad in ["", "yesterday", "D:20241301", "D:2024051710300", "D:2024x"] {
            assert_eq!(pdf_date(bad), None, "{bad}");
        }
    }
}
