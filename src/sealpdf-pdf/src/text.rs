//! Text of the visible signature: `$$...$$` placeholders and `SimpleDateFormat` patterns.

use chrono::{DateTime, Datelike, FixedOffset, Timelike};

/// Language of month, day and AM/PM names in formatted dates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DateLocale {
    #[default]
    Es,
    En,
}

/// Certificate data available to the text template.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SignerText {
    pub subject_cn: String,
    pub subject_dn: String,
    pub issuer_cn: String,
    pub serial: String,
    pub given_name: String,
    pub surname: String,
    pub organization: String,
    pub title: String,
    pub pseudonym: String,
    /// Organizational units, most specific first.
    pub ous: Vec<String>,
}

pub struct TextContext<'a> {
    pub signer: &'a SignerText,
    pub reason: Option<&'a str>,
    pub location: Option<&'a str>,
    pub contact: Option<&'a str>,
    /// Signing time in the zone the text should show.
    pub signed_at: DateTime<FixedOffset>,
    /// Value of `$$UUID$$`. Supplied by the caller so output stays deterministic.
    pub uuid: &'a str,
    pub locale: DateLocale,
}

/// Replaces every known `$$NAME$$` placeholder in one pass. Unknown tags stay as written.
pub fn expand_placeholders(template: &str, ctx: &TextContext<'_>) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(start) = rest.find("$$") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let Some(end) = after.find("$$") else {
            out.push_str(&rest[start..]);
            return out;
        };
        let tag = &after[..end];
        match resolve(tag, ctx) {
            Some(value) => {
                out.push_str(&value);
                rest = &after[end + 2..];
            }
            None => {
                // Not a tag: keep the opening `$$` and rescan from the text after it,
                // so `$$ $$REASON$$` still resolves the inner tag.
                out.push_str("$$");
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

fn resolve(tag: &str, ctx: &TextContext<'_>) -> Option<String> {
    let s = ctx.signer;
    let opt = |v: Option<&str>| v.unwrap_or("").to_owned();
    Some(match tag {
        "SUBJECTCN" => s.subject_cn.clone(),
        "SUBJECTDN" => s.subject_dn.clone(),
        "ISSUERCN" => s.issuer_cn.clone(),
        "CERTSERIAL" => s.serial.clone(),
        "GIVENNAME" => s.given_name.clone(),
        "SURNAME" => s.surname.clone(),
        "ORGANIZATION" => s.organization.clone(),
        "TITLE" => s.title.clone(),
        "PSEUDONYM" => s.pseudonym.clone(),
        "OU" => s.ous.first().cloned().unwrap_or_default(),
        "OUS" => s.ous.join(", "),
        "REASON" => opt(ctx.reason),
        "LOCATION" => opt(ctx.location),
        "CONTACT" => opt(ctx.contact),
        "UUID" => ctx.uuid.to_owned(),
        "DATE" | "SIGNDATE" => default_date(ctx),
        _ => {
            let pattern = tag.strip_prefix("SIGNDATE=")?;
            format_date(pattern, &ctx.signed_at, ctx.locale).unwrap_or_else(|| default_date(ctx))
        }
    })
}

fn default_date(ctx: &TextContext<'_>) -> String {
    let pattern = match ctx.locale {
        DateLocale::Es => "dd/MM/yy H:mm",
        DateLocale::En => "M/d/yy, h:mm a",
    };
    format_date(pattern, &ctx.signed_at, ctx.locale).expect("default pattern is valid")
}

const MONTHS_ES: [&str; 12] = [
    "enero",
    "febrero",
    "marzo",
    "abril",
    "mayo",
    "junio",
    "julio",
    "agosto",
    "septiembre",
    "octubre",
    "noviembre",
    "diciembre",
];
const MONTHS_EN: [&str; 12] = [
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
];
const DAYS_ES: [&str; 7] = [
    "lunes",
    "martes",
    "miércoles",
    "jueves",
    "viernes",
    "sábado",
    "domingo",
];
const DAYS_EN: [&str; 7] = [
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
    "Sunday",
];

fn short(name: &str, locale: DateLocale) -> String {
    match locale {
        // Spanish abbreviations keep three letters ("mié", "sáb"); months too ("sep" in Java 8).
        DateLocale::Es | DateLocale::En => name.chars().take(3).collect(),
    }
}

fn pad(n: i64, width: usize) -> String {
    format!("{n:0width$}")
}

/// Formats `dt` with a Java `SimpleDateFormat` pattern. `None` when the pattern is invalid,
/// as when Java throws `IllegalArgumentException`.
pub fn format_date(
    pattern: &str,
    dt: &DateTime<FixedOffset>,
    locale: DateLocale,
) -> Option<String> {
    let chars: Vec<char> = pattern.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '\'' {
            if chars.get(i + 1) == Some(&'\'') {
                out.push('\'');
                i += 2;
                continue;
            }
            i += 1;
            loop {
                match chars.get(i) {
                    None => return None, // unterminated quote
                    Some('\'') if chars.get(i + 1) == Some(&'\'') => {
                        out.push('\'');
                        i += 2;
                    }
                    Some('\'') => {
                        i += 1;
                        break;
                    }
                    Some(&q) => {
                        out.push(q);
                        i += 1;
                    }
                }
            }
            continue;
        }
        if !c.is_ascii_alphabetic() {
            out.push(c);
            i += 1;
            continue;
        }
        let n = chars[i..].iter().take_while(|&&x| x == c).count();
        i += n;
        out.push_str(&field(c, n, dt, locale)?);
    }
    Some(out)
}

fn field(c: char, n: usize, dt: &DateTime<FixedOffset>, locale: DateLocale) -> Option<String> {
    let (months, days) = match locale {
        DateLocale::Es => (&MONTHS_ES, &DAYS_ES),
        DateLocale::En => (&MONTHS_EN, &DAYS_EN),
    };
    let hour = i64::from(dt.hour());
    let offset_secs = dt.offset().local_minus_utc();
    let (sign, abs) = (
        if offset_secs < 0 { '-' } else { '+' },
        offset_secs.unsigned_abs(),
    );
    let (oh, om) = (abs / 3600, abs % 3600 / 60);
    let weekday = dt.weekday().num_days_from_monday() as usize;
    Some(match c {
        'G' => match locale {
            DateLocale::Es => "d. C.".into(),
            DateLocale::En => "AD".into(),
        },
        'y' | 'Y' => {
            let y = i64::from(dt.year());
            if n == 2 {
                pad(y.rem_euclid(100), 2)
            } else {
                pad(y, n)
            }
        }
        'M' | 'L' => {
            let m = dt.month0() as usize;
            match n {
                1 | 2 => pad(m as i64 + 1, n),
                3 => short(months[m], locale),
                _ => months[m].to_owned(),
            }
        }
        'w' => pad(i64::from(dt.iso_week().week()), n),
        'W' => {
            let first = dt.with_day(1)?.weekday().num_days_from_monday();
            pad(i64::from((dt.day() + first - 1) / 7 + 1), n)
        }
        'D' => pad(i64::from(dt.ordinal()), n),
        'd' => pad(i64::from(dt.day()), n),
        'F' => pad(i64::from((dt.day() - 1) / 7 + 1), n),
        'E' => {
            if n >= 4 {
                days[weekday].to_owned()
            } else {
                short(days[weekday], locale)
            }
        }
        'u' => pad(weekday as i64 + 1, n),
        'a' => (if hour < 12 { "AM" } else { "PM" }).to_owned(),
        'H' => pad(hour, n),
        'k' => pad(if hour == 0 { 24 } else { hour }, n),
        'K' => pad(hour % 12, n),
        'h' => pad(if hour % 12 == 0 { 12 } else { hour % 12 }, n),
        'm' => pad(i64::from(dt.minute()), n),
        's' => pad(i64::from(dt.second()), n),
        'S' => pad(i64::from(dt.timestamp_subsec_millis()), n),
        'z' => {
            if offset_secs == 0 {
                "UTC".into()
            } else {
                format!("GMT{sign}{oh:02}:{om:02}")
            }
        }
        'Z' => format!("{sign}{oh:02}{om:02}"),
        'X' => {
            if offset_secs == 0 {
                "Z".into()
            } else {
                match n {
                    1 => format!("{sign}{oh:02}"),
                    2 => format!("{sign}{oh:02}{om:02}"),
                    _ => format!("{sign}{oh:02}:{om:02}"),
                }
            }
        }
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn at(offset_h: i32) -> DateTime<FixedOffset> {
        FixedOffset::east_opt(offset_h * 3600)
            .unwrap()
            .with_ymd_and_hms(2024, 3, 5, 15, 7, 9)
            .unwrap()
    }

    fn signer() -> SignerText {
        SignerText {
            subject_cn: "PEREZ GARCIA JUAN - 12345678Z".into(),
            subject_dn: "CN=PEREZ GARCIA JUAN - 12345678Z,SERIALNUMBER=IDCES-12345678Z".into(),
            issuer_cn: "AC FNMT".into(),
            serial: "4660".into(),
            given_name: "JUAN".into(),
            surname: "PEREZ GARCIA".into(),
            organization: "ACME".into(),
            title: "Director".into(),
            pseudonym: "jperez".into(),
            ous: vec!["Ventas".into(), "Norte".into()],
        }
    }

    fn run(template: &str) -> String {
        let s = signer();
        let ctx = TextContext {
            signer: &s,
            reason: Some("Aprobado"),
            location: Some("Madrid"),
            contact: Some("a@b.es"),
            signed_at: at(1),
            uuid: "uuid-1",
            locale: DateLocale::Es,
        };
        expand_placeholders(template, &ctx)
    }

    #[test]
    fn every_placeholder() {
        let cases = [
            ("$$SUBJECTCN$$", "PEREZ GARCIA JUAN - 12345678Z"),
            (
                "$$SUBJECTDN$$",
                "CN=PEREZ GARCIA JUAN - 12345678Z,SERIALNUMBER=IDCES-12345678Z",
            ),
            ("$$ISSUERCN$$", "AC FNMT"),
            ("$$CERTSERIAL$$", "4660"),
            ("$$GIVENNAME$$", "JUAN"),
            ("$$SURNAME$$", "PEREZ GARCIA"),
            ("$$ORGANIZATION$$", "ACME"),
            ("$$OU$$", "Ventas"),
            ("$$OUS$$", "Ventas, Norte"),
            ("$$TITLE$$", "Director"),
            ("$$PSEUDONYM$$", "jperez"),
            ("$$REASON$$", "Aprobado"),
            ("$$LOCATION$$", "Madrid"),
            ("$$CONTACT$$", "a@b.es"),
            ("$$UUID$$", "uuid-1"),
            ("$$DATE$$", "05/03/24 15:07"),
            ("$$SIGNDATE$$", "05/03/24 15:07"),
            ("$$SIGNDATE=yyyy-MM-dd HH:mm:ss$$", "2024-03-05 15:07:09"),
        ];
        for (template, expected) in cases {
            assert_eq!(run(template), expected, "{template}");
        }
    }

    #[test]
    fn missing_values_become_empty() {
        let s = SignerText::default();
        let ctx = TextContext {
            signer: &s,
            reason: None,
            location: None,
            contact: None,
            signed_at: at(0),
            uuid: "",
            locale: DateLocale::Es,
        };
        assert_eq!(
            expand_placeholders("[$$OU$$|$$OUS$$|$$REASON$$|$$TITLE$$]", &ctx),
            "[|||]"
        );
    }

    #[test]
    fn mixed_text_and_repeated_tags() {
        assert_eq!(
            run("Firmado por $$SUBJECTCN$$\nMotivo: $$REASON$$ ($$REASON$$)"),
            "Firmado por PEREZ GARCIA JUAN - 12345678Z\nMotivo: Aprobado (Aprobado)"
        );
    }

    #[test]
    fn unknown_and_unterminated_tags_are_kept() {
        assert_eq!(run("$$NOPE$$ x"), "$$NOPE$$ x");
        assert_eq!(run("price $5 $$ end"), "price $5 $$ end");
        assert_eq!(run("$$ $$REASON$$"), "$$ Aprobado");
        assert_eq!(run("$$REASON"), "$$REASON");
    }

    #[test]
    fn values_are_not_rescanned() {
        let s = SignerText {
            subject_cn: "$$REASON$$".into(),
            ..Default::default()
        };
        let ctx = TextContext {
            signer: &s,
            reason: Some("X"),
            location: None,
            contact: None,
            signed_at: at(0),
            uuid: "",
            locale: DateLocale::Es,
        };
        assert_eq!(expand_placeholders("$$SUBJECTCN$$", &ctx), "$$REASON$$");
    }

    #[test]
    fn invalid_date_pattern_falls_back_to_default() {
        assert_eq!(run("$$SIGNDATE=qqq$$"), "05/03/24 15:07");
        assert_eq!(run("$$SIGNDATE=HH 'sin cerrar$$"), "05/03/24 15:07");
    }

    #[test]
    fn simple_date_format_letters() {
        let dt = at(1);
        let f = |p: &str, l| format_date(p, &dt, l).unwrap();
        assert_eq!(f("yy", DateLocale::Es), "24");
        assert_eq!(f("yyyy", DateLocale::Es), "2024");
        assert_eq!(f("M/MM/MMM/MMMM", DateLocale::Es), "3/03/mar/marzo");
        assert_eq!(f("MMMM", DateLocale::En), "March");
        assert_eq!(f("d dd D", DateLocale::Es), "5 05 65");
        assert_eq!(f("E EEEE", DateLocale::Es), "mar martes");
        assert_eq!(f("EEEE", DateLocale::En), "Tuesday");
        assert_eq!(f("u", DateLocale::Es), "2");
        assert_eq!(f("H h K k a", DateLocale::En), "15 3 3 15 PM");
        assert_eq!(f("hh:mm:ss", DateLocale::En), "03:07:09");
        assert_eq!(f("Z z", DateLocale::En), "+0100 GMT+01:00");
        assert_eq!(f("X XX XXX", DateLocale::En), "+01 +0100 +01:00");
        assert_eq!(f("w", DateLocale::Es), "10");
        assert_eq!(f("F", DateLocale::Es), "1");
        assert_eq!(f("G", DateLocale::En), "AD");
    }

    #[test]
    fn quoting_and_midnight_edge_cases() {
        let dt = at(0)
            .timezone()
            .with_ymd_and_hms(2024, 1, 1, 0, 0, 0)
            .unwrap();
        let f = |p: &str| format_date(p, &dt, DateLocale::En).unwrap();
        assert_eq!(f("h k K H a"), "12 24 0 0 AM");
        assert_eq!(f("dd 'de' MMMM 'de' yyyy"), "01 de January de 2024");
        assert_eq!(f("'it''s' d"), "it's 1");
        assert_eq!(f("''"), "'");
        assert_eq!(f("dd/MM/yyyy, [HH]"), "01/01/2024, [00]");
        assert_eq!(f("X"), "Z");
    }
}
