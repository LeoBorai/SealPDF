use super::{offered, open_keystore};
use crate::{args::KeystoreArgs, exit::Failure};
use certsign_keystore::Entry;
use chrono::DateTime;
use der::Decode;
use x509_cert::{Certificate, name::Name};

pub fn run(args: &KeystoreArgs) -> Result<(), Failure> {
    let opened = open_keystore(args)?;
    let entries = offered(opened.store.as_ref())?;
    if entries.is_empty() {
        eprintln!("No signing certificates found.");
        return Ok(());
    }
    print!("{}", table(&entries));
    Ok(())
}

/// What one entry shows: alias, subject CN, issuer CN, serial and validity.
#[derive(Debug, PartialEq, Eq)]
pub struct Row {
    pub alias: String,
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    pub valid: String,
}

fn common_name(name: &Name) -> String {
    name.iter()
        .find(|a| a.oid.to_string() == "2.5.4.3")
        .and_then(|a| std::str::from_utf8(a.value.value()).ok().map(str::to_owned))
        .unwrap_or_default()
}

fn date(t: x509_cert::time::Time) -> String {
    DateTime::from_timestamp(t.to_unix_duration().as_secs() as i64, 0)
        .map(|d| d.format("%Y-%m-%d").to_string())
        .unwrap_or_default()
}

pub fn row(entry: &Entry) -> Row {
    let mut row = Row {
        alias: entry.alias.clone(),
        subject: String::new(),
        issuer: String::new(),
        serial: String::new(),
        valid: String::new(),
    };
    if let Ok(cert) = Certificate::from_der(entry.certificate()) {
        let tbs = cert.tbs_certificate();
        row.subject = common_name(tbs.subject());
        row.issuer = common_name(tbs.issuer());
        row.serial = tbs
            .serial_number()
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect();
        row.valid = format!(
            "{} to {}",
            date(tbs.validity().not_before),
            date(tbs.validity().not_after)
        );
    }
    row
}

pub fn table(entries: &[Entry]) -> String {
    let rows: Vec<Row> = entries.iter().map(row).collect();
    let header = ["ALIAS", "SUBJECT", "ISSUER", "SERIAL", "VALID"];
    let cells: Vec<[&str; 5]> = rows
        .iter()
        .map(|r| {
            [
                r.alias.as_str(),
                r.subject.as_str(),
                r.issuer.as_str(),
                r.serial.as_str(),
                r.valid.as_str(),
            ]
        })
        .collect();
    let widths: Vec<usize> = (0..5)
        .map(|i| {
            cells
                .iter()
                .map(|c| c[i].chars().count())
                .chain([header[i].len()])
                .max()
                .unwrap_or(0)
        })
        .collect();
    let line = |cols: [&str; 5]| {
        let padded: Vec<String> = cols
            .iter()
            .zip(&widths)
            .map(|(c, w)| format!("{c:<w$}"))
            .collect();
        format!("{}\n", padded.join("  ").trim_end())
    };
    let mut out = line(header);
    for c in cells {
        out.push_str(&line(c));
    }
    out
}
