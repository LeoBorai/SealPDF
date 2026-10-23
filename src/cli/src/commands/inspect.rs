use crate::{args::InspectArgs, exit::Failure};
use sealpdf_core::{SystemClock, ValidityError, Verdict};
use sealpdf_pdf::PdfDocument;
use sealpdf_validate::{Report, SignatureInfo, inspect};

/// `sealpdf ls`: shows the signatures. Whatever they hold, it succeeds.
pub fn ls(args: &InspectArgs) -> Result<(), Failure> {
    let report = load(args)?;
    if args.json {
        print_json(&report);
    } else {
        print!("{}", signatures(&report));
    }
    Ok(())
}

/// `sealpdf verify`: shows the signatures and the verdict, and fails unless the verdict is `OK`.
pub fn verify(args: &InspectArgs) -> Result<(), Failure> {
    let report = load(args)?;
    if args.json {
        print_json(&report);
    } else {
        print!("{}{}", signatures(&report), verdicts(&report));
    }
    if report.is_ok() {
        return Ok(());
    }
    let list: Vec<String> = report.verdicts.iter().map(Verdict::to_string).collect();
    Err(Failure::verify_failed(format!(
        "verification failed: {}",
        list.join(", ")
    )))
}

fn load(args: &InspectArgs) -> Result<Report, Failure> {
    let bytes = std::fs::read(&args.input)
        .map_err(|e| Failure::other(format!("cannot read {}: {e}", args.input.display())))?;
    let pdf = PdfDocument::open(bytes, None)?;
    Ok(inspect(&pdf, &SystemClock)?)
}

fn print_json(report: &Report) {
    println!("{}", report.to_json());
}

/// What a signature's status says: `intact`, or the identifiers of what is wrong.
fn status(info: &SignatureInfo) -> String {
    if info.is_intact() {
        return "intact".into();
    }
    let ids: Vec<&str> = info.status.iter().map(|e| e.id()).collect();
    ids.join(", ")
}

/// One row per signature, or a line saying there is none.
pub fn signatures(report: &Report) -> String {
    if report.signatures.is_empty() {
        return "No signatures.\n".into();
    }
    let header = ["#", "FIELD", "SIGNER", "SIGNED AT", "COVERS", "STATUS"];
    let rows: Vec<[String; 6]> = report
        .signatures
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let signer = match (&s.signer, s.doc_timestamp) {
                (_, true) => "(document timestamp)".to_owned(),
                (Some(name), _) => name.clone(),
                (None, _) => "-".to_owned(),
            };
            [
                (i + 1).to_string(),
                s.field.clone(),
                signer,
                s.signed_at.clone().unwrap_or_else(|| "-".into()),
                format!("rev {} of {}", s.revision, report.revisions),
                status(s),
            ]
        })
        .collect();
    let widths: Vec<usize> = (0..header.len())
        .map(|i| {
            rows.iter()
                .map(|r| r[i].chars().count())
                .chain([header[i].len()])
                .max()
                .unwrap_or(0)
        })
        .collect();
    let line = |cols: Vec<&str>| {
        let padded: Vec<String> = cols
            .iter()
            .zip(&widths)
            .map(|(c, w)| format!("{c:<w$}"))
            .collect();
        format!("{}\n", padded.join("  ").trim_end())
    };
    let mut out = line(header.to_vec());
    for row in &rows {
        out.push_str(&line(row.iter().map(String::as_str).collect()));
    }
    out
}

/// The verdict lines, then the reminder that trust was not checked.
pub fn verdicts(report: &Report) -> String {
    let mut out = String::from("\n");
    for v in &report.verdicts {
        match v.error.and_then(meaning) {
            Some(text) => out.push_str(&format!("Verdict: {v} ({text})\n")),
            None => out.push_str(&format!("Verdict: {v}\n")),
        }
    }
    out.push_str("Certificate trust and revocation were not checked.\n");
    out
}

/// In words, what an error id means for a reader of the verdict.
fn meaning(error: ValidityError) -> Option<&'static str> {
    Some(match error {
        ValidityError::NoSign => "the PDF has no signatures",
        ValidityError::NoMatchData => "signed data was changed, or a signature value is wrong",
        ValidityError::CorruptedSign => "a signature cannot be read",
        ValidityError::AlgorithmNotSupported => "a signature uses an algorithm that is not allowed",
        ValidityError::CertificateExpired => "a signer certificate has expired",
        ValidityError::CertificateNotValidYet => "a signer certificate is not valid yet",
        ValidityError::CertificateProblem => "a signer certificate is missing",
        ValidityError::ModifiedDocument => "changes after the last signature were not analysed",
        ValidityError::SignProfileNotChecked => "timestamps and validation data were not verified",
        ValidityError::CertifiedSignRevision => {
            "signed after a certification that allows no changes"
        }
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sealpdf_validate::REPORT_VERSION;

    fn info(
        field: &str,
        signer: Option<&str>,
        revision: usize,
        bad: &[ValidityError],
    ) -> SignatureInfo {
        SignatureInfo {
            field: field.into(),
            page: Some(1),
            sub_filter: Some("adbe.pkcs7.detached".into()),
            doc_timestamp: false,
            signer: signer.map(str::to_owned),
            signed_at: Some("2026-10-20T14:03:00Z".into()),
            reason: None,
            location: None,
            revision,
            status: bad.to_vec(),
        }
    }

    fn report(signatures: Vec<SignatureInfo>, verdicts: Vec<Verdict>) -> Report {
        Report {
            version: REPORT_VERSION,
            revisions: 3,
            signatures,
            verdicts,
            trust_checked: false,
        }
    }

    #[test]
    fn lists_rows_with_coverage_and_status() {
        let r = report(
            vec![
                info("Signature1", Some("Jane Doe"), 2, &[]),
                info(
                    "Signature2",
                    Some("ACME Ltd"),
                    3,
                    &[ValidityError::NoMatchData],
                ),
            ],
            vec![Verdict::ko(ValidityError::NoMatchData)],
        );
        let text = signatures(&r);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].starts_with("#  FIELD"), "{text}");
        assert!(
            lines[1].contains("Jane Doe") && lines[1].ends_with("intact"),
            "{text}"
        );
        assert!(lines[1].contains("rev 2 of 3"), "{text}");
        assert!(lines[2].ends_with("NO_MATCH_DATA"), "{text}");
    }

    #[test]
    fn says_so_when_there_are_no_signatures() {
        let r = report(vec![], vec![Verdict::ko(ValidityError::NoSign)]);
        assert_eq!(signatures(&r), "No signatures.\n");
    }

    #[test]
    fn marks_timestamps_and_unknown_signers() {
        let mut stamp = info("Timestamp1", None, 3, &[]);
        stamp.doc_timestamp = true;
        let r = report(
            vec![info("Signature1", None, 2, &[]), stamp],
            vec![Verdict::OK],
        );
        let text = signatures(&r);
        assert!(text.contains("(document timestamp)"), "{text}");
        assert!(text.lines().nth(1).unwrap().contains("  -  "), "{text}");
    }

    #[test]
    fn verdicts_explain_the_unknown_and_state_the_trust_gap() {
        let r = report(
            vec![],
            vec![
                Verdict::ko(ValidityError::NoMatchData),
                Verdict::unknown(ValidityError::ModifiedDocument),
            ],
        );
        let text = verdicts(&r);
        assert!(text.contains("Verdict: KO NO_MATCH_DATA ("), "{text}");
        assert!(
            text.contains("Verdict: UNKNOWN MODIFIED_DOCUMENT (changes after the last signature were not analysed)"),
            "{text}"
        );
        assert!(
            text.ends_with("Certificate trust and revocation were not checked.\n"),
            "{text}"
        );
        assert_eq!(
            verdicts(&report(vec![], vec![Verdict::OK])).lines().nth(1),
            Some("Verdict: OK")
        );
    }
}
