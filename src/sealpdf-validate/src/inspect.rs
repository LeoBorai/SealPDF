use crate::{
    date::pdf_date,
    report::{REPORT_VERSION, Report, SignatureInfo},
    verdicts::order,
};
use sealpdf_cms::{digest_algorithm, verify_detached};
use sealpdf_core::{Clock, Error, Result, ValidityError, Verdict};
use sealpdf_pdf::{PdfDocument, SignatureField};
use std::time::SystemTime;

/// How many signatures the PDF carries, document timestamps excluded. No CMS is decoded, so
/// this is cheap enough to run whenever a document is opened.
pub fn signature_count(pdf: &PdfDocument) -> usize {
    pdf.signatures().len()
}

/// Lists the signatures of `pdf`, checks each one and builds the document verdict list.
///
/// `clock` gives the time the certificates' validity periods are compared with. Fails for an
/// encrypted PDF; a PDF without signatures is a report with the verdict `KO NO_SIGN`.
pub fn inspect(pdf: &PdfDocument, clock: &dyn Clock) -> Result<Report> {
    if pdf.is_encrypted() {
        return Err(Error::Refused(
            "the PDF is encrypted; inspecting encrypted PDFs is not supported yet".into(),
        ));
    }
    let total = pdf.revisions().len().max(1);
    let now = SystemTime::from(clock.now());

    let mut fields: Vec<SignatureField> = pdf
        .signature_fields()
        .into_iter()
        .filter(SignatureField::is_signed)
        .collect();
    // Oldest first: by where the signed range ends. A broken range sorts last.
    fields.sort_by_key(|f| range_end(pdf, f).unwrap_or(usize::MAX));
    let checked: Vec<Checked> = fields.iter().map(|f| check(pdf, f, total, now)).collect();

    let verdicts = verdicts(pdf, &checked, total);
    Ok(Report {
        version: REPORT_VERSION,
        revisions: pdf.revisions().len(),
        signatures: checked.into_iter().map(|c| c.info).collect(),
        verdicts,
        trust_checked: false,
    })
}

struct Checked {
    info: SignatureInfo,
    /// The signer info carries a signature timestamp token.
    has_timestamp: bool,
    /// DocMDP `/P` when this signature certifies the document.
    docmdp: Option<u8>,
}

/// The `/ByteRange` as four offsets that lie inside the file, in order.
fn byte_range(pdf: &PdfDocument, field: &SignatureField) -> Option<[usize; 4]> {
    let range = field.value.as_ref()?.byte_range.as_deref()?;
    let [a, b, c, d] = <[i64; 4]>::try_from(range).ok()?;
    let [a, b, c, d] = [a, b, c, d].map(|n| usize::try_from(n).ok());
    let (a, b, c, d) = (a?, b?, c?, d?);
    (a.checked_add(b)? <= c && c.checked_add(d)? <= pdf.bytes().len()).then_some([a, b, c, d])
}

/// Where the signed bytes end.
fn range_end(pdf: &PdfDocument, field: &SignatureField) -> Option<usize> {
    byte_range(pdf, field).map(|[_, _, c, d]| c + d)
}

/// The bytes a signature covers.
fn covered(pdf: &PdfDocument, [a, b, c, d]: [usize; 4]) -> Vec<u8> {
    let bytes = pdf.bytes();
    [&bytes[a..a + b], &bytes[c..c + d]].concat()
}

/// The 1-based revision a signature covering bytes up to `end` belongs to: the first one that
/// reaches `end`, allowing for line ends written after `%%EOF`.
fn revision_of(pdf: &PdfDocument, end: Option<usize>, total: usize) -> usize {
    let Some(end) = end else { return total };
    let bytes = pdf.bytes();
    pdf.revisions()
        .iter()
        .position(|r| {
            r.end >= end
                || bytes[r.end..end]
                    .iter()
                    .all(|b| matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
        })
        .map_or(total, |i| i + 1)
}

fn check(pdf: &PdfDocument, field: &SignatureField, total: usize, now: SystemTime) -> Checked {
    let value = field
        .value
        .as_ref()
        .expect("only signed fields are checked");
    let range = byte_range(pdf, field);
    let mut status = Vec::new();
    let mut signer = None;
    let mut has_timestamp = false;

    match (value.contents.as_deref(), range) {
        (Some(contents), Some(_)) if value.is_doc_timestamp => {
            if let Err(e) = digest_algorithm(contents) {
                status.push(e.kind);
            }
        }
        (Some(contents), Some(range)) => match verify_detached(contents, &covered(pdf, range)) {
            Ok(ok) => {
                signer = ok.signer_cn;
                has_timestamp = ok.has_signature_timestamp;
                if now < ok.not_before {
                    status.push(ValidityError::CertificateNotValidYet);
                } else if now > ok.not_after {
                    status.push(ValidityError::CertificateExpired);
                }
            }
            Err(e) => status.push(e.kind),
        },
        _ => status.push(ValidityError::CorruptedSign),
    }

    let info = SignatureInfo {
        field: field.name.clone(),
        page: field.page,
        sub_filter: value.sub_filter.clone(),
        doc_timestamp: value.is_doc_timestamp,
        signer: signer.or_else(|| value.name.clone()),
        signed_at: value
            .signing_time
            .as_ref()
            .map(|m| pdf_date(m).unwrap_or_else(|| m.clone())),
        reason: value.reason.clone(),
        location: value.location.clone(),
        revision: revision_of(pdf, range.map(|[_, _, c, d]| c + d), total),
        status,
    };
    Checked {
        info,
        has_timestamp,
        docmdp: value.docmdp,
    }
}

fn verdicts(pdf: &PdfDocument, checked: &[Checked], total: usize) -> Vec<Verdict> {
    let signatures = || checked.iter().filter(|c| !c.info.doc_timestamp);
    if signatures().next().is_none() {
        return vec![Verdict::ko(ValidityError::NoSign)];
    }

    let mut raised = Vec::new();
    let last_signed = checked.iter().map(|c| c.info.revision).max().unwrap_or(0);
    if total > last_signed {
        raised.push(Verdict::unknown(ValidityError::ModifiedDocument));
    }

    let newest = signatures().max_by_key(|c| c.info.revision);
    if newest.is_some_and(|c| c.has_timestamp)
        || pdf.has_dss()
        || checked.iter().any(|c| c.info.doc_timestamp)
    {
        raised.push(Verdict::unknown(ValidityError::SignProfileNotChecked));
    }

    raised.extend(
        checked
            .iter()
            .flat_map(|c| &c.info.status)
            .map(|e| Verdict::ko(*e)),
    );

    if raised.is_empty() && pdf.certification_level() == Some(1) {
        let certified_at = checked
            .iter()
            .filter(|c| c.docmdp.is_some())
            .map(|c| c.info.revision)
            .max()
            .unwrap_or(0);
        if checked.iter().any(|c| c.info.revision > certified_at) {
            raised.push(Verdict::ko(ValidityError::CertifiedSignRevision));
        }
    }

    order(raised)
}
