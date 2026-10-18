//! Signs a PDF with the in-house writer and CMS builder and checks it with OpenSSL.
//! Set `SEALPDF_KEEP_DIR` to keep the PDFs for other validators.

mod common;

use common::Pki;
use lopdf::{Document, Object, StringFormat, dictionary};
use sealpdf_cms::{PadesCms, PadesCmsOptions};
use sealpdf_core::{CommitmentType, DigestAlg, KeyType, Page, Policy, SigAlg};
use sealpdf_pdf::{FieldTarget, IncrementalWriter, PdfDocument, attach_signature};

fn blank_pdf() -> Vec<u8> {
    let mut doc = Document::with_version("1.5");
    let pages = doc.new_object_id();
    let page = doc.add_object(dictionary! { "Type" => "Page", "Parent" => pages });
    doc.objects.insert(
        pages,
        Object::Dictionary(dictionary! {
            "Type" => "Pages", "Kids" => vec![Object::Reference(page)], "Count" => 1,
            "MediaBox" => vec![0.into(), 0.into(), 595.into(), 842.into()],
        }),
    );
    let catalog = doc.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages });
    doc.trailer.set("Root", catalog);
    let id = Object::String(b"sealpdf-test-id!".to_vec(), StringFormat::Hexadecimal);
    doc.trailer.set("ID", vec![id.clone(), id]);
    doc.reference_table.cross_reference_type = lopdf::xref::XrefType::CrossReferenceTable;
    let mut out = Vec::new();
    doc.save_to(&mut out).unwrap();
    out
}

fn sign_pdf(
    pki: &Pki,
    leaf: &common::Leaf,
    chain: &[Vec<u8>],
    alg: SigAlg,
    digest: &str,
    policy: &Policy,
    input: &[u8],
) -> Vec<u8> {
    let pdf = PdfDocument::open(input.to_vec(), None).unwrap();
    let mut w = IncrementalWriter::new(&pdf).unwrap();
    let sig = w
        .add_signature(
            dictionary! {
                "Type" => "Sig", "Filter" => "Adobe.PPKLite", "SubFilter" => "adbe.pkcs7.detached",
                "Reason" => Object::String(b"test".to_vec(), StringFormat::Literal),
            },
            16_000,
        )
        .unwrap();
    attach_signature(
        &mut w,
        &FieldTarget::New {
            page: Page::Number(1),
            rect: None,
        },
        sig,
    )
    .unwrap();
    let prepared = w.finish_signature().unwrap();

    let cms = PadesCms::new(alg, chain, PadesCmsOptions::default()).unwrap();
    let data_digest = cms.digest(&prepared.signed_parts().concat());
    let attrs = cms.signed_attributes_epes(&data_digest, policy).unwrap();
    let signature = pki.sign(leaf, digest, &attrs.to_sign().unwrap());
    let der = cms.assemble(&attrs, &signature).unwrap();
    prepared.embed(&der).unwrap()
}

#[test]
fn signed_pdf_verifies_with_openssl_over_the_byte_range() {
    let Some(pki) = Pki::new() else { return };
    let rsa = pki.leaf("rsa-signer", false, true);
    let ec = pki.leaf("ec-signer", true, true);
    let ca = pki.ca_der();
    let cases = [
        (
            "rsa-sha256",
            &rsa,
            KeyType::Rsa,
            DigestAlg::Sha256,
            "sha256",
        ),
        (
            "rsa-sha512",
            &rsa,
            KeyType::Rsa,
            DigestAlg::Sha512,
            "sha512",
        ),
        (
            "ec-sha256",
            &ec,
            KeyType::Ecdsa,
            DigestAlg::Sha256,
            "sha256",
        ),
        (
            "ec-sha384",
            &ec,
            KeyType::Ecdsa,
            DigestAlg::Sha384,
            "sha384",
        ),
    ];
    for (name, leaf, key, digest, openssl_name) in cases {
        let chain = vec![leaf.cert_der.clone(), ca.clone()];
        let out = sign_pdf(
            &pki,
            leaf,
            &chain,
            SigAlg::new(digest, key),
            openssl_name,
            &Policy::default(),
            &blank_pdf(),
        );

        let parsed = PdfDocument::open(out.clone(), None).unwrap();
        let sig = &parsed.signatures()[0];
        let range = sig.value.as_ref().unwrap().byte_range.clone().unwrap();
        let (a, b, c) = (range[1] as usize, range[2] as usize, range[3] as usize);
        assert_eq!(b + c, out.len());
        let covered = [&out[..a], &out[b..]].concat();

        // The CMS inside /Contents, trimmed of its zero padding.
        let hex = std::str::from_utf8(&out[a + 1..b - 1]).unwrap();
        let raw: Vec<u8> = (0..hex.len() / 2)
            .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
            .collect();
        let len = if raw[1] < 0x80 {
            2 + raw[1] as usize
        } else {
            let n = (raw[1] & 0x7F) as usize;
            2 + n
                + raw[2..2 + n]
                    .iter()
                    .fold(0usize, |acc, x| (acc << 8) | *x as usize)
        };
        assert!(pki.verify(&raw[..len], &covered), "{name}");

        if let Ok(dir) = std::env::var("SEALPDF_KEEP_DIR") {
            std::fs::write(
                std::path::Path::new(&dir).join(format!("pades-{name}.pdf")),
                &out,
            )
            .unwrap();
        }
    }
}

#[test]
fn epes_signed_pdf_verifies_with_openssl() {
    let Some(pki) = Pki::new() else { return };
    let leaf = pki.leaf("rsa-signer", false, true);
    let policy = Policy {
        identifier: Some("2.16.724.1.3.1.1.2.1.9".into()),
        hash: Some("G7roucf600+f03r/o0bAOQ6WAs0=".into()),
        hash_algorithm: Some("SHA-1".into()),
        qualifier: Some("https://sede.060.gob.es/politica_de_firma_anexo_1.pdf".into()),
        commitment_types: vec![CommitmentType {
            identifier: "proof-of-approval".into(),
            qualifiers: vec![],
        }],
        claimed_roles: vec!["Director".into()],
    };
    let out = sign_pdf(
        &pki,
        &leaf,
        std::slice::from_ref(&leaf.cert_der),
        SigAlg::new(DigestAlg::Sha256, KeyType::Rsa),
        "sha256",
        &policy,
        &blank_pdf(),
    );
    let parsed = PdfDocument::open(out.clone(), None).unwrap();
    let range = parsed.signatures()[0]
        .value
        .as_ref()
        .unwrap()
        .byte_range
        .clone()
        .unwrap();
    let (a, b) = (range[1] as usize, range[2] as usize);
    let covered = [&out[..a], &out[b..]].concat();
    let hex = std::str::from_utf8(&out[a + 1..b - 1]).unwrap();
    let raw: Vec<u8> = (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
        .collect();
    let len = if raw[1] < 0x80 {
        2 + raw[1] as usize
    } else {
        let n = (raw[1] & 0x7F) as usize;
        2 + n
            + raw[2..2 + n]
                .iter()
                .fold(0usize, |acc, x| (acc << 8) | *x as usize)
    };
    assert!(pki.verify(&raw[..len], &covered));
    if let Ok(dir) = std::env::var("SEALPDF_KEEP_DIR") {
        std::fs::write(std::path::Path::new(&dir).join("pades-epes.pdf"), &out).unwrap();
    }
}
