mod common;

use certsign_cms::verify_detached;
use certsign_core::{Error, ErrorCode, FixedClock, KeystoreError};
use certsign_keystore::{KeyStore, NoPrompt, Pkcs12KeyStore, StaticPrompt};
use certsign_pades::{SigningParams, sign_pdf};
use chrono::{TimeZone, Utc};
use common::{Leaf, Pki, blank_pdf, certified_pdf};
use der::{Decode, Encode};
use sha2::{Digest, Sha256};

fn clock() -> FixedClock {
    FixedClock(Utc.with_ymd_and_hms(2024, 5, 17, 10, 30, 0).unwrap())
}

/// A key store over a PKCS#12 file that holds `leaf`.
fn store(pki: &Pki, leaf: &Leaf) -> Pkcs12KeyStore {
    let path = pki.p12(leaf, "pw", &[]);
    Pkcs12KeyStore::open(path, &StaticPrompt::new("pw")).unwrap()
}

fn sign(pdf: &[u8], store: &dyn KeyStore, alias: &str) -> certsign_core::Result<Vec<u8>> {
    sign_pdf(
        pdf.to_vec(),
        store,
        alias,
        &clock(),
        &NoPrompt,
        &SigningParams::default(),
    )
}

/// The `/ByteRange` and CMS of the `n`th signature, read from the bytes of the file.
struct Parsed {
    range: [usize; 4],
    cms: Vec<u8>,
    covered: Vec<u8>,
}

fn parse(file: &[u8], n: usize) -> Parsed {
    let pdf = certsign_pdf::PdfDocument::open(file.to_vec(), None).unwrap();
    let sig = &pdf.signatures()[n];
    let r = sig.value.as_ref().unwrap().byte_range.clone().unwrap();
    let range = [r[0] as usize, r[1] as usize, r[2] as usize, r[3] as usize];
    let hex = std::str::from_utf8(&file[range[1] + 1..range[2] - 1]).unwrap();
    let cms: Vec<u8> = (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
        .collect();
    let covered = [&file[..range[1]], &file[range[2]..range[2] + range[3]]].concat();
    Parsed {
        range,
        cms,
        covered,
    }
}

#[test]
fn signs_invisibly_and_keeps_the_original_bytes() {
    let Some(pki) = Pki::new() else { return };
    let leaf = pki.leaf("Ada Lovelace", None);
    let input = blank_pdf(2, false);
    let out = sign(&input, &store(&pki, &leaf), "Ada Lovelace").unwrap();

    assert_eq!(
        out[..input.len()],
        input[..],
        "the first N bytes are the input"
    );
    let pdf = certsign_pdf::PdfDocument::open(out.clone(), None).unwrap();
    assert_eq!(pdf.revisions().len(), 2);
    assert_eq!(pdf.pages().len(), 2);

    let sigs = pdf.signatures();
    assert_eq!(sigs.len(), 1);
    assert_eq!(sigs[0].name, "Signature1");
    assert_eq!(sigs[0].page, Some(1));
    assert_eq!(
        sigs[0].rect,
        Some([0.0; 4]),
        "empty rectangle: nothing is drawn"
    );
    let widget = pdf.document().get_dictionary(sigs[0].id).unwrap();
    assert!(!widget.has(b"AP"), "no appearance stream");

    // ByteRange is [0 a b c], reaching the end of the file, with the hex string in the gap.
    let p = parse(&out, 0);
    assert_eq!(p.range[0], 0);
    assert_eq!(p.range[2] + p.range[3], out.len());
    assert_eq!(out[p.range[1]], b'<');
    assert_eq!(out[p.range[2] - 1], b'>');
    assert_eq!(
        p.range[2] - p.range[1] - 2,
        2 * 27_000,
        "27000 bytes reserved"
    );
}

#[test]
fn the_signature_dictionary_and_cms_follow_the_spec() {
    let Some(pki) = Pki::new() else { return };
    let leaf = pki.leaf("Ada Lovelace", None);
    let out = sign(&blank_pdf(1, false), &store(&pki, &leaf), "Ada Lovelace").unwrap();
    let pdf = certsign_pdf::PdfDocument::open(out.clone(), None).unwrap();
    let value = pdf.signatures()[0].value.clone().unwrap();
    assert_eq!(value.filter.as_deref(), Some("Adobe.PPKLite"));
    assert_eq!(value.sub_filter.as_deref(), Some("adbe.pkcs7.detached"));

    let sig_id = value.id.unwrap();
    let dict = pdf.document().get_dictionary(sig_id).unwrap();
    assert_eq!(
        dict.get(b"Name").unwrap().as_str().unwrap(),
        b"Ada Lovelace"
    );
    assert_eq!(
        dict.get(b"M").unwrap().as_str().unwrap(),
        b"D:20240517103000+00'00'"
    );

    let p = parse(&out, 0);
    let verified = verify_detached(&p.cms, &p.covered).unwrap();
    assert_eq!(verified.signer, leaf.cert_der);
    assert_eq!(verified.certificates.len(), 3, "the whole chain");
    assert_eq!(verified.digest, certsign_core::DigestAlg::Sha256);
    assert_eq!(verified.key, certsign_core::KeyType::Rsa);

    // No signingTime attribute.
    let info = cms::content_info::ContentInfo::from_der(&p.cms[..der_len(&p.cms)]).unwrap();
    let signed: cms::signed_data::SignedData = info.content.decode_as().unwrap();
    let attrs = signed
        .signer_infos
        .0
        .iter()
        .next()
        .unwrap()
        .signed_attrs
        .clone()
        .unwrap();
    assert!(
        attrs
            .iter()
            .all(|a| a.oid.to_string() != "1.2.840.113549.1.9.5")
    );
    assert_eq!(attrs.len(), 3);
    let _ = attrs.to_der().unwrap();
}

fn der_len(data: &[u8]) -> usize {
    if data[1] < 0x80 {
        2 + data[1] as usize
    } else {
        let n = (data[1] & 0x7F) as usize;
        2 + n
            + data[2..2 + n]
                .iter()
                .fold(0usize, |a, b| (a << 8) | *b as usize)
    }
}

#[test]
fn the_algorithm_follows_the_key() {
    let Some(pki) = Pki::new() else { return };
    let cases = [
        (
            pki.leaf("rsa", None),
            certsign_core::DigestAlg::Sha256,
            certsign_core::KeyType::Rsa,
        ),
        (
            pki.leaf("p256", Some("P-256")),
            certsign_core::DigestAlg::Sha256,
            certsign_core::KeyType::Ecdsa,
        ),
        (
            pki.leaf("p384", Some("P-384")),
            certsign_core::DigestAlg::Sha384,
            certsign_core::KeyType::Ecdsa,
        ),
    ];
    for (leaf, digest, key) in cases {
        let out = sign(&blank_pdf(1, false), &store(&pki, &leaf), &leaf.name).unwrap();
        let p = parse(&out, 0);
        let v =
            verify_detached(&p.cms, &p.covered).unwrap_or_else(|e| panic!("{}: {e}", leaf.name));
        assert_eq!((v.digest, v.key), (digest, key), "{}", leaf.name);
    }
}

#[test]
fn p521_keys_are_not_supported() {
    let Some(pki) = Pki::new() else { return };
    let leaf = pki.leaf("p521", Some("P-521"));
    let err = sign(&blank_pdf(1, false), &store(&pki, &leaf), "p521").unwrap_err();
    assert!(matches!(err, Error::UnsupportedAlgorithm(m) if m.contains("curve")));
}

#[test]
fn output_is_deterministic_with_a_fixed_clock() {
    let Some(pki) = Pki::new() else { return };
    for curve in [None, Some("P-256")] {
        let leaf = pki.leaf(&format!("det-{}", curve.unwrap_or("rsa")), curve);
        let ks = store(&pki, &leaf);
        let input = blank_pdf(1, false);
        let a = sign(&input, &ks, &leaf.name).unwrap();
        let b = sign(&input, &ks, &leaf.name).unwrap();
        assert_eq!(a, b, "{curve:?}");
    }
}

#[test]
fn both_xref_styles_work() {
    let Some(pki) = Pki::new() else { return };
    let leaf = pki.leaf("rsa", None);
    let ks = store(&pki, &leaf);
    for modern in [false, true] {
        let out = sign(&blank_pdf(3, modern), &ks, "rsa").unwrap();
        let pdf = certsign_pdf::PdfDocument::open(out.clone(), None).unwrap();
        assert_eq!(pdf.revisions().last().unwrap().xref_stream, modern);
        let p = parse(&out, 0);
        assert!(
            verify_detached(&p.cms, &p.covered).is_ok(),
            "modern={modern}"
        );
    }
}

#[test]
fn signing_again_keeps_the_earlier_signature() {
    let Some(pki) = Pki::new() else { return };
    let a = pki.leaf("alice", None);
    let b = pki.leaf("bob", Some("P-256"));
    let one = sign(&blank_pdf(1, false), &store(&pki, &a), "alice").unwrap();
    let two = sign(&one, &store(&pki, &b), "bob").unwrap();

    assert_eq!(two[..one.len()], one[..]);
    let pdf = certsign_pdf::PdfDocument::open(two.clone(), None).unwrap();
    assert_eq!(pdf.revisions().len(), 3);
    let names: Vec<_> = pdf.signatures().into_iter().map(|s| s.name).collect();
    assert_eq!(names, ["Signature1", "Signature2"]);

    let (first, second) = (parse(&two, 0), parse(&two, 1));
    // The first signature covers the same bytes as before.
    let before = parse(&one, 0);
    assert_eq!(first.range, before.range);
    assert_eq!(
        Sha256::digest(&first.covered),
        Sha256::digest(&before.covered)
    );
    assert!(verify_detached(&first.cms, &first.covered).is_ok());
    assert!(verify_detached(&second.cms, &second.covered).is_ok());
    // The second covers the whole file, the first signature included.
    assert_eq!(second.range[2] + second.range[3], two.len());
}

#[test]
fn encrypted_pdfs_are_refused() {
    use lopdf::{EncryptionState, EncryptionVersion, Permissions};
    let Some(pki) = Pki::new() else { return };
    let leaf = pki.leaf("rsa", None);
    let ks = store(&pki, &leaf);
    let mut doc = lopdf::Document::load_mem(&blank_pdf(1, false)).unwrap();
    // An empty user password: the file opens without a password but is still encrypted.
    let state = EncryptionState::try_from(EncryptionVersion::V2 {
        document: &doc,
        owner_password: "owner",
        user_password: "",
        key_length: 128,
        permissions: Permissions::PRINTABLE,
    })
    .unwrap();
    doc.encrypt(&state).unwrap();
    let mut bytes = Vec::new();
    doc.save_to(&mut bytes).unwrap();
    let err = sign(&bytes, &ks, "rsa").unwrap_err();
    assert!(
        matches!(&err, Error::Refused(m) if m.contains("encrypted")),
        "{err}"
    );

    // One that needs a password is refused as password protected.
    let mut doc = lopdf::Document::load_mem(&blank_pdf(1, false)).unwrap();
    let state = EncryptionState::try_from(EncryptionVersion::V2 {
        document: &doc,
        owner_password: "owner",
        user_password: "user",
        key_length: 128,
        permissions: Permissions::PRINTABLE,
    })
    .unwrap();
    doc.encrypt(&state).unwrap();
    let mut bytes = Vec::new();
    doc.save_to(&mut bytes).unwrap();
    let err = sign(&bytes, &ks, "rsa").unwrap_err();
    assert_eq!(err.code(), Some(ErrorCode::PDF_PASSWORD_REQUIRED), "{err}");
}

#[test]
fn certified_pdfs_are_refused_only_when_they_forbid_changes() {
    let Some(pki) = Pki::new() else { return };
    let leaf = pki.leaf("rsa", None);
    let ks = store(&pki, &leaf);
    let err = sign(&certified_pdf(1), &ks, "rsa").unwrap_err();
    assert_eq!(err.code(), Some(ErrorCode::PDF_CERTIFIED), "{err}");
    // Levels 2 and 3 allow further signatures.
    for level in [2, 3] {
        assert!(sign(&certified_pdf(level), &ks, "rsa").is_ok(), "P={level}");
    }
}

#[test]
fn unreadable_inputs_are_refused() {
    let Some(pki) = Pki::new() else { return };
    let leaf = pki.leaf("rsa", None);
    let ks = store(&pki, &leaf);
    for bytes in [
        b"not a pdf".to_vec(),
        Vec::new(),
        b"%PDF-1.4\ngarbage".to_vec(),
        blank_pdf(1, false)[..80].to_vec(),
    ] {
        let err = sign(&bytes, &ks, "rsa").unwrap_err();
        assert!(matches!(err, Error::InvalidPdf(_)), "{err}");
    }
    let err = sign(&blank_pdf(0, false), &ks, "rsa").unwrap_err();
    assert!(
        matches!(&err, Error::InvalidPdf(m) if m.contains("no pages")),
        "{err}"
    );
}

#[test]
fn keystore_problems_surface_and_write_nothing() {
    let Some(pki) = Pki::new() else { return };
    let leaf = pki.leaf("rsa", None);
    let ks = store(&pki, &leaf);
    let err = sign(&blank_pdf(1, false), &ks, "nobody").unwrap_err();
    assert!(
        matches!(err, Error::Keystore(KeystoreError::UnknownAlias(_))),
        "{err}"
    );
}

#[test]
fn a_cms_that_does_not_fit_is_an_error() {
    let Some(pki) = Pki::new() else { return };
    let leaf = pki.leaf("rsa", None);
    let ks = store(&pki, &leaf);
    let tiny = SigningParams { reserved_size: 100 };
    let err = sign_pdf(blank_pdf(1, false), &ks, "rsa", &clock(), &NoPrompt, &tiny).unwrap_err();
    assert!(
        matches!(err, Error::SignatureTooLarge { reserved: 100, .. }),
        "{err}"
    );
}

#[test]
fn names_outside_ascii_are_written_as_utf16() {
    let Some(pki) = Pki::new() else { return };
    let leaf = pki.leaf("María Núñez", None);
    let out = sign(&blank_pdf(1, false), &store(&pki, &leaf), "María Núñez").unwrap();
    let pdf = certsign_pdf::PdfDocument::open(out, None).unwrap();
    let id = pdf.signatures()[0].value.as_ref().unwrap().id.unwrap();
    let name = pdf
        .document()
        .get_dictionary(id)
        .unwrap()
        .get(b"Name")
        .unwrap()
        .as_str()
        .unwrap()
        .to_vec();
    let expected: Vec<u8> = [0xFE, 0xFF]
        .into_iter()
        .chain("María Núñez".encode_utf16().flat_map(u16::to_be_bytes))
        .collect();
    assert_eq!(name, expected);
}

#[test]
fn the_signature_is_valid_for_other_tools() {
    let Some(pki) = Pki::new() else { return };
    if !common::pyhanko_available() {
        return;
    }
    for (name, curve) in [
        ("rsa", None),
        ("p256", Some("P-256")),
        ("p384", Some("P-384")),
    ] {
        let leaf = pki.leaf(name, curve);
        let out = sign(&blank_pdf(1, false), &store(&pki, &leaf), name).unwrap();
        let sigs = common::pyhanko_validate(pki.path(), &out);
        assert_eq!(sigs.len(), 1, "{name}");
        assert_eq!(sigs[0].field, "Signature1");
        assert!(
            sigs[0].intact && sigs[0].valid && sigs[0].entire_file,
            "{name}: {:?}",
            sigs[0]
        );
    }
}

#[test]
fn a_third_party_signature_stays_valid_and_a_chain_of_three_validates() {
    let Some(pki) = Pki::new() else { return };
    if !common::pyhanko_available() {
        return;
    }
    let third = pki.leaf("third", None);
    let a = pki.leaf("alice", None);
    let b = pki.leaf("bob", Some("P-256"));
    let p12 = pki.p12(&third, "tp", &[]);
    let signed_by_pyhanko =
        common::pyhanko_sign(pki.path(), &blank_pdf(1, false), &p12, "tp", "ThirdParty");
    assert_eq!(
        common::pyhanko_validate(pki.path(), &signed_by_pyhanko).len(),
        1
    );

    let two = sign(&signed_by_pyhanko, &store(&pki, &a), "alice").unwrap();
    let three = sign(&two, &store(&pki, &b), "bob").unwrap();
    let sigs = common::pyhanko_validate(pki.path(), &three);
    let names: Vec<&str> = sigs.iter().map(|s| s.field.as_str()).collect();
    assert_eq!(
        names,
        ["ThirdParty", "Signature1", "Signature2"],
        "{sigs:?}"
    );
    for s in &sigs {
        assert!(s.intact && s.valid, "{s:?}");
    }
    assert!(
        sigs[2].entire_file,
        "the last signature covers the whole file"
    );
    // The input is untouched at each step.
    assert_eq!(two[..signed_by_pyhanko.len()], signed_by_pyhanko[..]);
    assert_eq!(three[..two.len()], two[..]);
}

#[test]
fn signing_again_works_over_xref_streams_too() {
    let Some(pki) = Pki::new() else { return };
    let a = pki.leaf("alice", None);
    let b = pki.leaf("bob", Some("P-384"));
    let one = sign(&blank_pdf(2, true), &store(&pki, &a), "alice").unwrap();
    let two = sign(&one, &store(&pki, &b), "bob").unwrap();
    let pdf = certsign_pdf::PdfDocument::open(two.clone(), None).unwrap();
    assert_eq!(pdf.revisions().len(), 3);
    assert!(
        pdf.revisions().iter().all(|r| r.xref_stream),
        "every update is an xref stream"
    );
    let (first, second) = (parse(&two, 0), parse(&two, 1));
    assert!(verify_detached(&first.cms, &first.covered).is_ok());
    assert!(verify_detached(&second.cms, &second.covered).is_ok());
    if common::pyhanko_available() {
        let sigs = common::pyhanko_validate(pki.path(), &two);
        assert_eq!(sigs.len(), 2);
        assert!(sigs.iter().all(|s| s.intact && s.valid), "{sigs:?}");
    }
}
