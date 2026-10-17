mod common;

use certsign_cms::{PadesCms, PadesCmsOptions, VerifyError, verify_detached};
use certsign_core::{DigestAlg, KeyType, SigAlg, ValidityError};
use cms::{cert::CertificateChoices, content_info::ContentInfo, signed_data::SignedData};
use common::{Leaf, Pki};
use const_oid::ObjectIdentifier;
use der::{Any, Decode, Encode, asn1::OctetString};

const DATA: &[u8] = b"the covered bytes of a PDF";

fn openssl_digest(d: DigestAlg) -> &'static str {
    match d {
        DigestAlg::Sha256 => "sha256",
        DigestAlg::Sha384 => "sha384",
        DigestAlg::Sha512 => "sha512",
    }
}

fn sign(pki: &Pki, leaf: &Leaf, key: KeyType, digest: DigestAlg, data: &[u8]) -> Vec<u8> {
    let cms = PadesCms::new(
        SigAlg::new(digest, key),
        std::slice::from_ref(&leaf.cert_der),
        PadesCmsOptions::default(),
    )
    .unwrap();
    let attrs = cms.signed_attributes(&cms.digest(data)).unwrap();
    let signature = pki.sign(leaf, openssl_digest(digest), &attrs.to_sign().unwrap());
    cms.assemble(&attrs, &signature).unwrap()
}

fn kind(r: Result<impl std::fmt::Debug, VerifyError>) -> ValidityError {
    r.unwrap_err().kind
}

/// Decodes, lets `edit` change the structure, and encodes again.
fn edit(der: &[u8], f: impl FnOnce(&mut SignedData)) -> Vec<u8> {
    let mut info = ContentInfo::from_der(der).unwrap();
    let mut signed: SignedData = info.content.decode_as().unwrap();
    f(&mut signed);
    info.content = Any::encode_from(&signed).unwrap();
    info.to_der().unwrap()
}

fn algorithms() -> Vec<(KeyType, DigestAlg)> {
    let mut v = Vec::new();
    for key in [KeyType::Rsa, KeyType::Ecdsa] {
        for d in [DigestAlg::Sha256, DigestAlg::Sha384, DigestAlg::Sha512] {
            v.push((key, d));
        }
    }
    v
}

#[test]
fn valid_signatures_verify() {
    let Some(pki) = Pki::new() else { return };
    let rsa = pki.leaf("rsa", false, true);
    let p256 = pki.ec_leaf("p256", "P-256");
    let p384 = pki.ec_leaf("p384", "P-384");
    for (key, digest) in algorithms() {
        let leaves: Vec<&Leaf> = match key {
            KeyType::Rsa => vec![&rsa],
            KeyType::Ecdsa => vec![&p256, &p384],
        };
        for leaf in leaves {
            let der = sign(&pki, leaf, key, digest, DATA);
            let verified =
                verify_detached(&der, DATA).unwrap_or_else(|e| panic!("{key:?} {digest:?}: {e}"));
            assert_eq!(verified.signer, leaf.cert_der);
            assert_eq!((verified.key, verified.digest), (key, digest));
            assert_eq!(verified.certificates, vec![leaf.cert_der.clone()]);
        }
    }
}

#[test]
fn trailing_zero_padding_is_ignored() {
    let Some(pki) = Pki::new() else { return };
    let leaf = pki.leaf("rsa", false, false);
    let mut der = sign(&pki, &leaf, KeyType::Rsa, DigestAlg::Sha256, DATA);
    der.extend_from_slice(&[0; 4000]);
    assert!(verify_detached(&der, DATA).is_ok());
}

#[test]
fn signatures_made_by_openssl_verify() {
    // A signature produced by an independent implementation, not by `PadesCms`.
    let Some(pki) = Pki::new() else { return };
    let leaf = pki.leaf("rsa", false, false);
    let d = pki.path();
    std::fs::write(d.join("data.bin"), DATA).unwrap();
    let ok = std::process::Command::new("openssl")
        .args([
            "cms", "-sign", "-binary", "-in", "data.bin", "-signer", "rsa.pem", "-inkey",
            "rsa.key", "-outform", "DER", "-out", "o.der", "-md", "sha256",
        ])
        .current_dir(d)
        .status()
        .unwrap()
        .success();
    assert!(ok);
    let der = std::fs::read(d.join("o.der")).unwrap();
    // OpenSSL adds signingTime and a smimeCapabilities attribute, which are fine.
    let verified = verify_detached(&der, DATA).unwrap();
    assert_eq!(verified.signer, leaf.cert_der);
    assert_eq!(
        kind(verify_detached(&der, b"other")),
        ValidityError::NoMatchData
    );
}

#[test]
fn tampered_content_does_not_match() {
    let Some(pki) = Pki::new() else { return };
    let rsa = pki.leaf("rsa", false, false);
    let ec = pki.leaf("ec", true, false);
    for (leaf, key) in [(&rsa, KeyType::Rsa), (&ec, KeyType::Ecdsa)] {
        let der = sign(&pki, leaf, key, DigestAlg::Sha256, DATA);
        let mut tampered = DATA.to_vec();
        tampered[3] ^= 1;
        assert_eq!(
            kind(verify_detached(&der, &tampered)),
            ValidityError::NoMatchData
        );
        assert_eq!(kind(verify_detached(&der, b"")), ValidityError::NoMatchData);
        assert_eq!(
            kind(verify_detached(&der, &DATA[1..])),
            ValidityError::NoMatchData
        );
    }
}

#[test]
fn tampered_signature_value_is_corrupted() {
    let Some(pki) = Pki::new() else { return };
    let rsa = pki.leaf("rsa", false, false);
    let ec = pki.leaf("ec", true, false);
    for (leaf, key) in [(&rsa, KeyType::Rsa), (&ec, KeyType::Ecdsa)] {
        let der = sign(&pki, leaf, key, DigestAlg::Sha256, DATA);
        let bad = edit(&der, |s| {
            let mut infos: Vec<_> = s.signer_infos.0.iter().cloned().collect();
            let mut sig = infos[0].signature.as_bytes().to_vec();
            let last = sig.len() - 1;
            sig[last] ^= 1;
            infos[0].signature = OctetString::new(sig).unwrap();
            s.signer_infos.0 = der::asn1::SetOfVec::try_from(infos).unwrap();
        });
        assert_eq!(
            kind(verify_detached(&bad, DATA)),
            ValidityError::CorruptedSign,
            "{key:?}"
        );
    }
}

#[test]
fn tampered_signed_attribute_is_corrupted() {
    // The messageDigest still matches, but another signed attribute changed: only the
    // signature check can notice.
    let Some(pki) = Pki::new() else { return };
    let leaf = pki.leaf("rsa", false, true);
    let der = sign(&pki, &leaf, KeyType::Rsa, DigestAlg::Sha256, DATA);
    let scv2 = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.47");
    let bad = edit(&der, |s| {
        let mut infos: Vec<_> = s.signer_infos.0.iter().cloned().collect();
        let mut attrs: Vec<_> = infos[0]
            .signed_attrs
            .take()
            .unwrap()
            .iter()
            .cloned()
            .collect();
        for a in &mut attrs {
            if a.oid == scv2 {
                let mut bytes = a.values.iter().next().unwrap().to_der().unwrap();
                let i = bytes.len() - 5;
                bytes[i] ^= 1; // inside the issuer serial
                a.values =
                    der::asn1::SetOfVec::try_from(vec![Any::from_der(&bytes).unwrap()]).unwrap();
            }
        }
        infos[0].signed_attrs = Some(der::asn1::SetOfVec::try_from(attrs).unwrap());
        s.signer_infos.0 = der::asn1::SetOfVec::try_from(infos).unwrap();
    });
    assert_eq!(
        kind(verify_detached(&bad, DATA)),
        ValidityError::CorruptedSign
    );
}

#[test]
fn wrong_certificate_does_not_verify() {
    let Some(pki) = Pki::new() else { return };
    let signer = pki.leaf("signer", false, false);
    let other = pki.leaf("other", false, false);
    let der = sign(&pki, &signer, KeyType::Rsa, DigestAlg::Sha256, DATA);
    // Same issuer and serial are not shared, so swap in the other certificate's key by
    // replacing the certificate and the identifier together.
    let other_cert = x509_cert::Certificate::from_der(&other.cert_der).unwrap();
    let bad = edit(&der, |s| {
        let mut infos: Vec<_> = s.signer_infos.0.iter().cloned().collect();
        infos[0].sid = cms::signed_data::SignerIdentifier::IssuerAndSerialNumber(
            cms::cert::IssuerAndSerialNumber {
                issuer: other_cert.tbs_certificate().issuer().clone(),
                serial_number: other_cert.tbs_certificate().serial_number().clone(),
            },
        );
        s.signer_infos.0 = der::asn1::SetOfVec::try_from(infos).unwrap();
        s.certificates = Some(cms::signed_data::CertificateSet(
            der::asn1::SetOfVec::try_from(vec![CertificateChoices::Certificate(
                other_cert.clone(),
            )])
            .unwrap(),
        ));
    });
    assert_eq!(
        kind(verify_detached(&bad, DATA)),
        ValidityError::CorruptedSign
    );
}

#[test]
fn corrupted_cms() {
    let Some(pki) = Pki::new() else { return };
    let leaf = pki.leaf("rsa", false, false);
    let der = sign(&pki, &leaf, KeyType::Rsa, DigestAlg::Sha256, DATA);
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty", vec![]),
        ("garbage", b"definitely not DER".to_vec()),
        ("truncated", der[..der.len() / 2].to_vec()),
        ("one byte", vec![0x30]),
        ("zeros", vec![0; 64]),
        ("bad length form", vec![0x30, 0x85, 1, 2, 3, 4, 5]),
        ("flipped header", {
            let mut d = der.clone();
            d[4] ^= 0xFF;
            d
        }),
    ];
    for (name, bytes) in cases {
        assert_eq!(
            kind(verify_detached(&bytes, DATA)),
            ValidityError::CorruptedSign,
            "{name}"
        );
    }
}

#[test]
fn not_signed_data() {
    // A ContentInfo of type id-data.
    let info = ContentInfo {
        content_type: ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1"),
        content: Any::encode_from(&OctetString::new(b"x".to_vec()).unwrap()).unwrap(),
    };
    assert_eq!(
        kind(verify_detached(&info.to_der().unwrap(), DATA)),
        ValidityError::CorruptedSign
    );
}

#[test]
fn structure_errors() {
    let Some(pki) = Pki::new() else { return };
    let leaf = pki.leaf("rsa", false, false);
    let der = sign(&pki, &leaf, KeyType::Rsa, DigestAlg::Sha256, DATA);

    let no_signer = edit(&der, |s| s.signer_infos.0 = der::asn1::SetOfVec::new());
    assert_eq!(
        kind(verify_detached(&no_signer, DATA)),
        ValidityError::NoSign
    );

    let embedded = edit(&der, |s| {
        s.encap_content_info.econtent =
            Some(Any::encode_from(&OctetString::new(DATA.to_vec()).unwrap()).unwrap());
    });
    assert_eq!(
        kind(verify_detached(&embedded, DATA)),
        ValidityError::CorruptedSign
    );

    let no_attrs = edit(&der, |s| {
        let mut infos: Vec<_> = s.signer_infos.0.iter().cloned().collect();
        infos[0].signed_attrs = None;
        s.signer_infos.0 = der::asn1::SetOfVec::try_from(infos).unwrap();
    });
    assert_eq!(
        kind(verify_detached(&no_attrs, DATA)),
        ValidityError::CorruptedSign
    );

    let no_certs = edit(&der, |s| s.certificates = None);
    assert_eq!(
        kind(verify_detached(&no_certs, DATA)),
        ValidityError::CertificateProblem
    );
}

#[test]
fn algorithm_allow_list() {
    let Some(pki) = Pki::new() else { return };
    let rsa = pki.leaf("rsa", false, false);
    let der = sign(&pki, &rsa, KeyType::Rsa, DigestAlg::Sha256, DATA);

    let with = |digest: Option<&str>, signature: Option<&str>| {
        edit(&der, |s| {
            let mut infos: Vec<_> = s.signer_infos.0.iter().cloned().collect();
            if let Some(d) = digest {
                infos[0].digest_alg.oid = ObjectIdentifier::new_unwrap(d);
            }
            if let Some(a) = signature {
                infos[0].signature_algorithm.oid = ObjectIdentifier::new_unwrap(a);
            }
            s.signer_infos.0 = der::asn1::SetOfVec::try_from(infos).unwrap();
        })
    };
    // SHA-1 and MD5 digests.
    for oid in ["1.3.14.3.2.26", "1.2.840.113549.2.5"] {
        assert_eq!(
            kind(verify_detached(&with(Some(oid), None), DATA)),
            ValidityError::AlgorithmNotSupported,
            "{oid}"
        );
    }
    // RSA-PSS, sha1WithRSA, and something unknown.
    for oid in ["1.2.840.113549.1.1.10", "1.2.840.113549.1.1.5", "1.2.3.4"] {
        assert_eq!(
            kind(verify_detached(&with(None, Some(oid)), DATA)),
            ValidityError::AlgorithmNotSupported,
            "{oid}"
        );
    }
    // A digest that contradicts the one the signature algorithm names.
    assert_eq!(
        kind(verify_detached(
            &with(None, Some("1.2.840.113549.1.1.12")),
            DATA
        )),
        ValidityError::CorruptedSign
    );
    // The named combination that matches is fine.
    assert!(verify_detached(&with(None, Some("1.2.840.113549.1.1.11")), DATA).is_ok());
    // An ECDSA algorithm on an RSA certificate.
    assert_eq!(
        kind(verify_detached(
            &with(None, Some("1.2.840.10045.4.3.2")),
            DATA
        )),
        ValidityError::CorruptedSign
    );
}

#[test]
fn unsupported_curve() {
    let Some(pki) = Pki::new() else { return };
    let p521 = pki.ec_leaf("p521", "P-521");
    let der = sign(&pki, &p521, KeyType::Ecdsa, DigestAlg::Sha512, DATA);
    assert_eq!(
        kind(verify_detached(&der, DATA)),
        ValidityError::AlgorithmNotSupported
    );
}

#[test]
fn error_text_names_the_identifier() {
    let err = verify_detached(b"x", DATA).unwrap_err();
    assert!(err.to_string().starts_with("CORRUPTED_SIGN"), "{err}");
    let core: certsign_core::Error = err.into();
    assert!(matches!(
        core,
        certsign_core::Error::Validity(ValidityError::CorruptedSign)
    ));
}
