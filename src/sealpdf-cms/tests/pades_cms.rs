mod common;

use cms::{
    cert::CertificateChoices,
    content_info::{CmsVersion, ContentInfo},
    signed_data::{SignedData, SignerIdentifier},
};
use common::{Leaf, Pki};
use const_oid::ObjectIdentifier;
use der::{Decode, Encode};
use sealpdf_cms::{PadesCms, PadesCmsOptions};
use sealpdf_core::{DigestAlg, KeyType, SigAlg};
use sha2::{Digest, Sha256, Sha384};
use x509_cert::Certificate;

const ID_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
const CONTENT_TYPE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
const MESSAGE_DIGEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
const SIGNING_TIME: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.5");
const SCV2: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.47");

fn alg(digest: DigestAlg, key: KeyType) -> SigAlg {
    SigAlg::new(digest, key)
}

fn openssl_digest(d: DigestAlg) -> &'static str {
    match d {
        DigestAlg::Sha256 => "sha256",
        DigestAlg::Sha384 => "sha384",
        DigestAlg::Sha512 => "sha512",
    }
}

/// Signs `data` end to end: attributes, an OpenSSL signature over them, assembly.
fn build(
    pki: &Pki,
    leaf: &Leaf,
    chain: &[Vec<u8>],
    a: SigAlg,
    opts: PadesCmsOptions,
    data: &[u8],
) -> Vec<u8> {
    let cms = PadesCms::new(a, chain, opts).unwrap();
    let attrs = cms.signed_attributes(&cms.digest(data)).unwrap();
    let sig = pki.sign(leaf, openssl_digest(a.digest), &attrs.to_sign().unwrap());
    cms.assemble(&attrs, &sig).unwrap()
}

fn decode(der: &[u8]) -> SignedData {
    let info = ContentInfo::from_der(der).unwrap();
    assert_eq!(info.content_type.to_string(), "1.2.840.113549.1.7.2");
    info.content.decode_as::<SignedData>().unwrap()
}

#[test]
fn rsa_and_ecdsa_signatures_verify_with_openssl() {
    let Some(pki) = Pki::new() else { return };
    let rsa = pki.leaf("rsa-signer", false, true);
    let ec = pki.leaf("ec-signer", true, true);
    let data = b"the signed byte range of a PDF";
    let cases = [
        (&rsa, KeyType::Rsa, DigestAlg::Sha256),
        (&rsa, KeyType::Rsa, DigestAlg::Sha384),
        (&rsa, KeyType::Rsa, DigestAlg::Sha512),
        (&ec, KeyType::Ecdsa, DigestAlg::Sha256),
        (&ec, KeyType::Ecdsa, DigestAlg::Sha384),
        (&ec, KeyType::Ecdsa, DigestAlg::Sha512),
    ];
    for (leaf, key, digest) in cases {
        let a = alg(digest, key);
        let der = build(
            &pki,
            leaf,
            std::slice::from_ref(&leaf.cert_der),
            a,
            PadesCmsOptions::default(),
            data,
        );
        assert!(pki.verify(&der, data), "{a}");
        assert!(
            !pki.verify(&der, b"other data"),
            "{a}: a different payload must not verify"
        );
    }
}

#[test]
fn structure_matches_pades_mode() {
    let Some(pki) = Pki::new() else { return };
    let leaf = pki.leaf("signer", false, true);
    let a = alg(DigestAlg::Sha512, KeyType::Rsa);
    let data = b"payload";
    let der = build(
        &pki,
        &leaf,
        std::slice::from_ref(&leaf.cert_der),
        a,
        PadesCmsOptions::default(),
        data,
    );
    let signed = decode(&der);

    // Detached, version 1.
    assert_eq!(signed.version, CmsVersion::V1);
    assert_eq!(signed.encap_content_info.econtent_type, ID_DATA);
    assert!(
        signed.encap_content_info.econtent.is_none(),
        "no embedded content"
    );
    assert_eq!(signed.digest_algorithms.len(), 1);
    assert_eq!(
        signed
            .digest_algorithms
            .iter()
            .next()
            .unwrap()
            .oid
            .to_string(),
        "2.16.840.1.101.3.4.2.3"
    );

    let infos: Vec<_> = signed.signer_infos.0.iter().collect();
    assert_eq!(infos.len(), 1, "exactly one SignerInfo");
    let info = infos[0];
    assert_eq!(info.version, CmsVersion::V1);
    assert!(info.unsigned_attrs.is_none());
    assert_eq!(info.digest_alg.oid.to_string(), "2.16.840.1.101.3.4.2.3");
    assert_eq!(
        info.signature_algorithm.oid.to_string(),
        "1.2.840.113549.1.1.1",
        "rsaEncryption"
    );

    // Signer identified by issuer and serial.
    let cert = Certificate::from_der(&leaf.cert_der).unwrap();
    match &info.sid {
        SignerIdentifier::IssuerAndSerialNumber(ias) => {
            assert_eq!(&ias.issuer, cert.tbs_certificate().issuer());
            assert_eq!(&ias.serial_number, cert.tbs_certificate().serial_number());
        }
        other => panic!("expected IssuerAndSerialNumber, got {other:?}"),
    }

    // Exactly contentType, messageDigest and signingCertificateV2. No signingTime.
    let attrs = info.signed_attrs.as_ref().unwrap();
    let mut oids: Vec<_> = attrs.iter().map(|x| x.oid).collect();
    oids.sort();
    let mut expected = vec![CONTENT_TYPE, MESSAGE_DIGEST, SCV2];
    expected.sort();
    assert_eq!(oids, expected);
    assert!(!oids.contains(&SIGNING_TIME));

    let value = |oid| {
        attrs
            .iter()
            .find(|x| x.oid == oid)
            .unwrap()
            .values
            .iter()
            .next()
            .unwrap()
            .clone()
    };
    assert_eq!(
        value(CONTENT_TYPE).decode_as::<ObjectIdentifier>().unwrap(),
        ID_DATA
    );
    let digest = value(MESSAGE_DIGEST)
        .decode_as::<der::asn1::OctetString>()
        .unwrap();
    assert_eq!(digest.as_bytes(), sha2::Sha512::digest(data).as_slice());

    // DER SET OF: re-encoding the decoded set gives the very bytes that were signed.
    let cms = PadesCms::new(
        a,
        std::slice::from_ref(&leaf.cert_der),
        PadesCmsOptions::default(),
    )
    .unwrap();
    let rebuilt = cms
        .signed_attributes(&cms.digest(data))
        .unwrap()
        .to_sign()
        .unwrap();
    assert_eq!(attrs.to_der().unwrap(), rebuilt);
    assert_eq!(
        rebuilt[0], 0x31,
        "signed over a SET, not the [0] implicit tag"
    );
}

/// `SigningCertificateV2` contents, read from the DER by hand.
fn scv2(signed: &SignedData) -> Vec<der::Any> {
    let info = signed.signer_infos.0.iter().next().unwrap();
    let attr = info
        .signed_attrs
        .as_ref()
        .unwrap()
        .iter()
        .find(|x| x.oid == SCV2)
        .unwrap();
    let any = attr.values.iter().next().unwrap();
    any.decode_as().unwrap()
}

#[test]
fn signing_certificate_v2_hashes_the_signer_certificate() {
    let Some(pki) = Pki::new() else { return };
    let leaf = pki.leaf("signer", false, false);
    for (digest, expect_alg) in [(DigestAlg::Sha256, false), (DigestAlg::Sha384, true)] {
        let der = build(
            &pki,
            &leaf,
            std::slice::from_ref(&leaf.cert_der),
            alg(digest, KeyType::Rsa),
            PadesCmsOptions::default(),
            b"x",
        );
        let signed = decode(&der);
        let parts = scv2(&signed);
        let certs = parts.first().unwrap();
        let ids: Vec<der::Any> = certs.decode_as::<Vec<der::Any>>().unwrap();
        assert_eq!(ids.len(), 1);
        // ESSCertIDv2: [hashAlgorithm,] certHash, issuerSerial.
        let fields: Vec<der::Any> = ids[0].decode_as::<Vec<der::Any>>().unwrap();
        let hash_alg_present = fields.len() == 3;
        assert_eq!(
            hash_alg_present, expect_alg,
            "hashAlgorithm is left out only for SHA-256"
        );
        let hash_field = &fields[usize::from(hash_alg_present)];
        let want = match digest {
            DigestAlg::Sha256 => Sha256::digest(&leaf.cert_der).to_vec(),
            _ => Sha384::digest(&leaf.cert_der).to_vec(),
        };
        assert_eq!(
            hash_field
                .decode_as::<der::asn1::OctetString>()
                .unwrap()
                .as_bytes(),
            want.as_slice()
        );
    }
}

#[test]
fn certificate_policies_are_copied_unless_disabled() {
    let Some(pki) = Pki::new() else { return };
    let with = pki.leaf("with-policy", false, true);
    let without = pki.leaf("no-policy", false, false);
    let a = alg(DigestAlg::Sha256, KeyType::Rsa);
    let policy_count = |leaf: &Leaf, opts| {
        let signed = decode(&build(
            &pki,
            leaf,
            std::slice::from_ref(&leaf.cert_der),
            a,
            opts,
            b"x",
        ));
        scv2(&signed).len()
    };
    assert_eq!(
        policy_count(&with, PadesCmsOptions::default()),
        2,
        "certs + policies"
    );
    assert_eq!(
        policy_count(&without, PadesCmsOptions::default()),
        1,
        "certs only"
    );
    let off = PadesCmsOptions {
        include_cert_policies: false,
        ..Default::default()
    };
    assert_eq!(policy_count(&with, off), 1);
    // The policy OID made it through.
    let dump = pki.dump(&build(
        &pki,
        &with,
        std::slice::from_ref(&with.cert_der),
        a,
        PadesCmsOptions::default(),
        b"x",
    ));
    assert!(dump.contains("1.3.6.1.4.1.99999.1"), "{dump}");
}

#[test]
fn chain_options() {
    let Some(pki) = Pki::new() else { return };
    let leaf = pki.leaf("signer", false, true);
    let chain = vec![leaf.cert_der.clone(), pki.ca_der()];
    let a = alg(DigestAlg::Sha256, KeyType::Rsa);
    let count = |opts| {
        let signed = decode(&build(&pki, &leaf, &chain, a, opts, b"x"));
        let certs: Vec<_> = signed.certificates.unwrap().0.iter().cloned().collect();
        let first = match &certs[0] {
            CertificateChoices::Certificate(c) => c.to_der().unwrap(),
            other => panic!("{other:?}"),
        };
        (certs.len(), first)
    };
    let (n, _) = count(PadesCmsOptions::default());
    assert_eq!(n, 2, "whole chain");
    let (n, only) = count(PadesCmsOptions {
        include_chain: false,
        ..Default::default()
    });
    assert_eq!(n, 1, "signer only");
    assert_eq!(only, leaf.cert_der);
    // Signer chosen as the first of the chain, whatever the option.
}

#[test]
fn output_is_deterministic() {
    let Some(pki) = Pki::new() else { return };
    let leaf = pki.leaf("signer", false, true);
    let a = alg(DigestAlg::Sha256, KeyType::Rsa);
    let cms = PadesCms::new(
        a,
        std::slice::from_ref(&leaf.cert_der),
        PadesCmsOptions::default(),
    )
    .unwrap();
    let one = cms
        .signed_attributes(&cms.digest(b"x"))
        .unwrap()
        .to_sign()
        .unwrap();
    let two = cms
        .signed_attributes(&cms.digest(b"x"))
        .unwrap()
        .to_sign()
        .unwrap();
    assert_eq!(one, two);
    let other = cms
        .signed_attributes(&cms.digest(b"y"))
        .unwrap()
        .to_sign()
        .unwrap();
    assert_ne!(one, other);
}

#[test]
fn rejects_bad_input() {
    let Some(pki) = Pki::new() else { return };
    let leaf = pki.leaf("signer", false, true);
    let a = alg(DigestAlg::Sha256, KeyType::Rsa);
    assert!(
        PadesCms::new(a, &[], PadesCmsOptions::default()).is_err(),
        "empty chain"
    );
    assert!(
        PadesCms::new(
            a,
            &[b"not a certificate".to_vec()],
            PadesCmsOptions::default()
        )
        .is_err()
    );
    let cms = PadesCms::new(
        a,
        std::slice::from_ref(&leaf.cert_der),
        PadesCmsOptions::default(),
    )
    .unwrap();
    assert!(
        cms.signed_attributes(&[0; 20]).is_err(),
        "SHA-1 sized digest for SHA-256"
    );
    assert!(cms.signed_attributes(&[0; 64]).is_err());
}

#[test]
fn ecdsa_uses_the_ecdsa_signature_algorithm_oid() {
    let Some(pki) = Pki::new() else { return };
    let leaf = pki.leaf("ec", true, false);
    for (digest, oid) in [
        (DigestAlg::Sha256, "1.2.840.10045.4.3.2"),
        (DigestAlg::Sha384, "1.2.840.10045.4.3.3"),
        (DigestAlg::Sha512, "1.2.840.10045.4.3.4"),
    ] {
        let signed = decode(&build(
            &pki,
            &leaf,
            std::slice::from_ref(&leaf.cert_der),
            alg(digest, KeyType::Ecdsa),
            PadesCmsOptions::default(),
            b"x",
        ));
        let info = signed.signer_infos.0.iter().next().unwrap();
        assert_eq!(info.signature_algorithm.oid.to_string(), oid);
        assert!(
            info.signature_algorithm.parameters.is_none(),
            "RFC 5758: no parameters"
        );
    }
}

#[test]
fn openssl_dump_shows_no_signing_time() {
    let Some(pki) = Pki::new() else { return };
    let leaf = pki.leaf("signer", false, true);
    let a = alg(DigestAlg::Sha256, KeyType::Rsa);
    let dump = pki.dump(&build(
        &pki,
        &leaf,
        std::slice::from_ref(&leaf.cert_der),
        a,
        PadesCmsOptions::default(),
        b"x",
    ));
    assert!(dump.contains("contentType"), "{dump}");
    assert!(dump.contains("messageDigest"), "{dump}");
    assert!(
        dump.contains("signingCertificateV2") || dump.contains("1.2.840.113549.1.9.16.2.47"),
        "{dump}"
    );
    assert!(!dump.contains("signingTime"), "{dump}");
}
