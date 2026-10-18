mod common;

use certsign_cms::{PadesCms, PadesCmsOptions};
use certsign_core::{CommitmentType, DigestAlg, Error, KeyType, Policy, SigAlg};
use cms::{content_info::ContentInfo, signed_data::SignedData};
use common::{Leaf, Pki};
use const_oid::ObjectIdentifier;
use der::{Any, Decode, Encode, Tagged, asn1::OctetString};
use x509_cert::attr::Attribute;

const SIG_POLICY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.15");
const COMMITMENT: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.16");
const SIGNER_ATTR: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.18");
const ROLE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.72");

const AGE_POLICY: &str = "2.16.724.1.3.1.1.2.1.9";
const AGE_HASH: &str = "G7roucf600+f03r/o0bAOQ6WAs0=";
const AGE_URI: &str = "https://sede.060.gob.es/politica_de_firma_anexo_1.pdf";

fn sha256_rsa() -> SigAlg {
    SigAlg::new(DigestAlg::Sha256, KeyType::Rsa)
}

fn full_policy() -> Policy {
    Policy {
        identifier: Some(AGE_POLICY.into()),
        hash: Some(AGE_HASH.into()),
        hash_algorithm: Some("SHA-1".into()),
        qualifier: Some(AGE_URI.into()),
        ..Default::default()
    }
}

fn leaf() -> Option<(Pki, Leaf)> {
    let pki = Pki::new()?;
    let leaf = pki.leaf("signer", false, false);
    Some((pki, leaf))
}

fn attrs_for(leaf: &Leaf, alg: SigAlg, policy: &Policy) -> certsign_core::Result<Vec<Attribute>> {
    let cms = PadesCms::new(
        alg,
        std::slice::from_ref(&leaf.cert_der),
        PadesCmsOptions::default(),
    )?;
    let set = cms.signed_attributes_epes(&cms.digest(b"x"), policy)?;
    Ok(set.attributes().cloned().collect())
}

fn find(attrs: &[Attribute], oid: ObjectIdentifier) -> Vec<&Attribute> {
    attrs.iter().filter(|a| a.oid == oid).collect()
}

fn value_of(a: &Attribute) -> Any {
    a.values.iter().next().unwrap().clone()
}

fn children(any: &Any) -> Vec<Any> {
    any.decode_as::<Vec<Any>>().unwrap()
}

#[test]
fn signature_policy_identifier_structure() {
    let Some((_, leaf)) = leaf() else { return };
    let attrs = attrs_for(&leaf, sha256_rsa(), &full_policy()).unwrap();
    let found = find(&attrs, SIG_POLICY);
    assert_eq!(found.len(), 1);

    // SignaturePolicyId ::= SEQUENCE { id, SEQUENCE { AlgorithmIdentifier, OCTET STRING }, SEQUENCE OF qualifier }
    let parts = children(&value_of(found[0]));
    assert_eq!(parts.len(), 3);
    assert_eq!(
        parts[0]
            .decode_as::<ObjectIdentifier>()
            .unwrap()
            .to_string(),
        AGE_POLICY
    );

    let hash = children(&parts[1]);
    let alg = children(&hash[0]);
    assert_eq!(
        alg[0].decode_as::<ObjectIdentifier>().unwrap().to_string(),
        "1.3.14.3.2.26",
        "SHA-1"
    );
    assert_eq!(alg[1].tag(), der::Tag::Null);
    let value = hash[1].decode_as::<OctetString>().unwrap();
    assert_eq!(value.as_bytes().len(), 20);
    assert_eq!(value.as_bytes()[0], 0x1B);

    let qualifiers = children(&parts[2]);
    assert_eq!(qualifiers.len(), 1);
    let q = children(&qualifiers[0]);
    assert_eq!(
        q[0].decode_as::<ObjectIdentifier>().unwrap().to_string(),
        "1.2.840.113549.1.9.16.5.1"
    );
    assert_eq!(q[1].tag(), der::Tag::Ia5String);
    assert_eq!(q[1].value(), AGE_URI.as_bytes());
}

#[test]
fn urn_prefix_and_case_are_accepted() {
    let Some((_, leaf)) = leaf() else { return };
    let plain = attrs_for(&leaf, sha256_rsa(), &full_policy()).unwrap();
    let urn = Policy {
        identifier: Some(format!("URN:OID:{AGE_POLICY}")),
        ..full_policy()
    };
    assert_eq!(attrs_for(&leaf, sha256_rsa(), &urn).unwrap(), plain);
    let spaced = Policy {
        hash_algorithm: Some("sha1".into()),
        ..full_policy()
    };
    assert_eq!(attrs_for(&leaf, sha256_rsa(), &spaced).unwrap(), plain);
}

#[test]
fn hash_defaults() {
    let Some((_, leaf)) = leaf() else { return };
    // Only the identifier: hash algorithm follows the signature, hash value is a single zero byte.
    for (digest, oid) in [
        (DigestAlg::Sha256, "2.16.840.1.101.3.4.2.1"),
        (DigestAlg::Sha384, "2.16.840.1.101.3.4.2.2"),
        (DigestAlg::Sha512, "2.16.840.1.101.3.4.2.3"),
    ] {
        let policy = Policy {
            identifier: Some(AGE_POLICY.into()),
            ..Default::default()
        };
        let attrs = attrs_for(&leaf, SigAlg::new(digest, KeyType::Rsa), &policy).unwrap();
        let parts = children(&value_of(find(&attrs, SIG_POLICY)[0]));
        assert_eq!(parts.len(), 2, "no qualifier");
        let hash = children(&parts[1]);
        let alg = children(&hash[0]);
        assert_eq!(
            alg[0].decode_as::<ObjectIdentifier>().unwrap().to_string(),
            oid
        );
        assert_eq!(hash[1].decode_as::<OctetString>().unwrap().as_bytes(), &[0]);
    }
}

#[test]
fn policy_option_errors() {
    let Some((_, leaf)) = leaf() else { return };
    let bad = [
        Policy {
            identifier: Some("not-an-oid".into()),
            ..Default::default()
        },
        Policy {
            hash: Some("!!!".into()),
            ..full_policy()
        },
        Policy {
            hash_algorithm: Some("MD5".into()),
            ..full_policy()
        },
        Policy {
            qualifier: Some("https://exámple.test".into()),
            ..full_policy()
        },
        Policy {
            hash: Some(AGE_HASH.into()),
            ..Default::default()
        },
        Policy {
            qualifier: Some(AGE_URI.into()),
            ..Default::default()
        },
    ];
    for policy in bad {
        let err = attrs_for(&leaf, sha256_rsa(), &policy).unwrap_err();
        assert!(matches!(err, Error::Options(_)), "{policy:?}: {err}");
    }
}

fn commitment(identifier: &str, qualifiers: &[&str]) -> CommitmentType {
    CommitmentType {
        identifier: identifier.into(),
        qualifiers: qualifiers.iter().map(|s| s.to_string()).collect(),
    }
}

#[test]
fn commitment_type_indications() {
    let Some((_, leaf)) = leaf() else { return };
    let policy = Policy {
        commitment_types: vec![
            commitment("proof-of-origin", &[]),
            commitment("PROOF-OF-APPROVAL", &["1.2.3", "2.5.6"]),
            commitment("1.2.840.113549.1.9.16.6.6", &[]),
        ],
        ..Default::default()
    };
    let attrs = attrs_for(&leaf, sha256_rsa(), &policy).unwrap();
    let found = find(&attrs, COMMITMENT);
    assert_eq!(found.len(), 3, "one attribute per commitment type");

    let mut ids: Vec<(String, usize)> = found
        .iter()
        .map(|a| {
            let parts = children(&value_of(a));
            let id = parts[0]
                .decode_as::<ObjectIdentifier>()
                .unwrap()
                .to_string();
            (id, parts.len())
        })
        .collect();
    ids.sort();
    assert_eq!(
        ids,
        [
            ("1.2.840.113549.1.9.16.6.1".to_string(), 1),
            ("1.2.840.113549.1.9.16.6.5".to_string(), 2),
            ("1.2.840.113549.1.9.16.6.6".to_string(), 1),
        ]
    );
    // Qualifiers are a plain SEQUENCE OF OID, as other implementations write them.
    let approval = found
        .iter()
        .map(|a| children(&value_of(a)))
        .find(|p| p.len() == 2)
        .unwrap();
    let quals = approval[1].decode_as::<Vec<ObjectIdentifier>>().unwrap();
    assert_eq!(
        quals.iter().map(|o| o.to_string()).collect::<Vec<_>>(),
        ["1.2.3", "2.5.6"]
    );
}

#[test]
fn duplicate_commitment_types_collapse() {
    let Some((_, leaf)) = leaf() else { return };
    let policy = Policy {
        commitment_types: vec![
            commitment("proof-of-origin", &[]),
            commitment("proof-of-origin", &[]),
        ],
        ..Default::default()
    };
    assert_eq!(
        find(
            &attrs_for(&leaf, sha256_rsa(), &policy).unwrap(),
            COMMITMENT
        )
        .len(),
        1
    );
}

#[test]
fn commitment_type_errors() {
    let Some((_, leaf)) = leaf() else { return };
    for c in [
        commitment("proof-of-lunch", &[]),
        commitment("proof-of-origin", &["nope"]),
    ] {
        let policy = Policy {
            commitment_types: vec![c],
            ..Default::default()
        };
        let err = attrs_for(&leaf, sha256_rsa(), &policy).unwrap_err();
        assert!(matches!(err, Error::Options(_)), "{err}");
    }
}

#[test]
fn signer_claimed_roles() {
    let Some((_, leaf)) = leaf() else { return };
    let policy = Policy {
        claimed_roles: vec!["Director".into(), "".into(), "Árbol".into()],
        ..Default::default()
    };
    let attrs = attrs_for(&leaf, sha256_rsa(), &policy).unwrap();
    let found = find(&attrs, SIGNER_ATTR);
    assert_eq!(found.len(), 1);
    let value = value_of(found[0]);

    // SEQUENCE { [0] EXPLICIT SEQUENCE OF Attribute }
    let choice = children(&value);
    assert_eq!(choice.len(), 1);
    assert_eq!(
        choice[0].tag(),
        der::Tag::ContextSpecific {
            constructed: true,
            number: der::TagNumber(0)
        },
        "explicit [0]"
    );
    let claimed: Vec<Any> = Any::from_der(choice[0].value())
        .unwrap()
        .decode_as()
        .unwrap();
    assert_eq!(claimed.len(), 2, "empty roles are skipped");
    let roles: Vec<String> = claimed
        .iter()
        .map(|a| {
            let attribute = a.decode_as::<Attribute>().unwrap();
            assert_eq!(attribute.oid, ROLE);
            let v = attribute.values.iter().next().unwrap();
            assert_eq!(v.tag(), der::Tag::Utf8String);
            String::from_utf8(v.value().to_vec()).unwrap()
        })
        .collect();
    assert_eq!(roles, ["Director", "Árbol"]);

    let only_empty = Policy {
        claimed_roles: vec!["".into()],
        ..Default::default()
    };
    assert!(
        find(
            &attrs_for(&leaf, sha256_rsa(), &only_empty).unwrap(),
            SIGNER_ATTR
        )
        .is_empty()
    );
}

#[test]
fn empty_policy_adds_nothing() {
    let Some((_, leaf)) = leaf() else { return };
    let cms = PadesCms::new(
        sha256_rsa(),
        std::slice::from_ref(&leaf.cert_der),
        PadesCmsOptions::default(),
    )
    .unwrap();
    let digest = cms.digest(b"x");
    assert_eq!(
        cms.signed_attributes_epes(&digest, &Policy::default())
            .unwrap()
            .to_sign()
            .unwrap(),
        cms.signed_attributes(&digest).unwrap().to_sign().unwrap()
    );
}

fn everything() -> Policy {
    Policy {
        commitment_types: vec![
            commitment("proof-of-approval", &[]),
            commitment("proof-of-origin", &["1.2.3"]),
        ],
        claimed_roles: vec!["Director".into(), "Auditor".into()],
        ..full_policy()
    }
}

#[test]
fn epes_signatures_verify_and_show_in_openssl() {
    let Some(pki) = Pki::new() else { return };
    let rsa = pki.leaf("rsa", false, true);
    let ec = pki.leaf("ec", true, true);
    let data = b"covered bytes";
    for (leaf, key, digest, name) in [
        (&rsa, KeyType::Rsa, DigestAlg::Sha256, "sha256"),
        (&rsa, KeyType::Rsa, DigestAlg::Sha512, "sha512"),
        (&ec, KeyType::Ecdsa, DigestAlg::Sha384, "sha384"),
    ] {
        let alg = SigAlg::new(digest, key);
        let cms = PadesCms::new(
            alg,
            std::slice::from_ref(&leaf.cert_der),
            PadesCmsOptions::default(),
        )
        .unwrap();
        let attrs = cms
            .signed_attributes_epes(&cms.digest(data), &everything())
            .unwrap();
        let signature = pki.sign(leaf, name, &attrs.to_sign().unwrap());
        let der = cms.assemble(&attrs, &signature).unwrap();
        assert!(pki.verify(&der, data), "{alg}");

        let dump = pki.dump(&der);
        assert!(
            dump.contains(AGE_POLICY) || dump.contains("2.16.724.1.3.1.1.2.1.9"),
            "{dump}"
        );
        assert!(
            dump.contains("1.2.840.113549.1.9.16.2.15") || dump.contains("sigPolicyId"),
            "{dump}"
        );
        assert!(
            dump.contains("Director") && dump.contains("Auditor"),
            "{dump}"
        );
        assert!(
            dump.contains("1.2.840.113549.1.9.16.6.5") || dump.contains("proofOfApproval"),
            "{dump}"
        );

        // Attributes survive a decode/encode round trip byte for byte.
        let info = ContentInfo::from_der(&der)
            .unwrap()
            .content
            .decode_as::<SignedData>()
            .unwrap();
        let signed = info
            .signer_infos
            .0
            .iter()
            .next()
            .unwrap()
            .signed_attrs
            .clone()
            .unwrap();
        assert_eq!(signed.to_der().unwrap(), attrs.to_sign().unwrap());
        // Three base attributes, the policy, two commitment types and the roles.
        assert_eq!(signed.len(), 3 + 1 + 2 + 1);
    }
}
