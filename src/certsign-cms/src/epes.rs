//! Signed attributes of PAdES-EPES signatures: signature policy, commitment types, claimed roles.

use crate::{oids, pades::cms_err};
use base64::{Engine, engine::general_purpose::STANDARD};
use certsign_core::{DigestAlg, Error, Policy, Result};
use der::{
    Any, Sequence,
    asn1::{Ia5String, ObjectIdentifier, OctetString, Utf8StringRef},
};
use spki::AlgorithmIdentifierOwned;
use x509_cert::attr::Attribute;

/// ```text
/// SigPolicyQualifierInfo ::= SEQUENCE { sigPolicyQualifierId OID, sigQualifier ANY }
/// ```
/// Only the `id-spq-ets-uri` form, whose qualifier is an `IA5String`.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct SigPolicyQualifierInfo {
    id: ObjectIdentifier,
    uri: Ia5String,
}

/// ```text
/// OtherHashAlgAndValue ::= SEQUENCE { hashAlgorithm AlgorithmIdentifier, hashValue OCTET STRING }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct OtherHashAlgAndValue {
    hash_algorithm: AlgorithmIdentifierOwned,
    hash_value: OctetString,
}

/// ```text
/// SignaturePolicyId ::= SEQUENCE {
///     sigPolicyId OBJECT IDENTIFIER,
///     sigPolicyHash OtherHashAlgAndValue,
///     sigPolicyQualifiers SEQUENCE SIZE (1..MAX) OF SigPolicyQualifierInfo OPTIONAL }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct SignaturePolicyId {
    id: ObjectIdentifier,
    hash: OtherHashAlgAndValue,
    #[asn1(optional = "true")]
    qualifiers: Option<Vec<SigPolicyQualifierInfo>>,
}

/// As AutoFirma writes it: the qualifiers are a plain `SEQUENCE OF OBJECT IDENTIFIER`.
///
/// ```text
/// CommitmentTypeIndication ::= SEQUENCE { commitmentTypeId OID, qualifiers SEQUENCE OF OID OPTIONAL }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct CommitmentTypeIndication {
    id: ObjectIdentifier,
    #[asn1(optional = "true")]
    qualifiers: Option<Vec<ObjectIdentifier>>,
}

/// ```text
/// SignerAttribute ::= SEQUENCE OF CHOICE { claimedAttributes [0] ClaimedAttributes, ... }
/// ```
/// with a single `claimedAttributes` entry, explicitly tagged as in the ETSI module.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct SignerAttribute {
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT")]
    claimed: Vec<Attribute>,
}

fn opt_err(key: &str, value: &str, why: &str) -> Error {
    Error::Options(format!("{key} {value:?}: {why}"))
}

fn oid(key: &str, text: &str) -> Result<ObjectIdentifier> {
    ObjectIdentifier::new(text).map_err(|_| opt_err(key, text, "not a valid OID"))
}

fn attr(oid: ObjectIdentifier, value: Any) -> Result<Attribute> {
    Ok(Attribute {
        oid,
        values: der::asn1::SetOfVec::try_from(vec![value]).map_err(|e| cms_err("attribute", e))?,
    })
}

fn to_any<T: der::Encode>(value: &T, what: &str) -> Result<Any> {
    let der = value.to_der().map_err(|e| cms_err(what, e))?;
    <Any as der::Decode>::from_der(&der).map_err(|e| cms_err(what, e))
}

/// Digest names accepted for `policy.hash_algorithm`: `SHA-1`, `SHA-256`, ... with or without the dash.
fn policy_hash_oid(name: &str) -> Result<ObjectIdentifier> {
    let normalized: String = name
        .chars()
        .filter(|c| *c != '-')
        .collect::<String>()
        .to_ascii_uppercase();
    let text = match normalized.as_str() {
        "SHA1" => "1.3.14.3.2.26",
        "SHA224" => "2.16.840.1.101.3.4.2.4",
        "SHA256" => "2.16.840.1.101.3.4.2.1",
        "SHA384" => "2.16.840.1.101.3.4.2.2",
        "SHA512" => "2.16.840.1.101.3.4.2.3",
        _ => {
            return Err(opt_err(
                "policy.hash_algorithm",
                name,
                "expected SHA-1, SHA-224, SHA-256, SHA-384 or SHA-512",
            ));
        }
    };
    Ok(ObjectIdentifier::new_unwrap(text))
}

fn commitment_oid(identifier: &str) -> Result<ObjectIdentifier> {
    let text = match identifier.to_ascii_lowercase().as_str() {
        "proof-of-origin" => "1.2.840.113549.1.9.16.6.1",
        "proof-of-receipt" => "1.2.840.113549.1.9.16.6.2",
        "proof-of-delivery" => "1.2.840.113549.1.9.16.6.3",
        "proof-of-sender" => "1.2.840.113549.1.9.16.6.4",
        "proof-of-approval" => "1.2.840.113549.1.9.16.6.5",
        "proof-of-creation" => "1.2.840.113549.1.9.16.6.6",
        _ => return oid("policy.commitment_types.identifier", identifier),
    };
    Ok(ObjectIdentifier::new_unwrap(text))
}

/// The `signaturePolicyIdentifier` attribute for `policy.identifier`.
///
/// `signing_digest` is the hash algorithm of the signature, used when `policy.hash_algorithm`
/// is absent. With no `policy.hash`, the hash value is the single byte `0x00`, as AutoFirma writes it.
fn signature_policy(
    policy: &Policy,
    identifier: &str,
    signing_digest: DigestAlg,
) -> Result<Attribute> {
    let bare = identifier.trim().to_ascii_lowercase();
    let bare = bare.strip_prefix("urn:oid:").unwrap_or(&bare);
    let id = oid("policy.identifier", bare)?;

    let hash_oid = match &policy.hash_algorithm {
        Some(name) => policy_hash_oid(name)?,
        None => match signing_digest {
            DigestAlg::Sha256 => oids::SHA256,
            DigestAlg::Sha384 => oids::SHA384,
            DigestAlg::Sha512 => oids::SHA512,
        },
    };
    let hash_value = match &policy.hash {
        Some(b64) => STANDARD
            .decode(b64.trim())
            .map_err(|_| opt_err("policy.hash", b64, "not valid base64"))?,
        None => vec![0],
    };
    let qualifiers = match &policy.qualifier {
        Some(uri) => Some(vec![SigPolicyQualifierInfo {
            id: oids::ID_SPQ_ETS_URI,
            uri: Ia5String::new(uri)
                .map_err(|_| opt_err("policy.qualifier", uri, "must be ASCII"))?,
        }]),
        None => None,
    };
    let value = SignaturePolicyId {
        id,
        hash: OtherHashAlgAndValue {
            hash_algorithm: AlgorithmIdentifierOwned {
                oid: hash_oid,
                parameters: Some(Any::new(der::Tag::Null, Vec::new()).expect("NULL")),
            },
            hash_value: OctetString::new(hash_value).map_err(|e| cms_err("policy hash", e))?,
        },
        qualifiers,
    };
    attr(
        oids::ID_AA_ETS_SIG_POLICY_ID,
        to_any(&value, "signature policy")?,
    )
}

/// All EPES attributes configured in `policy`: the signature policy, one `commitmentTypeIndication`
/// attribute per commitment type, and `signerAttr` with the claimed roles.
///
/// Returns nothing for an empty policy.
pub(crate) fn attributes(policy: &Policy, signing_digest: DigestAlg) -> Result<Vec<Attribute>> {
    let mut out = Vec::new();
    if let Some(identifier) = &policy.identifier {
        out.push(signature_policy(policy, identifier, signing_digest)?);
    } else if policy.hash.is_some() || policy.hash_algorithm.is_some() || policy.qualifier.is_some()
    {
        return Err(Error::Options(
            "policy.hash, policy.hash_algorithm and policy.qualifier need policy.identifier".into(),
        ));
    }

    for commitment in &policy.commitment_types {
        let id = commitment_oid(&commitment.identifier)?;
        let qualifiers = if commitment.qualifiers.is_empty() {
            None
        } else {
            Some(
                commitment
                    .qualifiers
                    .iter()
                    .map(|q| oid("policy.commitment_types.qualifiers", q))
                    .collect::<Result<Vec<_>>>()?,
            )
        };
        let value = CommitmentTypeIndication { id, qualifiers };
        let attribute = attr(
            oids::ID_AA_ETS_COMMITMENT_TYPE,
            to_any(&value, "commitment type")?,
        )?;
        if !out.contains(&attribute) {
            out.push(attribute);
        }
    }

    let roles: Vec<Attribute> = policy
        .claimed_roles
        .iter()
        .filter(|r| !r.is_empty())
        .map(|role| {
            let text = Utf8StringRef::new(role).map_err(|e| cms_err("claimed role", e))?;
            attr(oids::ID_AT_ROLE, to_any(&text, "claimed role")?)
        })
        .collect::<Result<_>>()?;
    if !roles.is_empty() {
        let value = SignerAttribute { claimed: roles };
        out.push(attr(
            oids::ID_AA_ETS_SIGNER_ATTR,
            to_any(&value, "signer attributes")?,
        )?);
    }
    Ok(out)
}
