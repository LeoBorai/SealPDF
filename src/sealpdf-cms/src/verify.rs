//! Verification of detached CMS signatures as found in PDFs.

use crate::{oids, pades::hash};
use cms::{
    cert::CertificateChoices,
    content_info::ContentInfo,
    signed_data::{SignedData, SignerIdentifier, SignerInfo},
};
use const_oid::ObjectIdentifier;
use der::{Any, Decode, Encode, Sequence, asn1::UintRef};
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use rsa::{BigUint, Pkcs1v15Sign, RsaPublicKey};
use sealpdf_core::{DigestAlg, Error, KeyType, ValidityError};
use std::time::SystemTime;
use x509_cert::{Certificate, ext::pkix::SubjectKeyIdentifier};

/// Why a signature did not verify. `kind` is a stable identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyError {
    pub kind: ValidityError,
    pub detail: String,
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.kind.id(), self.detail)
    }
}

impl std::error::Error for VerifyError {}

impl From<VerifyError> for Error {
    fn from(e: VerifyError) -> Self {
        Error::Validity(e.kind)
    }
}

fn fail(kind: ValidityError, detail: impl Into<String>) -> VerifyError {
    VerifyError {
        kind,
        detail: detail.into(),
    }
}

fn corrupt(detail: impl Into<String>) -> VerifyError {
    fail(ValidityError::CorruptedSign, detail)
}

/// A signature that passed every check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSignature {
    /// DER of the signer certificate.
    pub signer: Vec<u8>,
    pub digest: DigestAlg,
    pub key: KeyType,
    /// DER of every certificate embedded in the CMS, in the order found.
    pub certificates: Vec<Vec<u8>>,
    /// Common name of the signer certificate's subject, when it has a readable one.
    pub signer_cn: Option<String>,
    /// Start of the signer certificate's validity period.
    pub not_before: SystemTime,
    /// End of the signer certificate's validity period.
    pub not_after: SystemTime,
    /// The signer info carries a signature timestamp token (an unsigned attribute).
    pub has_signature_timestamp: bool,
}

const RSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const RSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
const RSA_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");
const EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const P384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");

/// The digests a signature may use. SHA-1 and MD5 are refused.
fn digest_alg(oid: &ObjectIdentifier) -> Result<DigestAlg, VerifyError> {
    if *oid == oids::SHA256 {
        Ok(DigestAlg::Sha256)
    } else if *oid == oids::SHA384 {
        Ok(DigestAlg::Sha384)
    } else if *oid == oids::SHA512 {
        Ok(DigestAlg::Sha512)
    } else {
        Err(fail(
            ValidityError::AlgorithmNotSupported,
            format!("digest algorithm {oid} is not allowed"),
        ))
    }
}

/// The signature algorithms allowed, with the digest they imply (`None` for plain `rsaEncryption`).
fn signature_alg(oid: &ObjectIdentifier) -> Result<(KeyType, Option<DigestAlg>), VerifyError> {
    Ok(if *oid == oids::RSA_ENCRYPTION {
        (KeyType::Rsa, None)
    } else if *oid == RSA_SHA256 {
        (KeyType::Rsa, Some(DigestAlg::Sha256))
    } else if *oid == RSA_SHA384 {
        (KeyType::Rsa, Some(DigestAlg::Sha384))
    } else if *oid == RSA_SHA512 {
        (KeyType::Rsa, Some(DigestAlg::Sha512))
    } else if *oid == oids::ECDSA_SHA256 {
        (KeyType::Ecdsa, Some(DigestAlg::Sha256))
    } else if *oid == oids::ECDSA_SHA384 {
        (KeyType::Ecdsa, Some(DigestAlg::Sha384))
    } else if *oid == oids::ECDSA_SHA512 {
        (KeyType::Ecdsa, Some(DigestAlg::Sha512))
    } else {
        return Err(fail(
            ValidityError::AlgorithmNotSupported,
            format!("signature algorithm {oid} is not allowed"),
        ));
    })
}

#[derive(Sequence)]
struct RsaPublicKeyDer<'a> {
    modulus: UintRef<'a>,
    public_exponent: UintRef<'a>,
}

/// DER `DigestInfo` header that precedes the hash in PKCS#1 v1.5 signatures.
fn pkcs1_prefix(d: DigestAlg) -> Vec<u8> {
    let (oid_last, len) = match d {
        DigestAlg::Sha256 => (0x01, 0x20),
        DigestAlg::Sha384 => (0x02, 0x30),
        DigestAlg::Sha512 => (0x03, 0x40),
    };
    let total = 0x11 + len;
    let mut p = vec![
        0x30, total, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
    ];
    p.extend_from_slice(&[oid_last, 0x05, 0x00, 0x04, len]);
    p
}

/// Verifies the CMS `SignedData` in `cms_der` over `content`, the bytes of a PDF `/ByteRange`.
///
/// The CMS must be detached with exactly one `SignerInfo`, signed attributes that carry
/// `contentType` and `messageDigest`, a digest of SHA-256, SHA-384 or SHA-512, and an RSA
/// (PKCS#1 v1.5) or ECDSA (P-256, P-384) signature by a certificate embedded in the CMS.
/// Trailing bytes after the CMS, such as the zero padding of `/Contents`, are ignored.
///
/// Errors carry these identifiers: `CORRUPTED_SIGN` for a CMS that cannot be read,
/// `NO_MATCH_DATA` when `content` is not what was signed or the signature value does not verify,
/// `NO_SIGN` without a signer, `CERTIFICATE_PROBLEM` without the signer's certificate, and
/// `ALGORITHM_NOT_SUPPORTED` outside the allow-list.
pub fn verify_detached(cms_der: &[u8], content: &[u8]) -> Result<VerifiedSignature, VerifyError> {
    let signed = parse_signed_data(cms_der)?;
    if signed.encap_content_info.econtent.is_some() {
        return Err(corrupt(
            "the CMS embeds its content; PAdES signatures are detached",
        ));
    }

    let mut infos = signed.signer_infos.0.iter();
    let Some(signer_info) = infos.next() else {
        return Err(fail(ValidityError::NoSign, "the CMS has no SignerInfo"));
    };
    if infos.next().is_some() {
        return Err(corrupt("the CMS has more than one SignerInfo"));
    }

    let digest = digest_alg(&signer_info.digest_alg.oid)?;
    let (key, implied_digest) = signature_alg(&signer_info.signature_algorithm.oid)?;
    if implied_digest.is_some_and(|d| d != digest) {
        return Err(corrupt("signature algorithm and digest algorithm disagree"));
    }

    let certificates: Vec<Certificate> = signed
        .certificates
        .iter()
        .flat_map(|set| set.0.iter())
        .filter_map(|c| match c {
            CertificateChoices::Certificate(c) => Some(c.clone()),
            _ => None,
        })
        .collect();
    let signer = find_signer(signer_info, &certificates)?;

    let attrs = signer_info
        .signed_attrs
        .as_ref()
        .ok_or_else(|| corrupt("the SignerInfo has no signed attributes"))?;
    let single = |oid: ObjectIdentifier| -> Result<Any, VerifyError> {
        let mut found = attrs.iter().filter(|a| a.oid == oid);
        let attr = found
            .next()
            .ok_or_else(|| corrupt(format!("signed attribute {oid} is missing")))?;
        if found.next().is_some() || attr.values.len() != 1 {
            return Err(corrupt(format!(
                "signed attribute {oid} must appear once with one value"
            )));
        }
        Ok(attr.values.iter().next().expect("one value").clone())
    };
    let content_type: ObjectIdentifier = single(oids::ID_CONTENT_TYPE)?
        .decode_as()
        .map_err(|e| corrupt(format!("contentType attribute: {e}")))?;
    if content_type != oids::ID_DATA {
        return Err(corrupt(format!(
            "contentType attribute is {content_type}, not id-data"
        )));
    }
    let message_digest: der::asn1::OctetString = single(oids::ID_MESSAGE_DIGEST)?
        .decode_as()
        .map_err(|e| corrupt(format!("messageDigest attribute: {e}")))?;
    if message_digest.as_bytes() != hash(digest, content).as_slice() {
        return Err(fail(
            ValidityError::NoMatchData,
            "the digest in the signature is not the digest of the signed bytes",
        ));
    }

    // The signature covers the attributes encoded as a SET OF.
    let signed_bytes = attrs
        .to_der()
        .map_err(|e| corrupt(format!("signed attributes: {e}")))?;
    let prehash = hash(digest, &signed_bytes);
    verify_signature(
        &signer,
        key,
        digest,
        &prehash,
        signer_info.signature.as_bytes(),
    )?;

    let validity = signer.tbs_certificate().validity();
    let has_signature_timestamp = signer_info.unsigned_attrs.as_ref().is_some_and(|attrs| {
        attrs
            .iter()
            .any(|a| a.oid == oids::ID_AA_SIGNATURE_TIME_STAMP_TOKEN)
    });

    Ok(VerifiedSignature {
        signer_cn: common_name(&signer),
        not_before: validity.not_before.to_system_time(),
        not_after: validity.not_after.to_system_time(),
        has_signature_timestamp,
        signer: signer.to_der().map_err(|e| corrupt(e.to_string()))?,
        digest,
        key,
        certificates: certificates
            .iter()
            .map(|c| c.to_der().map_err(|e| corrupt(e.to_string())))
            .collect::<Result<_, _>>()?,
    })
}

fn parse_signed_data(cms_der: &[u8]) -> Result<SignedData, VerifyError> {
    let info = ContentInfo::from_der(trim_padding(cms_der)?)
        .map_err(|e| corrupt(format!("not a CMS ContentInfo: {e}")))?;
    if info.content_type != oids::ID_SIGNED_DATA {
        return Err(corrupt(format!(
            "content type {} is not signedData",
            info.content_type
        )));
    }
    info.content
        .decode_as()
        .map_err(|e| corrupt(format!("not a SignedData: {e}")))
}

/// The digest algorithm of the first signer of a CMS `SignedData`, which may embed its content.
///
/// Used for document timestamps, whose token is not detached and so cannot go through
/// [`verify_detached`]. Fails with `ALGORITHM_NOT_SUPPORTED` outside the allow-list, `NO_SIGN`
/// without a signer and `CORRUPTED_SIGN` for a CMS that cannot be read.
pub fn digest_algorithm(cms_der: &[u8]) -> Result<DigestAlg, VerifyError> {
    let signed = parse_signed_data(cms_der)?;
    let signer = signed
        .signer_infos
        .0
        .iter()
        .next()
        .ok_or_else(|| fail(ValidityError::NoSign, "the CMS has no SignerInfo"))?;
    digest_alg(&signer.digest_alg.oid)
}

/// The subject's common name.
fn common_name(cert: &Certificate) -> Option<String> {
    cert.tbs_certificate()
        .subject()
        .iter()
        .find(|a| a.oid == oids::ID_AT_COMMON_NAME)
        .and_then(|a| directory_string(&a.value))
}

fn directory_string(value: &Any) -> Option<String> {
    use der::{Tag, Tagged};
    let bytes = value.value();
    match value.tag() {
        Tag::Utf8String | Tag::PrintableString | Tag::Ia5String => {
            std::str::from_utf8(bytes).ok().map(str::to_owned)
        }
        // TeletexString is treated as Latin-1, which is how it is used in practice.
        Tag::TeletexString => Some(bytes.iter().map(|b| char::from(*b)).collect()),
        Tag::BmpString => {
            let units: Vec<u16> = bytes
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_be_bytes(*c))
                .collect();
            String::from_utf16(&units).ok()
        }
        _ => None,
    }
}

/// Cuts a CMS followed by padding (the unused part of `/Contents`) down to its own length.
fn trim_padding(data: &[u8]) -> Result<&[u8], VerifyError> {
    if data.len() < 2 || data[0] != 0x30 {
        return Err(corrupt("not a DER SEQUENCE"));
    }
    let (header, len) = if data[1] < 0x80 {
        (2, usize::from(data[1]))
    } else {
        let n = usize::from(data[1] & 0x7F);
        if n == 0 || n > 4 || data.len() < 2 + n {
            return Err(corrupt("unsupported length encoding"));
        }
        (
            2 + n,
            data[2..2 + n]
                .iter()
                .fold(0usize, |acc, b| (acc << 8) | usize::from(*b)),
        )
    };
    data.get(..header + len)
        .ok_or_else(|| corrupt("the CMS is truncated"))
}

fn find_signer(info: &SignerInfo, certs: &[Certificate]) -> Result<Certificate, VerifyError> {
    let found = certs.iter().find(|c| match &info.sid {
        SignerIdentifier::IssuerAndSerialNumber(ias) => {
            c.tbs_certificate().issuer() == &ias.issuer
                && c.tbs_certificate().serial_number() == &ias.serial_number
        }
        SignerIdentifier::SubjectKeyIdentifier(ski) => c
            .tbs_certificate()
            .get_extension::<SubjectKeyIdentifier>()
            .ok()
            .flatten()
            .is_some_and(|(_, ext)| ext.0.as_bytes() == ski.0.as_bytes()),
    });
    found.cloned().ok_or_else(|| {
        fail(
            ValidityError::CertificateProblem,
            "the signer's certificate is not in the CMS",
        )
    })
}

fn verify_signature(
    signer: &Certificate,
    key: KeyType,
    digest: DigestAlg,
    prehash: &[u8],
    signature: &[u8],
) -> Result<(), VerifyError> {
    let spki = &signer.tbs_certificate().subject_public_key_info();
    let key_bytes = spki
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| corrupt("signer public key is not a whole number of bytes"))?;
    let bad = || {
        fail(
            ValidityError::NoMatchData,
            "the signature value does not verify",
        )
    };

    match key {
        KeyType::Rsa => {
            if spki.algorithm.oid != oids::RSA_ENCRYPTION {
                return Err(corrupt("an RSA signature needs an RSA certificate"));
            }
            let parsed = RsaPublicKeyDer::from_der(key_bytes)
                .map_err(|e| corrupt(format!("RSA public key: {e}")))?;
            let public = RsaPublicKey::new(
                BigUint::from_bytes_be(parsed.modulus.as_bytes()),
                BigUint::from_bytes_be(parsed.public_exponent.as_bytes()),
            )
            .map_err(|e| corrupt(format!("RSA public key: {e}")))?;
            let scheme = Pkcs1v15Sign {
                hash_len: Some(prehash.len()),
                prefix: pkcs1_prefix(digest).into_boxed_slice(),
            };
            public.verify(scheme, prehash, signature).map_err(|_| bad())
        }
        KeyType::Ecdsa => {
            if spki.algorithm.oid != EC_PUBLIC_KEY {
                return Err(corrupt("an ECDSA signature needs an EC certificate"));
            }
            let curve: ObjectIdentifier = spki
                .algorithm
                .parameters
                .as_ref()
                .ok_or_else(|| corrupt("EC key without a curve"))?
                .decode_as()
                .map_err(|_| {
                    fail(
                        ValidityError::AlgorithmNotSupported,
                        "EC key with explicit curve parameters",
                    )
                })?;
            if curve == P256 {
                let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(key_bytes)
                    .map_err(|_| corrupt("invalid P-256 public key"))?;
                let sig = p256::ecdsa::Signature::from_der(signature).map_err(|_| bad())?;
                key.verify_prehash(prehash, &sig).map_err(|_| bad())
            } else if curve == P384 {
                let key = p384::ecdsa::VerifyingKey::from_sec1_bytes(key_bytes)
                    .map_err(|_| corrupt("invalid P-384 public key"))?;
                let sig = p384::ecdsa::Signature::from_der(signature).map_err(|_| bad())?;
                key.verify_prehash(prehash, &sig).map_err(|_| bad())
            } else {
                Err(fail(
                    ValidityError::AlgorithmNotSupported,
                    format!("elliptic curve {curve} is not allowed"),
                ))
            }
        }
    }
}
