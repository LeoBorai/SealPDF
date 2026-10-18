use crate::{
    ess::{EssCertIdV2, IssuerSerial, SigningCertificateV2},
    oids,
};
use certsign_core::{DigestAlg, Error, KeyType, Policy, Result, SigAlg};
use cms::{
    cert::{CertificateChoices, IssuerAndSerialNumber},
    content_info::{CmsVersion, ContentInfo},
    signed_data::{
        CertificateSet, EncapsulatedContentInfo, SignedData, SignerIdentifier, SignerInfo,
        SignerInfos,
    },
};
use const_oid::{AssociatedOid, ObjectIdentifier};
use der::{
    Any, Decode, Encode, Tag,
    asn1::{OctetString, SetOfVec},
};
use sha2::{Digest, Sha256, Sha384, Sha512};
use spki::AlgorithmIdentifierOwned;
use x509_cert::{
    Certificate,
    attr::Attribute,
    ext::pkix::{
        certpolicy::{CertificatePolicies, PolicyInformation},
        name::GeneralName,
    },
};

#[derive(Debug, Clone, Copy)]
pub struct PadesCmsOptions {
    /// Embed the whole chain given to [`PadesCms::new`]; otherwise only the signer certificate.
    pub include_chain: bool,
    /// Copy the signer certificate's policies into `SigningCertificateV2`, when it declares any.
    pub include_cert_policies: bool,
}

impl Default for PadesCmsOptions {
    fn default() -> Self {
        Self {
            include_chain: true,
            include_cert_policies: true,
        }
    }
}

pub(crate) fn cms_err(what: &str, e: impl std::fmt::Display) -> Error {
    Error::Other(format!("CMS: {what}: {e}"))
}

fn digest_oid(d: DigestAlg) -> ObjectIdentifier {
    match d {
        DigestAlg::Sha256 => oids::SHA256,
        DigestAlg::Sha384 => oids::SHA384,
        DigestAlg::Sha512 => oids::SHA512,
    }
}

fn null() -> Any {
    Any::new(Tag::Null, Vec::new()).expect("NULL is valid")
}

/// Digest algorithm identifier, with NULL parameters, as other implementations write it.
fn digest_alg(d: DigestAlg) -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid: digest_oid(d),
        parameters: Some(null()),
    }
}

fn signature_alg(alg: SigAlg) -> AlgorithmIdentifierOwned {
    match alg.key {
        // Name plain rsaEncryption and rely on the digest algorithm field.
        KeyType::Rsa => AlgorithmIdentifierOwned {
            oid: oids::RSA_ENCRYPTION,
            parameters: Some(null()),
        },
        // RFC 5758: no parameters for ECDSA.
        KeyType::Ecdsa => AlgorithmIdentifierOwned {
            oid: match alg.digest {
                DigestAlg::Sha256 => oids::ECDSA_SHA256,
                DigestAlg::Sha384 => oids::ECDSA_SHA384,
                DigestAlg::Sha512 => oids::ECDSA_SHA512,
            },
            parameters: None,
        },
    }
}

pub(crate) fn hash(d: DigestAlg, data: &[u8]) -> Vec<u8> {
    match d {
        DigestAlg::Sha256 => Sha256::digest(data).to_vec(),
        DigestAlg::Sha384 => Sha384::digest(data).to_vec(),
        DigestAlg::Sha512 => Sha512::digest(data).to_vec(),
    }
}

fn attribute(oid: ObjectIdentifier, value: Any) -> Result<Attribute> {
    let values = SetOfVec::try_from(vec![value]).map_err(|e| cms_err("attribute", e))?;
    Ok(Attribute { oid, values })
}

/// The signed attributes of one signature.
#[derive(Debug, Clone)]
pub struct SignedAttrs {
    set: SetOfVec<Attribute>,
}

impl SignedAttrs {
    /// The bytes to sign: the attributes as a DER `SET OF` (tag `0x31`).
    pub fn to_sign(&self) -> Result<Vec<u8>> {
        self.set
            .to_der()
            .map_err(|e| cms_err("encoding signed attributes", e))
    }

    /// The attributes, for inspection.
    pub fn attributes(&self) -> impl Iterator<Item = &Attribute> {
        self.set.iter()
    }
}

/// Builds the CMS `SignedData` of a PAdES signature in two steps, so a token can do the signing:
///
/// 1. [`PadesCms::signed_attributes`] gives the bytes to sign;
/// 2. [`PadesCms::assemble`] wraps the resulting signature value.
///
/// The structure follows the PAdES detached mode: no content, version 1, signer identified by
/// issuer and serial number, attributes `contentType` (id-data), `messageDigest` and
/// `signingCertificateV2`, and no `signingTime` (the time lives in the signature dictionary).
pub struct PadesCms {
    alg: SigAlg,
    chain: Vec<Certificate>,
    options: PadesCmsOptions,
}

impl PadesCms {
    /// `chain_der` holds DER certificates, the signer's first.
    pub fn new(alg: SigAlg, chain_der: &[Vec<u8>], options: PadesCmsOptions) -> Result<Self> {
        if chain_der.is_empty() {
            return Err(Error::Other("CMS: empty certificate chain".into()));
        }
        let chain = chain_der
            .iter()
            .map(|d| Certificate::from_der(d).map_err(|e| cms_err("invalid certificate", e)))
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            alg,
            chain,
            options,
        })
    }

    pub fn algorithm(&self) -> SigAlg {
        self.alg
    }

    pub fn signer(&self) -> &Certificate {
        &self.chain[0]
    }

    /// Digest of `data` with the signature's digest algorithm.
    pub fn digest(&self, data: &[u8]) -> Vec<u8> {
        hash(self.alg.digest, data)
    }

    /// Signed attributes for a signature over data whose digest is `data_digest`.
    pub fn signed_attributes(&self, data_digest: &[u8]) -> Result<SignedAttrs> {
        self.signed_attributes_with(data_digest, Vec::new())
    }

    /// Signed attributes with the EPES attributes configured in `policy`: signature policy,
    /// commitment types and claimed roles. An empty policy gives the same as [`Self::signed_attributes`].
    pub fn signed_attributes_epes(
        &self,
        data_digest: &[u8],
        policy: &Policy,
    ) -> Result<SignedAttrs> {
        let extra = crate::epes::attributes(policy, self.alg.digest)?;
        self.signed_attributes_with(data_digest, extra)
    }

    /// As [`Self::signed_attributes`], with extra attributes (signature policy and so on).
    pub fn signed_attributes_with(
        &self,
        data_digest: &[u8],
        extra: Vec<Attribute>,
    ) -> Result<SignedAttrs> {
        let expected = hash(self.alg.digest, b"").len();
        if data_digest.len() != expected {
            return Err(Error::Other(format!(
                "CMS: data digest is {} bytes, {} needs {expected}",
                data_digest.len(),
                self.alg
            )));
        }
        let to_any =
            |v: &dyn Fn() -> der::Result<Any>, what: &str| v().map_err(|e| cms_err(what, e));

        let content_type = attribute(
            oids::ID_CONTENT_TYPE,
            to_any(&|| Any::encode_from(&oids::ID_DATA), "contentType")?,
        )?;
        let message_digest = attribute(
            oids::ID_MESSAGE_DIGEST,
            to_any(
                &|| Any::encode_from(&OctetString::new(data_digest.to_vec())?),
                "messageDigest",
            )?,
        )?;
        let scv2 = self.signing_certificate_v2()?;
        let signing_certificate = attribute(
            oids::ID_SIGNING_CERTIFICATE_V2,
            to_any(&|| Any::encode_from(&scv2), "signingCertificateV2")?,
        )?;

        let mut all = vec![content_type, message_digest, signing_certificate];
        all.extend(extra);
        let set = SetOfVec::try_from(all).map_err(|e| cms_err("duplicate signed attribute", e))?;
        Ok(SignedAttrs { set })
    }

    fn signing_certificate_v2(&self) -> Result<SigningCertificateV2> {
        let signer = self.signer();
        let der = signer
            .to_der()
            .map_err(|e| cms_err("encoding certificate", e))?;
        let tbs = &signer.tbs_certificate();
        let cert_id = EssCertIdV2 {
            hash_algorithm: (self.alg.digest != DigestAlg::Sha256).then(|| {
                AlgorithmIdentifierOwned {
                    oid: digest_oid(self.alg.digest),
                    parameters: Some(null()),
                }
            }),
            cert_hash: OctetString::new(hash(self.alg.digest, &der))
                .map_err(|e| cms_err("hash", e))?,
            issuer_serial: Some(IssuerSerial {
                issuer: vec![GeneralName::DirectoryName(tbs.issuer().clone())],
                serial_number: tbs.serial_number().clone(),
            }),
        };
        let policies = if self.options.include_cert_policies {
            certificate_policies(signer)?
        } else {
            None
        };
        Ok(SigningCertificateV2 {
            certs: vec![cert_id],
            policies,
        })
    }

    /// Wraps `signature` (PKCS#1 v1.5 for RSA, DER `ECDSA-Sig-Value` for ECDSA) and returns the DER `ContentInfo`.
    pub fn assemble(&self, attrs: &SignedAttrs, signature: &[u8]) -> Result<Vec<u8>> {
        let tbs = self.signer().tbs_certificate();
        let signer_info = SignerInfo {
            version: CmsVersion::V1,
            sid: SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
                issuer: tbs.issuer().clone(),
                serial_number: tbs.serial_number().clone(),
            }),
            digest_alg: digest_alg(self.alg.digest),
            signed_attrs: Some(attrs.set.clone()),
            signature_algorithm: signature_alg(self.alg),
            signature: OctetString::new(signature.to_vec()).map_err(|e| cms_err("signature", e))?,
            unsigned_attrs: None,
        };
        self.encode(signer_info)
    }

    /// `ContentInfo` for an already built `SignerInfo`.
    pub(crate) fn encode(&self, signer_info: SignerInfo) -> Result<Vec<u8>> {
        let certs: Vec<CertificateChoices> = if self.options.include_chain {
            self.chain
                .iter()
                .cloned()
                .map(CertificateChoices::Certificate)
                .collect()
        } else {
            vec![CertificateChoices::Certificate(self.chain[0].clone())]
        };
        let signed = SignedData {
            version: CmsVersion::V1,
            digest_algorithms: SetOfVec::try_from(vec![digest_alg(self.alg.digest)])
                .map_err(|e| cms_err("digest algorithms", e))?,
            encap_content_info: EncapsulatedContentInfo {
                econtent_type: oids::ID_DATA,
                econtent: None,
            },
            certificates: Some(CertificateSet(
                SetOfVec::try_from(certs).map_err(|e| cms_err("certificates", e))?,
            )),
            crls: None,
            signer_infos: SignerInfos(
                SetOfVec::try_from(vec![signer_info]).map_err(|e| cms_err("signer infos", e))?,
            ),
        };
        let info = ContentInfo {
            content_type: oids::ID_SIGNED_DATA,
            content: Any::encode_from(&signed).map_err(|e| cms_err("SignedData", e))?,
        };
        info.to_der().map_err(|e| cms_err("ContentInfo", e))
    }
}

fn certificate_policies(cert: &Certificate) -> Result<Option<Vec<PolicyInformation>>> {
    let Some(extensions) = cert.tbs_certificate().extensions() else {
        return Ok(None);
    };
    let Some(ext) = extensions
        .iter()
        .find(|e| e.extn_id == CertificatePolicies::OID)
    else {
        return Ok(None);
    };
    let policies: Vec<PolicyInformation> = Vec::from_der(ext.extn_value.as_bytes())
        .map_err(|e| cms_err("certificatePolicies extension", e))?;
    Ok((!policies.is_empty()).then_some(policies))
}
