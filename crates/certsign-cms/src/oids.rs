use const_oid::ObjectIdentifier as Oid;

pub(crate) const ID_DATA: Oid = Oid::new_unwrap("1.2.840.113549.1.7.1");
pub(crate) const ID_SIGNED_DATA: Oid = Oid::new_unwrap("1.2.840.113549.1.7.2");
pub(crate) const ID_CONTENT_TYPE: Oid = Oid::new_unwrap("1.2.840.113549.1.9.3");
pub(crate) const ID_MESSAGE_DIGEST: Oid = Oid::new_unwrap("1.2.840.113549.1.9.4");
pub(crate) const ID_SIGNING_CERTIFICATE_V2: Oid = Oid::new_unwrap("1.2.840.113549.1.9.16.2.47");

pub(crate) const SHA256: Oid = Oid::new_unwrap("2.16.840.1.101.3.4.2.1");
pub(crate) const SHA384: Oid = Oid::new_unwrap("2.16.840.1.101.3.4.2.2");
pub(crate) const SHA512: Oid = Oid::new_unwrap("2.16.840.1.101.3.4.2.3");

pub(crate) const RSA_ENCRYPTION: Oid = Oid::new_unwrap("1.2.840.113549.1.1.1");
pub(crate) const ECDSA_SHA256: Oid = Oid::new_unwrap("1.2.840.10045.4.3.2");
pub(crate) const ECDSA_SHA384: Oid = Oid::new_unwrap("1.2.840.10045.4.3.3");
pub(crate) const ECDSA_SHA512: Oid = Oid::new_unwrap("1.2.840.10045.4.3.4");

pub(crate) const ID_AA_ETS_SIG_POLICY_ID: Oid = Oid::new_unwrap("1.2.840.113549.1.9.16.2.15");
pub(crate) const ID_AA_ETS_COMMITMENT_TYPE: Oid = Oid::new_unwrap("1.2.840.113549.1.9.16.2.16");
pub(crate) const ID_AA_ETS_SIGNER_ATTR: Oid = Oid::new_unwrap("1.2.840.113549.1.9.16.2.18");
pub(crate) const ID_SPQ_ETS_URI: Oid = Oid::new_unwrap("1.2.840.113549.1.9.16.5.1");
pub(crate) const ID_AT_ROLE: Oid = Oid::new_unwrap("2.5.4.72");
