use crate::{Error, Result};
use std::{fmt, str::FromStr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DigestAlg {
    Sha256,
    Sha384,
    Sha512,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyType {
    Rsa,
    Ecdsa,
}

/// Signature algorithm: digest plus key type (`SHA256withRSA`, `SHA384withECDSA`, ...).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SigAlg {
    pub digest: DigestAlg,
    pub key: KeyType,
}

impl SigAlg {
    pub const ALL: [SigAlg; 6] = [
        Self::new(DigestAlg::Sha256, KeyType::Rsa),
        Self::new(DigestAlg::Sha384, KeyType::Rsa),
        Self::new(DigestAlg::Sha512, KeyType::Rsa),
        Self::new(DigestAlg::Sha256, KeyType::Ecdsa),
        Self::new(DigestAlg::Sha384, KeyType::Ecdsa),
        Self::new(DigestAlg::Sha512, KeyType::Ecdsa),
    ];

    pub const fn new(digest: DigestAlg, key: KeyType) -> Self {
        Self { digest, key }
    }
}

impl fmt::Display for SigAlg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let d = match self.digest {
            DigestAlg::Sha256 => "SHA256",
            DigestAlg::Sha384 => "SHA384",
            DigestAlg::Sha512 => "SHA512",
        };
        let k = match self.key {
            KeyType::Rsa => "RSA",
            KeyType::Ecdsa => "ECDSA",
        };
        write!(f, "{d}with{k}")
    }
}

impl FromStr for SigAlg {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::ALL
            .into_iter()
            .find(|a| a.to_string().eq_ignore_ascii_case(s))
            .ok_or_else(|| Error::UnsupportedAlgorithm(s.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_all_algorithms() {
        for a in SigAlg::ALL {
            assert_eq!(a.to_string().parse::<SigAlg>().unwrap(), a);
        }
    }

    #[test]
    fn rejects_unsupported() {
        assert!(matches!(
            "SHA1withRSA".parse::<SigAlg>(),
            Err(Error::UnsupportedAlgorithm(_))
        ));
    }
}
