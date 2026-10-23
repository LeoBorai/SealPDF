#![doc = include_str!("../README.md")]

mod epes;
mod ess;
mod oids;
mod pades;
mod verify;

pub use pades::{PadesCms, PadesCmsOptions, SignedAttrs};
pub use verify::{VerifiedSignature, VerifyError, digest_algorithm, verify_detached};
