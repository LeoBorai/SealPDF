#![doc = include_str!("../README.md")]

mod ess;
mod oids;
mod pades;

pub use pades::{PadesCms, PadesCmsOptions, SignedAttrs};
