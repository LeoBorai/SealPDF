#![doc = include_str!("../README.md")]

mod sign;

pub use sign::{AUTOFIRMA_TEMPLATE, Placement, SigningParams, VisibleSignature, sign_pdf};
