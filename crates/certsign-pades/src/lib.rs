#![doc = include_str!("../README.md")]

mod sign;

pub use sign::{SigningParams, sign_pdf};
