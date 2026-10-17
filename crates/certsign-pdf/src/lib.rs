#![doc = include_str!("../README.md")]

mod document;
mod fields;
mod pages;
mod revisions;
mod serialize;
mod writer;

pub use document::{EncryptionInfo, PdfDocument};
pub use fields::{AcroForm, SignatureField, SignatureValue};
pub use pages::Page;
pub use revisions::Revision;
pub use writer::{IncrementalWriter, PreparedSignature};
