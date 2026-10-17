#![doc = include_str!("../README.md")]

mod appearance;
mod document;
mod field;
mod fields;
mod font_metrics;
mod image;
mod pages;
mod revisions;
mod serialize;
mod text;
mod writer;

pub use appearance::{
    AppearanceSpec, FontFamily, FontSpec, TextLayout, add_appearance, layout_text,
    set_widget_appearance, wrap,
};
pub use document::{EncryptionInfo, PdfDocument};
pub use field::{AttachedField, FieldTarget, attach_signature};
pub use fields::{AcroForm, SignatureField, SignatureValue};
pub use pages::Page;
pub use revisions::Revision;
pub use text::{DateLocale, SignerText, TextContext, expand_placeholders, format_date};
pub use writer::{IncrementalWriter, PreparedSignature};
