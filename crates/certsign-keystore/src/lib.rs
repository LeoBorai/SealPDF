#![doc = include_str!("../README.md")]

mod auth;
mod entry;
mod pkcs12;
mod secret;

pub use auth::{AuthPrompt, AuthRequest, NoPrompt, SecretKind, StaticPrompt};
pub use entry::{Entry, KeyStore};
pub use pkcs12::Pkcs12KeyStore;
pub use secret::SecretBytes;
// The secret string type that crosses the API, so callers need no extra dependency.
pub use secrecy::{ExposeSecret, SecretString};
