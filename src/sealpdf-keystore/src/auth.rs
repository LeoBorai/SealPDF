use sealpdf_core::{KeystoreError, Result};
use secrecy::SecretString;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretKind {
    /// The password of a key store file.
    Password,
    /// The PIN of a token.
    Pin,
}

impl SecretKind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::Pin => "PIN",
        }
    }
}

/// What a key store is asking for, so a prompt can word its question.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthRequest<'a> {
    pub kind: SecretKind,
    /// The file or token the secret unlocks.
    pub target: &'a str,
    /// Set when an earlier attempt failed and the token reports how many are left.
    pub retries_left: Option<u32>,
}

impl<'a> AuthRequest<'a> {
    pub fn new(kind: SecretKind, target: &'a str) -> Self {
        Self {
            kind,
            target,
            retries_left: None,
        }
    }
}

/// Where a key store gets its passwords and PINs.
///
/// A terminal asks with echo off, a script reads an environment variable, a GUI shows a dialog.
/// The secret comes back as a [`SecretString`], which is wiped from memory when dropped and
/// does not appear in `Debug` output. Implementations must not log what they return.
pub trait AuthPrompt {
    /// Returns the secret, or [`KeystoreError::SecretUnavailable`] when there is none to give.
    fn secret(&self, request: &AuthRequest<'_>) -> Result<SecretString>;
}

/// Always answers with the same secret. For tests and for callers that already hold one.
pub struct StaticPrompt(SecretString);

impl StaticPrompt {
    pub fn new(secret: impl Into<String>) -> Self {
        Self(SecretString::from(secret.into()))
    }
}

impl AuthPrompt for StaticPrompt {
    fn secret(&self, _request: &AuthRequest<'_>) -> Result<SecretString> {
        Ok(self.0.clone())
    }
}

impl std::fmt::Debug for StaticPrompt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StaticPrompt(<redacted>)")
    }
}

/// Never has a secret. Use it with stores that need none, or to refuse to ask.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoPrompt;

impl AuthPrompt for NoPrompt {
    fn secret(&self, request: &AuthRequest<'_>) -> Result<SecretString> {
        Err(KeystoreError::SecretUnavailable {
            kind: request.kind.name(),
            reason: format!(
                "nothing to ask for the {} of {}",
                request.kind.name(),
                request.target
            ),
        }
        .into())
    }
}
