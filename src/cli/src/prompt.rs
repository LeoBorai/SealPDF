use certsign_core::{KeystoreError, Result};
use certsign_keystore::{AuthPrompt, AuthRequest, SecretString};
use std::io::{IsTerminal, Write};

/// Gets a password from an environment variable or from the terminal, without echo.
///
/// Nothing is remembered: every request asks again. A secret is never taken from the command
/// line, only the *name* of the environment variable is.
pub struct TerminalPrompt {
    env_var: Option<String>,
}

impl TerminalPrompt {
    pub fn new(env_var: Option<String>) -> Self {
        Self { env_var }
    }
}

impl AuthPrompt for TerminalPrompt {
    fn secret(&self, request: &AuthRequest<'_>) -> Result<SecretString> {
        let kind = request.kind.name();
        if let Some(var) = &self.env_var {
            return match std::env::var(var) {
                Ok(value) => Ok(SecretString::from(value)),
                Err(_) => Err(KeystoreError::SecretUnavailable {
                    kind,
                    reason: format!("the environment variable {var} is not set"),
                }
                .into()),
            };
        }
        if !std::io::stdin().is_terminal() {
            return Err(KeystoreError::SecretUnavailable {
                kind,
                reason: format!(
                    "there is no terminal to ask on; pass --password-env <VAR> to read the {kind} of {} from the environment",
                    request.target
                ),
            }
            .into());
        }
        let mut stderr = std::io::stderr();
        let _ = write!(stderr, "{kind} for {}: ", request.target);
        let _ = stderr.flush();
        let secret = rpassword::read_password().map_err(|e| KeystoreError::SecretUnavailable {
            kind,
            reason: format!("cannot read from the terminal: {e}"),
        })?;
        Ok(SecretString::from(secret))
    }
}
