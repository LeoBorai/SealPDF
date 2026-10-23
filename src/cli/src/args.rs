use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

/// Sign PDF documents with the digital certificate installed on your system.
#[derive(Debug, Parser)]
#[command(name = "sealpdf", version, about)]
pub struct Cli {
    /// Print what is being done on stderr. Never prints passwords or keys.
    #[arg(long, global = true)]
    pub verbose: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// List the signing certificates that are available.
    ListCerts(KeystoreArgs),
    /// Sign a PDF with an invisible signature.
    Sign(SignArgs),
    /// List the signatures in a PDF and whether each one is intact.
    Ls(InspectArgs),
    /// Check the signatures in a PDF. Exits 5 unless the PDF is signed and nothing is wrong or unchecked.
    Verify(InspectArgs),
}

#[derive(Debug, Args)]
pub struct InspectArgs {
    /// The PDF to look at.
    pub input: PathBuf,

    /// Print the report as JSON on stdout.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct KeystoreArgs {
    /// Where the certificates are: `keychain` (the macOS Keychain, the default on macOS) or
    /// `pkcs12:<file>`.
    #[arg(long, value_name = "TYPE[:LOCATION]")]
    pub keystore: Option<String>,

    /// Read a PKCS#12 password from this environment variable instead of asking for it.
    /// The password itself is never accepted as an argument.
    #[arg(long, value_name = "VAR")]
    pub password_env: Option<String>,
}

#[derive(Debug, Args)]
pub struct SignArgs {
    /// The PDF to sign.
    pub input: PathBuf,

    #[command(flatten)]
    pub keystore: KeystoreArgs,

    /// Sign with the certificate of this alias (see `sealpdf list-certs`).
    #[arg(long)]
    pub alias: Option<String>,

    /// Where to write the signed PDF. Default: `<name>_signed.pdf` next to the input.
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Replace the output file if it already exists.
    #[arg(long)]
    pub force: bool,
}

/// Where the certificates come from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeystoreSpec {
    Keychain,
    Pkcs12(PathBuf),
}

/// What `--keystore` said wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeystoreSpecError(pub String);

impl KeystoreSpec {
    /// Parses `--keystore`. Without it, macOS uses the Keychain and other systems need an answer.
    pub fn parse(arg: Option<&str>) -> Result<Self, KeystoreSpecError> {
        let supported = "the supported types are `keychain` and `pkcs12:<file>`";
        let Some(arg) = arg else {
            return if cfg!(target_os = "macos") {
                Ok(Self::Keychain)
            } else {
                Err(KeystoreSpecError(format!(
                    "--keystore is required on this system; {supported}"
                )))
            };
        };
        let (kind, location) = arg.split_once(':').map_or((arg, ""), |(k, l)| (k, l));
        match (kind, location) {
            ("keychain", "") => Ok(Self::Keychain),
            ("keychain", _) => Err(KeystoreSpecError(
                "the keychain keystore takes no location".into(),
            )),
            ("pkcs12", "") => Err(KeystoreSpecError(
                "pkcs12 needs a file: --keystore pkcs12:<file>".into(),
            )),
            ("pkcs12", file) => Ok(Self::Pkcs12(PathBuf::from(file))),
            (other, _) => Err(KeystoreSpecError(format!(
                "unknown keystore type `{other}`; {supported}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_keystore_specs() {
        assert_eq!(
            KeystoreSpec::parse(Some("keychain")),
            Ok(KeystoreSpec::Keychain)
        );
        assert_eq!(
            KeystoreSpec::parse(Some("pkcs12:/tmp/a b/c.p12")),
            Ok(KeystoreSpec::Pkcs12("/tmp/a b/c.p12".into()))
        );
        // A Windows path keeps its colon.
        assert_eq!(
            KeystoreSpec::parse(Some(r"pkcs12:C:\certs\me.p12")),
            Ok(KeystoreSpec::Pkcs12(r"C:\certs\me.p12".into()))
        );
    }

    #[test]
    fn rejects_bad_keystore_specs() {
        for bad in [
            "windows:",
            "pkcs12",
            "pkcs12:",
            "keychain:x",
            "",
            "PKCS12:x",
        ] {
            let err = KeystoreSpec::parse(Some(bad)).unwrap_err();
            assert!(!err.0.is_empty(), "{bad}");
        }
        let msg = KeystoreSpec::parse(Some("windows:")).unwrap_err().0;
        assert!(msg.contains("keychain") && msg.contains("pkcs12"), "{msg}");
    }

    #[test]
    fn default_keystore_depends_on_the_system() {
        let default = KeystoreSpec::parse(None);
        if cfg!(target_os = "macos") {
            assert_eq!(default, Ok(KeystoreSpec::Keychain));
        } else {
            assert!(default.unwrap_err().0.contains("--keystore is required"));
        }
    }
}
