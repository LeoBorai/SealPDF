mod list_certs;
mod sign;

use crate::{
    args::{Command, KeystoreArgs, KeystoreSpec},
    exit::Failure,
    prompt::TerminalPrompt,
};
use certsign_core::SystemClock;
use certsign_keystore::{CertFilters, Entry, KeyStore, KeychainKeyStore, Pkcs12KeyStore};

pub fn run(command: Command) -> Result<(), Failure> {
    match command {
        Command::ListCerts(args) => list_certs::run(&args),
        Command::Sign(args) => sign::run(&args),
    }
}

/// An opened key store and the prompt it may need.
pub struct Opened {
    pub store: Box<dyn KeyStore>,
    pub prompt: TerminalPrompt,
}

/// Opens the key store `--keystore` names. A PKCS#12 file asks for its password here.
pub fn open_keystore(args: &KeystoreArgs) -> Result<Opened, Failure> {
    let spec = KeystoreSpec::parse(args.keystore.as_deref()).map_err(|e| Failure::usage(e.0))?;
    let prompt = TerminalPrompt::new(args.password_env.clone());
    let store: Box<dyn KeyStore> = match spec {
        KeystoreSpec::Keychain => Box::new(KeychainKeyStore::open()?),
        KeystoreSpec::Pkcs12(path) => Box::new(Pkcs12KeyStore::open(path, &prompt)?),
    };
    Ok(Opened { store, prompt })
}

/// The entries a user should be offered: those that pass the default certificate filters.
pub fn offered(store: &dyn KeyStore) -> Result<Vec<Entry>, Failure> {
    Ok(CertFilters::default().apply(store.entries()?, &SystemClock))
}
