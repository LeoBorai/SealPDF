//! The work behind the window, free of any UI so it runs and is tested on every platform.

use sealpdf_core::SystemClock;
use sealpdf_keystore::{CertFilters, Entry, KeyStore, NoPrompt};
use sealpdf_pades::{SigningParams, sign_pdf};
use std::{
    io::Write,
    path::{Path, PathBuf},
};

/// The certificates worth offering: those that pass the default filters.
pub fn offered(store: &dyn KeyStore) -> Result<Vec<Entry>, String> {
    let entries = store.entries().map_err(|e| e.to_string())?;
    Ok(CertFilters::default().apply(entries, &SystemClock))
}

/// Signs `input` with the certificate `alias` and writes the result to `output`.
///
/// The input is never changed, and `output` may not be the input. A failure leaves no partial
/// file behind. Keychain access is decided by macOS itself, which shows its own prompt, so
/// nothing is asked of the user here.
pub fn sign_file(
    input: &Path,
    output: &Path,
    alias: &str,
    store: &dyn KeyStore,
) -> Result<(), String> {
    if same_file(input, output) {
        return Err("the output is the input file; the input is never overwritten".into());
    }
    let bytes =
        std::fs::read(input).map_err(|e| format!("cannot read {}: {e}", input.display()))?;
    let signed = sign_pdf(
        bytes,
        store,
        alias,
        &SystemClock,
        &NoPrompt,
        &SigningParams::default(),
    )
    .map_err(|e| e.to_string())?;
    write_atomically(output, &signed)
}

/// Whether two paths name one file, even through links or relative segments.
fn same_file(a: &Path, b: &Path) -> bool {
    let resolve = |p: &Path| -> Option<PathBuf> {
        if let Ok(c) = p.canonicalize() {
            return Some(c);
        }
        // A file that does not exist yet: resolve its folder and keep the name.
        let name = p.file_name()?;
        let dir = p
            .parent()
            .filter(|d| !d.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        Some(dir.canonicalize().ok()?.join(name))
    };
    matches!((resolve(a), resolve(b)), (Some(x), Some(y)) if x == y)
}

/// Writes next to the target and renames, replacing it. The save panel has already asked the
/// user to confirm replacing an existing file.
fn write_atomically(output: &Path, bytes: &[u8]) -> Result<(), String> {
    let dir = output
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut temp = tempfile::NamedTempFile::new_in(dir)
        .map_err(|e| format!("cannot write in {}: {e}", dir.display()))?;
    temp.write_all(bytes)
        .and_then(|()| temp.flush())
        .map_err(|e| format!("cannot write {}: {e}", output.display()))?;
    temp.persist(output)
        .map(|_| ())
        .map_err(|e| format!("cannot write {}: {}", output.display(), e.error))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_file_sees_through_paths() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.pdf");
        std::fs::write(&a, b"x").unwrap();
        assert!(same_file(&a, &dir.path().join(".").join("a.pdf")));
        assert!(!same_file(&a, &dir.path().join("b.pdf")));
    }
}
