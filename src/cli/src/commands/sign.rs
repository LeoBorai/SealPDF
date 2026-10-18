use super::{offered, open_keystore};
use crate::{args::SignArgs, exit::Failure};
use sealpdf_core::{KeystoreError, SystemClock};
use sealpdf_keystore::Entry;
use sealpdf_pades::{SigningParams, sign_pdf};
use std::{
    io::{BufRead, IsTerminal, Write},
    path::{Path, PathBuf},
};

pub fn run(args: &SignArgs) -> Result<(), Failure> {
    // Everything that can be checked without a certificate is checked before asking for one.
    let output = output_path(&args.input, args.output.as_deref())?;
    check_output(&args.input, &output, args.force)?;
    let input = std::fs::read(&args.input)
        .map_err(|e| Failure::other(format!("cannot read {}: {e}", args.input.display())))?;

    let opened = open_keystore(&args.keystore)?;
    let alias = choose_alias(opened.store.as_ref(), args.alias.as_deref())?;
    tracing::debug!(%alias, "signing with");

    let signed = sign_pdf(
        input,
        opened.store.as_ref(),
        &alias,
        &SystemClock,
        &opened.prompt,
        &SigningParams::default(),
    )?;
    write_atomically(&output, &signed, args.force)?;
    eprintln!("Signed {} -> {}", args.input.display(), output.display());
    Ok(())
}

/// `--output`, or `<name>_signed.pdf` next to the input.
pub fn output_path(input: &Path, output: Option<&Path>) -> Result<PathBuf, Failure> {
    if let Some(o) = output {
        return Ok(o.to_owned());
    }
    let stem = input.file_stem().and_then(|s| s.to_str()).ok_or_else(|| {
        Failure::usage(format!(
            "cannot derive an output name from {}",
            input.display()
        ))
    })?;
    Ok(input.with_file_name(format!("{stem}_signed.pdf")))
}

/// The input is never overwritten, and an existing output is replaced only with `--force`.
fn check_output(input: &Path, output: &Path, force: bool) -> Result<(), Failure> {
    if same_file(input, output) {
        return Err(Failure::usage(format!(
            "the output {} is the input file; the input is never overwritten",
            output.display()
        )));
    }
    if output.exists() && !force {
        return Err(Failure::usage(format!(
            "{} already exists; use --force to replace it",
            output.display()
        )));
    }
    Ok(())
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

/// Picks the signing certificate: `--alias`, the only one, or a numbered choice on a terminal.
fn choose_alias(
    store: &dyn sealpdf_keystore::KeyStore,
    alias: Option<&str>,
) -> Result<String, Failure> {
    if let Some(alias) = alias {
        // Naming a certificate wins over the filters, but it has to exist.
        return if store.entries()?.iter().any(|e| e.alias == alias) {
            Ok(alias.to_owned())
        } else {
            Err(sealpdf_core::Error::from(KeystoreError::UnknownAlias(alias.to_owned())).into())
        };
    }
    let entries = offered(store)?;
    match entries.as_slice() {
        [] => Err(sealpdf_core::Error::from(KeystoreError::Backend(
            "no signing certificate found; `sealpdf list-certs` shows what is available".into(),
        ))
        .into()),
        [only] => Ok(only.alias.clone()),
        several => {
            if !std::io::stdin().is_terminal() {
                return Err(Failure::usage(format!(
                    "several certificates are available; choose one with --alias: {}",
                    several
                        .iter()
                        .map(|e| e.alias.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )));
            }
            pick(several)
        }
    }
}

fn pick(entries: &[Entry]) -> Result<String, Failure> {
    let mut stderr = std::io::stderr();
    let _ = writeln!(stderr, "Choose a certificate:");
    for (i, e) in entries.iter().enumerate() {
        let _ = writeln!(stderr, "  {}) {}", i + 1, e.alias);
    }
    let _ = write!(stderr, "Number [1-{}]: ", entries.len());
    let _ = stderr.flush();
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| Failure::other(format!("cannot read the choice: {e}")))?;
    parse_choice(&line, entries.len())
        .map(|i| entries[i].alias.clone())
        .ok_or_else(|| {
            Failure::usage(format!(
                "`{}` is not a number from 1 to {}",
                line.trim(),
                entries.len()
            ))
        })
}

/// Zero-based index for a typed choice of `1..=len`.
pub fn parse_choice(line: &str, len: usize) -> Option<usize> {
    let n: usize = line.trim().parse().ok()?;
    (1..=len).contains(&n).then(|| n - 1)
}

/// Writes next to the target and renames, so a failure never leaves a partial PDF.
fn write_atomically(output: &Path, bytes: &[u8], force: bool) -> Result<(), Failure> {
    let dir = output
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut temp = tempfile::NamedTempFile::new_in(dir)
        .map_err(|e| Failure::other(format!("cannot write in {}: {e}", dir.display())))?;
    temp.write_all(bytes)
        .and_then(|()| temp.flush())
        .map_err(|e| Failure::other(format!("cannot write {}: {e}", output.display())))?;
    let result = if force {
        temp.persist(output)
    } else {
        temp.persist_noclobber(output)
    };
    result
        .map(|_| ())
        .map_err(|e| Failure::other(format!("cannot write {}: {}", output.display(), e.error)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_output_name() {
        assert_eq!(
            output_path(Path::new("dir/contract.pdf"), None).unwrap(),
            Path::new("dir/contract_signed.pdf")
        );
        assert_eq!(
            output_path(Path::new("contract.pdf"), None).unwrap(),
            Path::new("contract_signed.pdf")
        );
        assert_eq!(
            output_path(Path::new("a.b.pdf"), None).unwrap(),
            Path::new("a.b_signed.pdf")
        );
        assert_eq!(
            output_path(Path::new("noext"), None).unwrap(),
            Path::new("noext_signed.pdf")
        );
        assert_eq!(
            output_path(Path::new("x.pdf"), Some(Path::new("out/y.pdf"))).unwrap(),
            Path::new("out/y.pdf")
        );
    }

    #[test]
    fn numbered_choices() {
        assert_eq!(parse_choice("1\n", 3), Some(0));
        assert_eq!(parse_choice(" 3 ", 3), Some(2));
        for bad in ["0", "4", "", "x", "-1", "1.5"] {
            assert_eq!(parse_choice(bad, 3), None, "{bad:?}");
        }
    }

    #[test]
    fn same_file_sees_through_paths() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.pdf");
        std::fs::write(&a, b"x").unwrap();
        assert!(same_file(&a, &dir.path().join(".").join("a.pdf")));
        assert!(same_file(&a, &a));
        assert!(!same_file(&a, &dir.path().join("b.pdf")));
        // A file that does not exist yet.
        assert!(same_file(
            &dir.path().join("new.pdf"),
            &dir.path().join("./new.pdf")
        ));
        assert!(!same_file(&a, &dir.path().join("nested").join("a.pdf")));
    }
}
