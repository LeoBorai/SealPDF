# Crate conventions

- Every crate in `src/` has a `README.md` explaining its purpose.
- Each crate's `src/lib.rs` embeds its README as crate docs: `#![doc = include_str!("../README.md")]`.
- Adding a crate: create the README and lib.rs doc attribute in the same change.

# Testing conventions

- Unit tests may live in the same module as the source, in a `#[cfg(test)] mod tests`.
- Integration and e2e tests must live in the crate's `tests/` directory, not in `src/`.
