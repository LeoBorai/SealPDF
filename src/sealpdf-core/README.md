# sealpdf-core

Shared foundation for the sealpdf workspace: error types, `SignOptions` (typed signing options loaded from TOML), the `Clock` abstraction and identifier helpers. Contains no async runtime or web framework dependencies, so every other crate can depend on it cheaply.
