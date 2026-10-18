# `sealpdf sign`

Signs a PDF with an invisible PAdES signature and writes the result to a new file.

```
sealpdf sign <INPUT> [--keystore TYPE[:LOCATION]] [--password-env VAR]
                      [--alias NAME] [-o, --output FILE] [--force]
```

| Option | Meaning |
| --- | --- |
| `INPUT` | The PDF to sign. |
| `--keystore`, `--password-env` | As in [list-certs](list-certs.md). |
| `--alias` | Sign with this certificate. It need not pass the default filters but must exist. |
| `-o, --output` | Output path. Default: `<name>_signed.pdf` next to the input (`a.b.pdf` gives `a.b_signed.pdf`). |
| `--force` | Replace the output if it exists. |

On success it prints `Signed <input> -> <output>` on stderr.

## Flow

```mermaid
flowchart TD
    A([start]) --> B["Work out the output path"]
    B --> C{"Output is the input<br/>(same file, through links or ./..)?"}
    C -- yes --> U1["exit 2: input is never overwritten"]
    C -- no --> D{"Output exists and no --force?"}
    D -- yes --> U2["exit 2: use --force"]
    D -- no --> E["Read the input"]
    E --> F["Open the key store<br/>(may ask the password)"]
    F --> G{"--alias given?"}
    G -- yes --> H{"Alias exists?"}
    H -- no --> K1["exit 4: unknown alias"]
    H -- yes --> L
    G -- no --> I{"How many offered?"}
    I -- 0 --> K2["exit 4: no signing certificate"]
    I -- 1 --> L
    I -- several --> J{"stdin is a terminal?"}
    J -- no --> U3["exit 2: choose with --alias"]
    J -- yes --> J2["numbered list, read a number"] --> L
    L["sign_pdf"] --> M{"Refused?<br/>encrypted, certified, no pages, unreadable"}
    M -- yes --> R["exit 3, nothing written"]
    M -- no --> N["Write temp file in output folder, then rename"]
    N --> O(["exit 0"])
```

## How the certificate is found and used

`sealpdf` does not request or enroll certificates from a certificate authority: no CSR is made and nothing is issued. The certificate must already exist, in the macOS Keychain or in a PKCS#12 (`.p12`) file. This diagram shows how `sign` gets from `--keystore` to a signature.

```mermaid
flowchart TD
    S(["--keystore"]) --> T{"Value"}
    T -- "absent, macOS" --> KC
    T -- "absent, other systems" --> E1["exit 2: --keystore is required"]
    T -- "keychain" --> KC["Open the Keychain search list<br/>no password asked by sealpdf"]
    T -- "pkcs12:file" --> PW{"--password-env VAR given?"}
    T -- "anything else" --> E2["exit 2: unknown keystore type"]

    PW -- yes --> V{"VAR is set?"}
    V -- yes --> OPEN
    V -- no --> E3["exit 4: variable is not set"]
    PW -- no --> TTY{"stdin is a terminal?"}
    TTY -- yes --> ASK["Ask on stderr, no echo"] --> OPEN
    TTY -- no --> E4["exit 4: no terminal, use --password-env"]

    OPEN["Decrypt the file once<br/>list identities: certificate, chain, key"] --> ENT
    KC --> ENT["Entries of the store"]
    ENT --> AL{"--alias given?"}

    AL -- yes --> EX{"An entry has this alias?"}
    EX -- no --> E5["exit 4: unknown alias"]
    EX -- yes --> PICKED
    AL -- no --> FIL["Default filters<br/>hide expired and not yet valid<br/>hide DNIe authentication certificate"]
    FIL --> N{"Entries left"}
    N -- 0 --> E6["exit 4: no signing certificate found"]
    N -- 1 --> PICKED
    N -- several --> TT{"stdin is a terminal?"}
    TT -- no --> E7["exit 2: choose one with --alias"]
    TT -- yes --> NUM["Numbered list on stderr<br/>read a number"] --> PICKED

    PICKED["Selected alias"] --> PARSE["sign_pdf reads its certificate and chain<br/>RSA or ECDSA is chosen from the key type"]
    PARSE --> HASH["Hash the PDF bytes covered by /ByteRange<br/>build the CMS signed attributes"]
    HASH --> USE{"Store type"}
    USE -- "PKCS#12" --> SIGN1["Sign with the key decrypted at open"]
    USE -- "Keychain" --> SIGN2["macOS signs inside the Keychain<br/>shows its own allow prompt: password or Touch ID<br/>sealpdf never sees the key"]
    SIGN1 --> EMB
    SIGN2 --> EMB["Embed the CMS, with the chain, in /Contents"]
```

Notes:

- `--alias` skips the filters, so an expired certificate can be used by naming it, but it must exist in the store.
- A PKCS#12 password is asked once per run and is never stored.
- Only the signed attributes go to the key. On the Keychain path the private key never leaves macOS.

## What `sign_pdf` does

```mermaid
sequenceDiagram
    participant S as sign_pdf
    participant P as PDF
    participant K as KeyStore
    S->>P: open, refuse encrypted / certified / empty
    S->>K: find entry for alias, read chain
    S->>S: pick RSA or ECDSA from the certificate
    S->>P: append one revision with a signature dictionary (/M = now) and a reserved /Contents
    S->>S: hash the bytes covered by /ByteRange
    S->>S: build CMS signed attributes
    S->>K: sign(attributes), may ask PIN or password
    K-->>S: signature value
    S->>S: assemble CMS (detached, with chain)
    S->>P: embed CMS in /Contents
```

- The signature is an incremental update: the original bytes are untouched and earlier signatures stay valid.
- It has no appearance: pages are not changed. The field is attached to page 1.
- The private key stays in the key store; only the hash-bound attributes are sent to it.

## Safety

| Risk | Protection |
| --- | --- |
| Losing the original | The input is never the output, even through symlinks or `./..` paths, and `--force` does not change that. |
| Overwriting another file | Needs `--force`. |
| Half-written output | Temp file in the same folder, then rename; `--force` replaces, otherwise the rename refuses to clobber. |
| Password leak | Never an argument, never logged, never cached. See [password handling](README.md#password-handling). |
| Wasted prompts | Output and input checks run before any certificate or password is requested. |
| Unsafe documents | Encrypted and certified (no-changes) PDFs are refused. |
| Wrong certificate | With several, a non-interactive run fails and lists the aliases instead of guessing. |

Exit codes: see [the table](README.md#exit-codes).
