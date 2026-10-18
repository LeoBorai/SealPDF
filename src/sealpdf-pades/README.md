# sealpdf-pades

Signs a PDF with an invisible PAdES signature. `sign_pdf` ties the other crates together: it opens the PDF, refuses what it cannot sign safely, builds the CMS for the digest of the covered bytes, has a `KeyStore` sign it (the private key never leaves the store), and embeds the result.

## What it does

- The output is the input followed by one incremental update, so earlier signatures stay valid.
- The signature is invisible: an empty-rectangle signature field on the first page and no appearance stream. The pages are not touched.
- The algorithm follows the key: SHA-256 with RSA (PKCS#1 v1.5), SHA-256 with ECDSA on P-256, SHA-384 with ECDSA on P-384. The subfilter is `adbe.pkcs7.detached`, `/Contents` reserves 27000 bytes, `/Name` is the certificate's common name and `/M` is the time from the injected `Clock`.
- The CMS holds `contentType`, `messageDigest` and `signingCertificateV2` (no `signingTime`) and the whole chain the key store returns.

## What it refuses

Nothing is written when the document is encrypted, certified with no changes allowed (DocMDP `P` 1), has no pages, or cannot be read as a PDF, or when the CMS does not fit in the reserved space.
