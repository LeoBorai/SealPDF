# sealpdf-pades

Signs a PDF with a PAdES signature, invisible by default and optionally visible. `sign_pdf` ties the other crates together: it opens the PDF, refuses what it cannot sign safely, builds the CMS for the digest of the covered bytes, has a `KeyStore` sign it (the private key never leaves the store), and embeds the result.

## What it does

- The output is the input followed by one incremental update, so earlier signatures stay valid.
- By default the signature is invisible: an empty-rectangle signature field on the first page and no appearance stream. The pages are not touched.
- With `SigningParams::visible` the signature field gets a rectangle and an appearance stream that draws a fixed text. The page content streams are still not touched: the stamp exists only as the widget's appearance.
- The algorithm follows the key: SHA-256 with RSA (PKCS#1 v1.5), SHA-256 with ECDSA on P-256, SHA-384 with ECDSA on P-384. The subfilter is `adbe.pkcs7.detached`, `/Contents` reserves 27000 bytes, `/Name` is the certificate's common name and `/M` is the time from the injected `Clock`.
- The CMS holds `contentType`, `messageDigest` and `signingCertificateV2` (no `signingTime`) and the whole chain the key store returns.

## Visible signatures

`VisibleSignature { placement, utc_offset }` asks for one.

- **Text.** `AUTOFIRMA_TEMPLATE`, the text AutoFirma prints by default: `Firmado por $$SUBJECTCN$$ el día $$SIGNDATE=dd/MM/yyyy$$ con un certificado emitido por $$ISSUERCN$$`. The names are the common names of the signing certificate's subject and issuer. The text is wrapped and sized to fit the rectangle, in base-14 Courier with WinAnsi encoding, so characters outside WinAnsi do not render. The template is a constant; making it configurable is left for later.
- **Date.** The signing time from the injected `Clock`, shown with `utc_offset`. The offset is an input so the crate stays free of the system time zone and tests are deterministic. `/M` always keeps UTC.
- **Place.** `placement: Some(Placement { page, rect })` gives a 1-based page and a rectangle `[llx, lly, urx, ury]` in the page's default user space, the space `/Rect` uses (`/Rotate` is not applied to it). `None` uses `sealpdf_pdf::default_signature_box`: a 200 x 50 point box in the lower-left corner of the last page as displayed, 36 points from its edges.
- **Rotation.** The appearance is turned by the page's `/Rotate`, so the text reads upright when the page is displayed.
- A rectangle with no area or outside the page is refused with `INVALID_SIGNATURE_POSITION`, and a page that does not exist with `INVALID_SIGNATURE_PAGE`. Nothing is written.

## What it refuses

Nothing is written when the document is encrypted, certified with no changes allowed (DocMDP `P` 1), has no pages, or cannot be read as a PDF, or when the CMS does not fit in the reserved space.
