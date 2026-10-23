# sealpdf-validate

Inspects the signatures of a PDF. `inspect` lists every signature with its signer, signing time and the revision it covers, checks each one, and returns a document verdict list. `signature_count` only counts the signatures, without decoding any of them.

## What is checked

- The digest of the `/ByteRange` bytes against the CMS, the signature value, and the allowed algorithms.
- That the signer certificate is within its validity period at the time of the check.
- Revisions after the last signature (reported as `UNKNOWN MODIFIED_DOCUMENT`: they are not analysed).
- Signature timestamps, document timestamps and `/DSS` (reported as `UNKNOWN SIGN_PROFILE_NOT_CHECKED`: they are not verified).
- Signatures added after a certification that allows no changes.

## What is not checked

Certificate chains and trust anchors, revocation, timestamp tokens, and form or page changes between revisions. `Report::trust_checked` is always `false`: an intact signature is not a trusted one.
