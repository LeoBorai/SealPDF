# `sealpdf verify`

Checks the signatures in a PDF and tells whether the document can be accepted as signed. It prints what [`ls`](ls.md) prints, then the verdict, and exits non-zero unless the verdict is `OK`.

```
sealpdf verify [--json] <input.pdf>
```

| Option | Meaning |
| --- | --- |
| `--json` | Print the report as JSON on stdout instead of text. The exit code is the same. |

## Output

```
#  FIELD       SIGNER    SIGNED AT             COVERS      STATUS
1  Signature1  Jane Doe  2026-10-20T14:03:00Z  rev 2 of 2  intact

Verdict: OK
Certificate trust and revocation were not checked.
```

## What is checked

| Check | Result when it fails |
| --- | --- |
| The digest of the signed bytes matches the signature, and the signature value verifies | `KO NO_MATCH_DATA` |
| The signature can be read | `KO CORRUPTED_SIGN` |
| The digest and signature algorithms are allowed (SHA-256/384/512 with RSA or ECDSA P-256/P-384) | `KO ALGORITHM_NOT_SUPPORTED` |
| The signer certificate is inside its validity period now | `KO CERTIFICATE_EXPIRED`, `KO CERTIFICATE_NOT_VALID_YET` |
| The PDF has at least one signature (document timestamps do not count) | `KO NO_SIGN` |
| No signature was added after a certification that allows no changes | `KO CERTIFIED_SIGN_REVISION` |

## What is reported as unknown

`UNKNOWN` means "not checked", never "fine":

| Verdict | Why |
| --- | --- |
| `UNKNOWN MODIFIED_DOCUMENT` | The file has revisions after the last signature. They are not analysed, so they could be harmless (a form filled in, an annotation) or not. |
| `UNKNOWN SIGN_PROFILE_NOT_CHECKED` | The newest signature has a signature timestamp, or the file has a document timestamp or validation data (`/DSS`). They are not verified. |

Both make the exit code 5. A PDF with long-term validation data, which many tools write, will usually show the second one.

## Not checked

Whether the certificate chain leads to a trusted authority, whether a certificate was revoked, the contents of timestamp tokens, and what changed between revisions. The last line of the output says so. A signature by a self-signed certificate is `intact`.

## Verdict order

Repeated items appear once, `KO` items come before the rest, and a clean document is exactly `OK`. When the only `KO` is `CERTIFICATE_EXPIRED` and `SIGN_PROFILE_NOT_CHECKED` is present, the latter comes first: an expired certificate says little about a signature that carries long-term data.

<a id="json"></a>

## `--json`

```json
{
  "version": 1,
  "revisions": 2,
  "signatures": [
    {
      "field": "Signature1",
      "page": 1,
      "sub_filter": "adbe.pkcs7.detached",
      "doc_timestamp": false,
      "signer": "Jane Doe",
      "signed_at": "2026-10-20T14:03:00Z",
      "reason": null,
      "location": null,
      "revision": 2,
      "status": []
    }
  ],
  "verdicts": [{ "verdict": "OK" }],
  "trust_checked": false
}
```

- `verdicts` is never empty. Each item is `{"verdict": "OK"}`, or `{"verdict": "KO" | "UNKNOWN", "error": "<ID>"}`.
- `status` is empty for an intact signature, or lists identifiers like `NO_MATCH_DATA`.
- `signed_at` is RFC 3339 when the file's date can be read, the text as written otherwise.
- `trust_checked` is always `false`.
- `version` changes when a field changes meaning or goes away.

## Exit codes

| Code | When |
| --- | --- |
| 0 | The verdict is exactly `OK`. |
| 2 | The command was used wrongly, for example no file was given. |
| 3 | The file is not a readable PDF, or it is encrypted. |
| 5 | The verdict is anything else: no signature, a broken one, or something not checked. The reason is on stderr. |
| 6 | The file cannot be read from disk. |

For a script: `sealpdf verify doc.pdf && upload doc.pdf` uploads only a PDF that is signed, intact and unchanged since.

## Safety

Read-only: the file is read and nothing is written. No network access.
