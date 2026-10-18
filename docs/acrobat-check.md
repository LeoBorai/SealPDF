# Adobe Acrobat check

Before a release, sign a few PDFs with the release build, open each one in Adobe Acrobat (desktop), and record the result here. None may show a "document has been modified" warning or an invalid signature. A "validity unknown" message for a certificate Acrobat does not trust is expected and fine.

| Date | sealpdf version | Certificate (type and issuer)  | Kind of output             | Acrobat version | Result |
| ---- | ---------------- | ------------------------------ | -------------------------- | --------------- | ------ |
|      |                  | RSA                            | single signature           |                 |        |
|      |                  | ECDSA P-256                    | single signature           |                 |        |
|      |                  | RSA, then a second certificate | co-signed (two signatures) |                 |        |
