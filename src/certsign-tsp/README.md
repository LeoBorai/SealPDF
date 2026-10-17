# certsign-tsp

RFC 3161 time-stamp client. It builds a time-stamp request for a digest, sends it to a time-stamping authority (TSA), and checks the answer before handing back the token that signing code embeds in a signature or a document timestamp.

## Layout

| Piece                               | Role                                                                                                          |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| `TsaRequest`                        | What to stamp: hash algorithm, digest, optional policy OID, nonce, `certReq` flag and one optional extension. |
| `TsaClient<T: Transport>`           | Encodes the request, sends it through `T`, and validates the answer.                                          |
| `Transport`                         | The seam between the protocol and the network: send DER request bytes, get DER response bytes.                |
| `HttpTransport`                     | The production transport: HTTP or HTTPS, with optional Basic credentials. Behind the `http` feature.          |
| `RecordedTransport` / `RecordedTsa` | A test transport that replays stored answers and keeps the requests it was sent.                              |
| `Tsa`                               | The trait signing code depends on (`&dyn Tsa`), implemented by every `TsaClient`.                             |

## What is checked

A token is returned only when the answer has status 0 (granted) or 1 (granted with modifications), carries a `TSTInfo`, and matches the request: same message imprint (hash algorithm and digest), same nonce when one was sent, and same policy when one was requested. Every failure is a `TsaError` that names the TSA and, where there is one, the status.

The token's own signature and the TSA certificate are not verified here. That belongs to signature validation.

## HTTP and the `http` feature

TSAs are web services: a request is a `POST` of the DER `TimeStampReq` with content type `application/timestamp-query`, and the answer is a DER `TimeStampResp` (`application/timestamp-reply`). `HttpTransport` does exactly that and adds the parts every caller would otherwise repeat:

- Basic credentials (`with_credentials`), kept out of `Debug` output;
- a 30 second timeout and a 4 MiB cap on the response;
- HTTP error statuses reported with the TSA's URL, not as a protocol error;
- a retry when a signal interrupts the call;
- the platform trust roots for HTTPS. TLS client certificates are not supported.

It lives in this crate because without it the crate could not contact a TSA at all, but it is isolated: the protocol code only knows the `Transport` trait, and `HttpTransport` is built only with the `http` cargo feature, which is on by default. It is the only user of the `ureq` and `getrandom` dependencies. Building with `--no-default-features` leaves a crate with no network dependency, which suits callers that bring their own transport.

## Testing without a network

`RecordedTsa` is a `TsaClient<RecordedTransport>`. It replays answers queued with `respond` (a stored `TimeStampResp`) or `fail` (a transport error), and answers go through the same checks as a live TSA's. That makes recorded refusals, tokens issued for other data and HTTP failures exercise the real code path. `requests()` returns the DER requests that were sent, for assertions.
