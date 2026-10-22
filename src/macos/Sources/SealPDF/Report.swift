import CSealPDF
import Foundation

/// One item of the document verdict: `OK`, or `KO` / `UNKNOWN` with the reason.
struct Verdict: Decodable, Hashable {
    let verdict: String
    let error: String?

    /// `OK`, or `KO NO_SIGN`: the same text `sealpdf verify` prints.
    var text: String {
        error.map { "\(verdict) \($0)" } ?? verdict
    }

    /// In words, what the reason means for a reader.
    var meaning: String? {
        switch error {
        case "NO_SIGN": return "The PDF has no signatures."
        case "NO_MATCH_DATA": return "Signed data was changed, or a signature value is wrong."
        case "CORRUPTED_SIGN": return "A signature cannot be read."
        case "ALGORITHM_NOT_SUPPORTED": return "A signature uses an algorithm that is not allowed."
        case "CERTIFICATE_EXPIRED": return "A signer certificate has expired."
        case "CERTIFICATE_NOT_VALID_YET": return "A signer certificate is not valid yet."
        case "CERTIFICATE_PROBLEM": return "A signer certificate is missing."
        case "MODIFIED_DOCUMENT": return "Changes after the last signature were not analysed."
        case "SIGN_PROFILE_NOT_CHECKED": return "Timestamps and validation data were not verified."
        case "CERTIFIED_SIGN_REVISION": return "Signed after a certification that allows no changes."
        default: return nil
        }
    }
}

/// One signature of the PDF, as `sealpdf_inspect` reports it.
struct SignatureInfo: Decodable {
    let field: String
    let page: Int?
    let subFilter: String?
    let docTimestamp: Bool
    let signer: String?
    let signedAt: String?
    let reason: String?
    let location: String?
    let revision: Int
    /// Empty when the signature is intact; otherwise the identifiers of what is wrong.
    let status: [String]

    var isIntact: Bool { status.isEmpty }

    /// The signing time for people: local, short. Text that is not a date is shown as written.
    var signedAtText: String? {
        guard let signedAt else { return nil }
        guard let date = ISO8601DateFormatter().date(from: signedAt) else { return signedAt }
        return date.formatted(date: .abbreviated, time: .shortened)
    }
}

/// What `sealpdf_inspect` returns, decoded from its JSON.
struct Report: Decodable {
    let version: Int
    let revisions: Int
    let signatures: [SignatureInfo]
    let verdicts: [Verdict]
    let trustChecked: Bool

    /// The verdict list is exactly `[OK]`.
    var isOK: Bool { verdicts.count == 1 && verdicts[0].verdict == "OK" }

    var hasSignatures: Bool { signatures.contains { !$0.docTimestamp } }
}

/// Looks inside a PDF through the Rust library.
enum PDFInspector {
    /// How many signatures the PDF carries, without checking any. Blocks briefly: call it off the
    /// main thread.
    static func signatureCount(of url: URL) throws -> Int {
        var error: UnsafeMutablePointer<CChar>?
        let count = sealpdf_signature_count(url.path, &error)
        guard count >= 0 else {
            throw SealError(message: take(error) ?? "cannot read \(url.lastPathComponent)")
        }
        return count
    }

    /// Lists and checks the signatures. Blocks while the signatures are checked: call it off the
    /// main thread.
    static func report(for url: URL) throws -> Report {
        var error: UnsafeMutablePointer<CChar>?
        guard let text = take(sealpdf_inspect(url.path, &error)) else {
            throw SealError(message: take(error) ?? "cannot check \(url.lastPathComponent)")
        }
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        do {
            return try decoder.decode(Report.self, from: Data(text.utf8))
        } catch {
            throw SealError(message: "the report could not be read: \(error.localizedDescription)")
        }
    }
}
