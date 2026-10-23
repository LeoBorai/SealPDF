import CSealPDF
import Foundation

struct SealError: LocalizedError {
    let message: String
    var errorDescription: String? { message }
}

/// Reads and releases a string the Rust library allocated.
func take(_ pointer: UnsafeMutablePointer<CChar>?) -> String? {
    guard let pointer else { return nil }
    defer { sealpdf_string_free(pointer) }
    return String(cString: pointer)
}

/// The Keychain's signing certificates, through the Rust library.
///
/// `@unchecked Sendable`: the handle is only read, and the window allows one signing at a time.
final class Certificates: @unchecked Sendable {
    private let handle: OpaquePointer
    let aliases: [String]

    private init(handle: OpaquePointer) {
        self.handle = handle
        self.aliases = (0..<sealpdf_certs_count(handle)).compactMap {
            take(sealpdf_certs_alias(handle, $0))
        }
    }

    /// The signing identities in the user's Keychain.
    static func keychain() throws -> Certificates {
        var error: UnsafeMutablePointer<CChar>?
        guard let handle = sealpdf_certs_open(&error) else {
            throw SealError(message: take(error) ?? "cannot read the Keychain")
        }
        return Certificates(handle: handle)
    }

    /// The certificates in a `.p12` / `.pfx` file. A wrong password throws.
    static func pkcs12(at url: URL, password: String) throws -> Certificates {
        var error: UnsafeMutablePointer<CChar>?
        guard let handle = sealpdf_certs_open_pkcs12(url.path, password, &error) else {
            throw SealError(message: take(error) ?? "cannot open \(url.lastPathComponent)")
        }
        return Certificates(handle: handle)
    }

    deinit { sealpdf_certs_free(handle) }

    /// Blocks until done, and while macOS asks to use the key: call it off the main thread.
    func sign(input: URL, output: URL, alias: String) throws {
        var error: UnsafeMutablePointer<CChar>?
        let code = sealpdf_sign(handle, input.path, output.path, alias, &error)
        if code != 0 {
            throw SealError(message: take(error) ?? "signing failed (code \(code))")
        }
    }
}
