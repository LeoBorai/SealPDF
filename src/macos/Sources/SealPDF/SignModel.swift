import AppKit
import Foundation
import UniformTypeIdentifiers

enum CertificateSource: Hashable {
    case keychain
    case file
}

@MainActor
final class SignModel: ObservableObject {
    @Published var input: URL?
    @Published var source: CertificateSource = .keychain {
        didSet { refreshAliases() }
    }
    @Published var certificateFile: URL?
    /// Held only until the file is opened, then cleared.
    @Published var password = ""
    @Published private(set) var aliases: [String] = []
    @Published var selected = ""
    @Published var status = ""
    @Published var failure: String?
    @Published var isWorking = false

    private var keychain: Certificates?
    private var fromFile: Certificates?

    init() {
        do {
            keychain = try Certificates.keychain()
        } catch {
            status = "Keychain: \(error.localizedDescription)"
        }
        refreshAliases()
        if keychain?.aliases.isEmpty == true {
            status = "No signing certificate was found in the Keychain."
        }
    }

    private var active: Certificates? {
        source == .keychain ? keychain : fromFile
    }

    private func refreshAliases() {
        aliases = active?.aliases ?? []
        selected = aliases.first ?? ""
    }

    var canUnlock: Bool { certificateFile != nil && !password.isEmpty && !isWorking }
    var canSign: Bool { input != nil && !selected.isEmpty && !isWorking }

    func setInput(_ url: URL) {
        input = url
        status = ""
    }

    func chooseFile() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.pdf]
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        panel.message = "Choose the PDF to sign"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        setInput(url)
    }

    func chooseCertificateFile() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = ["p12", "pfx"].compactMap { UTType(filenameExtension: $0) }
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        panel.message = "Choose a certificate file (.p12 or .pfx)"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        certificateFile = url
        // A new file starts locked: forget the previous file's certificates.
        fromFile = nil
        password = ""
        status = ""
        refreshAliases()
    }

    func unlockCertificateFile() async {
        guard let file = certificateFile, !password.isEmpty else { return }
        let password = self.password
        isWorking = true
        defer { isWorking = false }
        do {
            fromFile = try await Task.detached {
                try Certificates.pkcs12(at: file, password: password)
            }.value
            self.password = ""
            status = fromFile?.aliases.isEmpty == true
                ? "\(file.lastPathComponent) has no usable signing certificate." : ""
        } catch {
            fromFile = nil
            failure = error.localizedDescription
        }
        refreshAliases()
    }

    func sign() async {
        guard let input, let certificates = active, !selected.isEmpty else { return }

        let panel = NSSavePanel()
        panel.allowedContentTypes = [.pdf]
        panel.message = "Save the signed PDF"
        panel.directoryURL = input.deletingLastPathComponent()
        panel.nameFieldStringValue =
            input.deletingPathExtension().lastPathComponent + "_signed.pdf"
        guard panel.runModal() == .OK, let output = panel.url else { return }

        let alias = selected
        isWorking = true
        status = "Signing…"
        defer { isWorking = false }
        do {
            // macOS may show its own prompt for the key; keep the window responsive meanwhile.
            try await Task.detached {
                try certificates.sign(input: input, output: output, alias: alias)
            }.value
            status = "Signed. Saved to \(output.path)"
        } catch {
            status = ""
            failure = error.localizedDescription
        }
    }
}
