import AppKit
import Foundation
import UniformTypeIdentifiers

/// The Verify tab's state. Nothing is checked until a PDF is opened here.
@MainActor
final class VerifyModel: ObservableObject {
    @Published private(set) var input: URL?
    @Published private(set) var report: Report?
    /// Why there is no report: the file is not a readable PDF, or it is encrypted.
    @Published private(set) var failure: String?
    @Published private(set) var isWorking = false

    func chooseFile() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.pdf]
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        panel.message = "Choose the PDF to check"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        open(url)
    }

    /// Takes a PDF and checks its signatures off the main thread.
    func open(_ url: URL) {
        input = url
        report = nil
        failure = nil
        isWorking = true
        Task { [self] in
            let result = await Task.detached { () -> Result<Report, Error> in
                Result { try PDFInspector.report(for: url) }
            }.value
            // Another PDF was opened meanwhile: its answer is the one to show.
            guard input == url else { return }
            switch result {
            case .success(let value): report = value
            case .failure(let error): failure = error.localizedDescription
            }
            isWorking = false
        }
    }
}
