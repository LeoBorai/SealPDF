import PDFKit
import SwiftUI

/// Shows the pages of a PDF, scrollable and zoomable.
struct PDFPreview: NSViewRepresentable {
    let url: URL?

    func makeNSView(context: Context) -> PDFView {
        let view = PDFView()
        view.autoScales = true
        view.displayMode = .singlePageContinuous
        view.displaysPageBreaks = true
        return view
    }

    func updateNSView(_ view: PDFView, context: Context) {
        // SwiftUI calls this on every change of the window; load again only for a new file.
        guard view.document?.documentURL != url else { return }
        view.document = url.flatMap { PDFDocument(url: $0) }
    }
}

/// The preview with its empty state, which also takes a PDF dropped on it.
struct PreviewPane: View {
    let url: URL?
    let onDrop: @MainActor (URL) -> Void

    var body: some View {
        ZStack {
            PDFPreview(url: url)
            if url == nil {
                VStack(spacing: 8) {
                    Image(systemName: "doc.richtext")
                        .font(.system(size: 44))
                    Text("Open a PDF, or drop one here")
                }
                .foregroundStyle(.secondary)
                .allowsHitTesting(false)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color(nsColor: .underPageBackgroundColor))
        .dropDestination(for: URL.self) { urls, _ in
            guard let pdf = urls.first(where: { $0.pathExtension.lowercased() == "pdf" }) else {
                return false
            }
            onDrop(pdf)
            return true
        }
    }
}
