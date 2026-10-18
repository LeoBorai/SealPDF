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
