import PDFKit
import SwiftUI

/// Shows the pages of a PDF, scrollable and zoomable.
///
/// With a `box`, a box for a visible signature is laid over it; the user can move and resize it.
struct PDFPreview: NSViewRepresentable {
    let url: URL?
    var box: Binding<PlacedBox?> = .constant(nil)

    func makeCoordinator() -> SignatureBoxCoordinator {
        SignatureBoxCoordinator(box: box)
    }

    func makeNSView(context: Context) -> PDFView {
        let view = PDFView()
        view.autoScales = true
        view.displayMode = .singlePageContinuous
        view.displaysPageBreaks = true
        context.coordinator.attach(to: view)
        return view
    }

    func updateNSView(_ view: PDFView, context: Context) {
        context.coordinator.box = box
        // SwiftUI calls this on every change of the window; load again only for a new file.
        if view.document?.documentURL != url {
            view.document = url.flatMap { PDFDocument(url: $0) }
        }
        context.coordinator.layout()
    }
}

/// The preview with its empty state, which also takes a PDF dropped on it.
struct PreviewPane: View {
    let url: URL?
    /// The box for a visible signature, on the Sign tab. Left out, there is none.
    var box: Binding<PlacedBox?> = .constant(nil)
    let onDrop: @MainActor (URL) -> Void

    var body: some View {
        ZStack {
            PDFPreview(url: url, box: box)
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
