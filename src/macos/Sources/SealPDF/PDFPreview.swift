import PDFKit
import SwiftUI

/// Shows the pages of a PDF, scrollable and zoomable.
///
/// With a `box`, a box for a visible signature is laid over it; the user can move and resize it.
struct PDFPreview: NSViewRepresentable {
    let url: URL?
    var box: Binding<PlacedBox?> = .constant(nil)
    /// Called with a PDF dropped on the preview.
    var onDrop: @MainActor (URL) -> Void = { _ in }
    /// Called as a drag enters or leaves the preview.
    var onTargeted: @MainActor (Bool) -> Void = { _ in }

    func makeCoordinator() -> SignatureBoxCoordinator {
        SignatureBoxCoordinator(box: box)
    }

    func makeNSView(context: Context) -> PDFView {
        let view = DropPDFView()
        view.autoScales = true
        view.displayMode = .singlePageContinuous
        view.displaysPageBreaks = true
        context.coordinator.attach(to: view)
        DispatchQueue.main.async { view.claimDrags() }
        return view
    }

    func updateNSView(_ view: PDFView, context: Context) {
        context.coordinator.box = box
        if let view = view as? DropPDFView {
            view.onDrop = onDrop
            view.onTargeted = onTargeted
        }
        // SwiftUI calls this on every change of the window; load again only for a new file.
        if view.document?.documentURL != url {
            view.document = url.flatMap { PDFDocument(url: $0) }
            // PDFKit's inner views register for drags themselves and swallow them.
            (view as? DropPDFView)?.claimDrags()
        }
        context.coordinator.layout()
    }
}

/// A `PDFView` that takes a dropped PDF itself: PDFKit's inner views would otherwise eat the drag
/// before SwiftUI sees it.
final class DropPDFView: PDFView {
    var onDrop: @MainActor (URL) -> Void = { _ in }
    var onTargeted: @MainActor (Bool) -> Void = { _ in }

    override init(frame: NSRect) {
        super.init(frame: frame)
        registerForDraggedTypes([.fileURL])
    }

    required init?(coder: NSCoder) {
        super.init(coder: coder)
        registerForDraggedTypes([.fileURL])
    }

    /// Unregisters every inner view so drags reach this one.
    func claimDrags() {
        func walk(_ view: NSView) {
            for sub in view.subviews {
                sub.unregisterDraggedTypes()
                walk(sub)
            }
        }
        walk(self)
        registerForDraggedTypes([.fileURL])
    }

    private func pdf(in info: NSDraggingInfo) -> URL? {
        let urls = info.draggingPasteboard.readObjects(
            forClasses: [NSURL.self],
            options: [.urlReadingFileURLsOnly: true]) as? [URL]
        return urls?.first { $0.pathExtension.lowercased() == "pdf" }
    }

    override func draggingEntered(_ sender: NSDraggingInfo) -> NSDragOperation {
        guard pdf(in: sender) != nil else { return [] }
        MainActor.assumeIsolated { onTargeted(true) }
        return .copy
    }

    override func draggingUpdated(_ sender: NSDraggingInfo) -> NSDragOperation {
        pdf(in: sender) == nil ? [] : .copy
    }

    override func draggingExited(_ sender: NSDraggingInfo?) {
        MainActor.assumeIsolated { onTargeted(false) }
    }

    override func prepareForDragOperation(_ sender: NSDraggingInfo) -> Bool {
        pdf(in: sender) != nil
    }

    override func performDragOperation(_ sender: NSDraggingInfo) -> Bool {
        guard let url = pdf(in: sender) else { return false }
        MainActor.assumeIsolated {
            onTargeted(false)
            onDrop(url)
        }
        return true
    }

    override func concludeDragOperation(_ sender: NSDraggingInfo?) {
        MainActor.assumeIsolated { onTargeted(false) }
    }
}

/// Whether a drag is over the preview.
@MainActor
final class DragState: ObservableObject {
    @Published var isTargeted = false
}

/// The preview with its empty state, which also takes a PDF dropped on it.
struct PreviewPane: View {
    let url: URL?
    /// The box for a visible signature, on the Sign tab. Left out, there is none.
    var box: Binding<PlacedBox?> = .constant(nil)
    let onDrop: @MainActor (URL) -> Void

    // `@StateObject`, not `@State`: `@State` is a macro, and the Command Line Tools toolchain
    // ships without the SwiftUI macro plugin.
    @StateObject private var drag = DragState()

    var body: some View {
        ZStack {
            PDFPreview(url: url, box: box, onDrop: onDrop, onTargeted: { drag.isTargeted = $0 })
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
        .overlay {
            if drag.isTargeted {
                RoundedRectangle(cornerRadius: 8)
                    .strokeBorder(Color.accentColor, lineWidth: 3)
                    .background(Color.accentColor.opacity(0.08))
                    .padding(6)
                    .allowsHitTesting(false)
            }
        }
        .animation(.easeInOut(duration: 0.12), value: drag.isTargeted)
    }
}
