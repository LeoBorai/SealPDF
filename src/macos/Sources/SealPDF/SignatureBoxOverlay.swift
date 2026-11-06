import AppKit
import PDFKit
import SwiftUI

/// The box on the preview that marks where a visible signature goes. It is a view laid over the
/// `PDFView`; it can be dragged to move it and by a corner to resize it.
///
/// It knows nothing about pages. It reports its frame, in its superview's coordinates, and the
/// coordinator turns that into a page and a rectangle.
final class SignatureBoxView: NSView {
    /// Asked for the frame to use while dragging; it keeps the box on a page.
    var constrain: ((CGRect, _ resizing: Bool) -> CGRect)?
    /// Called when a drag ends, with the box's frame.
    var onCommit: ((CGRect) -> Void)?
    /// The least size, in superview units. The coordinator keeps it at 40 x 20 page points.
    var minimumSize = CGSize(width: 40, height: 20)
    private(set) var isDragging = false

    private enum Drag {
        case move(grab: CGPoint)
        /// Resizing by a corner: the opposite corner stays where it is.
        case resize(anchor: CGPoint)
    }
    private var drag: Drag?
    private let handleSize: CGFloat = 12

    override func acceptsFirstMouse(for event: NSEvent?) -> Bool { true }

    override func draw(_ dirtyRect: NSRect) {
        let accent = NSColor.controlAccentColor
        accent.withAlphaComponent(0.15).setFill()
        NSBezierPath(rect: bounds).fill()
        accent.setStroke()
        let border = NSBezierPath(rect: bounds.insetBy(dx: 1, dy: 1))
        border.lineWidth = 2
        border.stroke()

        let label = NSAttributedString(
            string: "Signature",
            attributes: [
                .font: NSFont.systemFont(ofSize: 11, weight: .medium),
                .foregroundColor: accent,
            ])
        let size = label.size()
        if size.width < bounds.width - 4, size.height < bounds.height - 4 {
            label.draw(
                at: CGPoint(x: bounds.midX - size.width / 2, y: bounds.midY - size.height / 2))
        }

        accent.setFill()
        let side: CGFloat = 8
        for corner in [
            CGPoint(x: bounds.minX, y: bounds.minY), CGPoint(x: bounds.maxX, y: bounds.minY),
            CGPoint(x: bounds.minX, y: bounds.maxY), CGPoint(x: bounds.maxX, y: bounds.maxY),
        ] {
            NSBezierPath(
                rect: CGRect(x: corner.x - side / 2, y: corner.y - side / 2, width: side, height: side)
            ).fill()
        }
    }

    override func mouseDown(with event: NSEvent) {
        guard let parent = superview else { return }
        let point = parent.convert(event.locationInWindow, from: nil)
        let corners = [
            CGPoint(x: frame.minX, y: frame.minY), CGPoint(x: frame.maxX, y: frame.minY),
            CGPoint(x: frame.minX, y: frame.maxY), CGPoint(x: frame.maxX, y: frame.maxY),
        ]
        if let corner = corners.first(where: { hypot($0.x - point.x, $0.y - point.y) <= handleSize }) {
            drag = .resize(anchor: CGPoint(x: frame.minX + frame.maxX - corner.x,
                                           y: frame.minY + frame.maxY - corner.y))
        } else {
            drag = .move(grab: CGPoint(x: point.x - frame.minX, y: point.y - frame.minY))
        }
        isDragging = true
    }

    override func mouseDragged(with event: NSEvent) {
        guard let parent = superview, let drag else { return }
        let point = parent.convert(event.locationInWindow, from: nil)
        var proposed: CGRect
        var resizing = false
        switch drag {
        case .move(let grab):
            proposed = CGRect(
                x: point.x - grab.x, y: point.y - grab.y,
                width: frame.width, height: frame.height)
        case .resize(let anchor):
            resizing = true
            let width = max(abs(point.x - anchor.x), minimumSize.width)
            let height = max(abs(point.y - anchor.y), minimumSize.height)
            proposed = CGRect(
                x: point.x < anchor.x ? anchor.x - width : anchor.x,
                y: point.y < anchor.y ? anchor.y - height : anchor.y,
                width: width, height: height)
        }
        frame = constrain?(proposed, resizing) ?? proposed
        needsDisplay = true
    }

    override func mouseUp(with event: NSEvent) {
        guard drag != nil else { return }
        drag = nil
        isDragging = false
        onCommit?(frame)
    }
}

/// Keeps the `SignatureBoxView` over the right part of the right page, and turns what the user
/// does with it into a `PlacedBox`.
///
/// The model holds the box in page space. This class derives the view's frame from it whenever
/// the zoom, the scroll position or the layout changes, so the box stays on the same part of the
/// page. PDFKit's `convert` takes `/Rotate` into account, so no rotation arithmetic is done here.
final class SignatureBoxCoordinator: NSObject {
    var box: Binding<PlacedBox?>
    private weak var pdfView: PDFView?
    private let overlay = SignatureBoxView()
    private var observers: [NSObjectProtocol] = []
    private var scrollObserver: NSObjectProtocol?

    /// The least size of the box as displayed, in page points.
    private let minimumPoints = CGSize(width: 40, height: 20)

    init(box: Binding<PlacedBox?>) {
        self.box = box
        super.init()
        overlay.isHidden = true
        overlay.constrain = { [weak self] frame, resizing in
            self?.constrained(frame, resizing: resizing) ?? frame
        }
        overlay.onCommit = { [weak self] frame in self?.commit(frame) }
    }

    deinit {
        for token in observers + [scrollObserver].compactMap({ $0 }) {
            NotificationCenter.default.removeObserver(token)
        }
    }

    func attach(to view: PDFView) {
        pdfView = view
        view.addSubview(overlay)
        view.postsFrameChangedNotifications = true
        let center = NotificationCenter.default
        for name in [
            Notification.Name.PDFViewScaleChanged, .PDFViewPageChanged,
            .PDFViewDocumentChanged, NSView.frameDidChangeNotification,
        ] {
            observers.append(
                center.addObserver(forName: name, object: view, queue: .main) { [weak self] _ in
                    self?.layout()
                })
        }
    }

    // The preview scrolls inside a scroll view that PDFKit makes itself.
    private func observeScrolling() {
        guard scrollObserver == nil, let view = pdfView,
            let scroll = view.subviews.compactMap({ $0 as? NSScrollView }).first
        else { return }
        scroll.contentView.postsBoundsChangedNotifications = true
        scrollObserver = NotificationCenter.default.addObserver(
            forName: NSView.boundsDidChangeNotification, object: scroll.contentView, queue: .main
        ) { [weak self] _ in self?.layout() }
    }

    // MARK: Page space <-> user space

    // PDFKit's page space is taken to be the PDF's default user space, the space of `/Rect`.
    // This is the one place to correct it if it is not (task 5.1 of the change checks this on a
    // page whose boxes do not start at the origin, and on a rotated page).
    private func userSpace(fromPageSpace rect: CGRect, on page: PDFPage) -> CGRect { rect }
    private func pageSpace(fromUserSpace rect: CGRect, on page: PDFPage) -> CGRect { rect }

    // MARK: Model -> view

    /// Puts the overlay over the model's box. Called on every change of the view and of the model.
    func layout() {
        observeScrolling()
        guard let view = pdfView, !overlay.isDragging, let placed = box.wrappedValue,
            let page = view.document?.page(at: placed.pageIndex)
        else {
            overlay.isHidden = true
            return
        }
        overlay.isHidden = false
        let scale = view.scaleFactor
        overlay.minimumSize = CGSize(
            width: minimumPoints.width * scale, height: minimumPoints.height * scale)
        overlay.frame = view.convert(pageSpace(fromUserSpace: placed.rect, on: page), from: page)
        overlay.needsDisplay = true

        if placed.needsReveal {
            view.go(to: pageSpace(fromUserSpace: placed.rect, on: page), on: page)
            // Not while SwiftUI is updating the view.
            DispatchQueue.main.async { [weak self] in
                self?.box.wrappedValue?.needsReveal = false
            }
        }
    }

    // MARK: View -> model

    /// Keeps a box being dragged on the page under its center: a move slides it back inside the
    /// page's visible area, a resize stops at the edge. Over no page it is left alone.
    private func constrained(_ frame: CGRect, resizing: Bool) -> CGRect {
        guard let view = pdfView,
            let page = view.page(for: CGPoint(x: frame.midX, y: frame.midY), nearest: false)
        else { return frame }
        let visible = view.convert(page.bounds(for: .cropBox), from: page).standardized
        if resizing { return frame.intersection(visible) }
        var out = frame
        out.size.width = min(out.width, visible.width)
        out.size.height = min(out.height, visible.height)
        out.origin.x = min(max(out.minX, visible.minX), visible.maxX - out.width)
        out.origin.y = min(max(out.minY, visible.minY), visible.maxY - out.height)
        return out
    }

    /// The drag ended: the box belongs to the page under its center. Over no page it goes back
    /// to where it was.
    private func commit(_ frame: CGRect) {
        guard let view = pdfView, let document = view.document,
            let page = view.page(for: CGPoint(x: frame.midX, y: frame.midY), nearest: false)
        else {
            layout()
            return
        }
        let rect = userSpace(fromPageSpace: view.convert(frame, to: page).standardized, on: page)
        box.wrappedValue = PlacedBox(pageIndex: document.index(for: page), rect: rect)
        layout()
    }
}
