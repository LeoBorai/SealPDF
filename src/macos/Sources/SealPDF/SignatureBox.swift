import CSealPDF
import CoreGraphics
import Foundation

/// Where the visible signature will go: a page and a rectangle on it.
struct PlacedBox: Equatable, Sendable {
    /// 0-based position in the document, as PDFKit counts pages.
    var pageIndex: Int
    /// In PDF user space: points, origin at the bottom-left, the space a PDF's `/Rect` uses. The
    /// model keeps it in page space, never in view space, so zooming and scrolling cannot move it.
    var rect: CGRect
    /// The preview should scroll to the box. Set when the box is first placed.
    var needsReveal = false
}

enum SignatureBoxes {
    /// The place `sealpdf sign --visible` would use for the PDF at `url`: the last page, in its
    /// lower-left corner as displayed. Reads the file, so call it off the main thread.
    static func defaultBox(of url: URL) throws -> PlacedBox {
        var page: UInt32 = 0
        var llx = 0.0, lly = 0.0, urx = 0.0, ury = 0.0
        var error: UnsafeMutablePointer<CChar>?
        let code = sealpdf_default_signature_box(url.path, &page, &llx, &lly, &urx, &ury, &error)
        if code != 0 {
            throw SealError(message: take(error) ?? "cannot place the signature (code \(code))")
        }
        return PlacedBox(
            pageIndex: Int(page) - 1,
            rect: CGRect(x: llx, y: lly, width: urx - llx, height: ury - lly),
            needsReveal: true)
    }
}
