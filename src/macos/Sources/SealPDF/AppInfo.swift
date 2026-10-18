import Foundation

/// What the About window shows. The version and commit are written into the app's Info.plist by
/// `bundle.sh`; run from `swift run` there is no bundle, so they fall back to "dev".
enum AppInfo {
    static let name = "SealPDF"
    static let summary = "PDF Digital Signature Tool"
    static let repository = URL(string: "https://github.com/LeoBorai/SealPDF")!

    static var version: String { value("CFBundleShortVersionString") ?? "dev" }

    /// The full SHA of the commit the app was built from, when it was bundled.
    static var commit: String? { value("SealPDFCommit") }

    static func commitURL(_ commit: String) -> URL {
        repository.appendingPathComponent("commit").appendingPathComponent(commit)
    }

    private static func value(_ key: String) -> String? {
        Bundle.main.object(forInfoDictionaryKey: key) as? String
    }
}
